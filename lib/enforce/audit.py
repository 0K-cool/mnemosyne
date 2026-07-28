"""`mnemosyne audit` — aggregate hook firings into rule-level stats.

The hook templates write JSONL audit entries (one per fire) to
``.claude/logs/<rule>.audit.jsonl``. This module reads those files and
reports per-rule stats: warn / allow / block / skip-override counts,
first/last seen timestamps, and (with ``--threshold``) flags rules that
have crossed a violation threshold as escalation candidates.

v2.1.0 — soft-to-hard escalation: rules generated with ``mode: warn``
may declare an ``escalation:`` policy (threshold + window_days). When
``--memory-dir`` resolves, this module joins those policies against the
audit logs (join key: ``audit_log`` basename stem), counts warn events
inside the rolling window, and marks crossing rules READY TO ESCALATE.
``--apply`` promotes them (operator-gated): the memory entry's ``mode``
flips warn → block, the consumed ``escalation:`` block is removed, and
the hook is regenerated from the rewritten rule via the enforce CLI —
the rule stays the single source of truth, settings.json is never
touched.

Usage:
  PYTHONPATH=lib python -m enforce.audit \\
    [--logs-dir DIR]        # default: .claude/logs
    [--memory-dir DIR]      # default: memory (absent → skip escalation)
    [--threshold N]         # flag rules with blocks >= N (legacy, all-time)
    [--apply] [--yes]       # promote READY rules (interactive unless --yes)
    [--output-dir DIR]      # where regenerated hooks land (default .claude/hooks/auto)
    [--template-dir DIR]    # template override for regeneration
    [--webhook-url URL]     # notify per READY rule (or MNEMOSYNE_WEBHOOK_URL)
    [--fail-on-escalation]  # exit 3 when READY rules exist (cron/CI alerting)
    [--json]                # machine-readable output
    [-v]

Exit codes:
  0 — successful aggregation (READY rules may exist; informational)
  1 — --apply attempted and at least one promotion failed
  2 — invalid CLI arguments
  3 — --fail-on-escalation set and READY rules exist (none applied)

Behavior contract is locked by tests/test_enforce_audit.py and
tests/test_enforce_escalation.py — change carefully.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import tempfile
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger("mnemosyne.audit")

DEFAULT_LOGS_DIR = ".claude/logs"
DEFAULT_MEMORY_DIR = "memory"
DEFAULT_OUTPUT_DIR = ".claude/hooks/auto"
AUDIT_SUFFIX = ".audit.jsonl"
WEBHOOK_ENV_VAR = "MNEMOSYNE_WEBHOOK_URL"
WEBHOOK_TIMEOUT_SECS = 5


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )


def _parse_ts(ts: str) -> Optional[datetime]:
    """ISO 8601 → aware datetime, or None when unparseable.

    The three template ports emit different dialects — TS/sh write
    ``...Z``, the Python port writes ``...Z`` via strftime but stdlib
    consumers elsewhere produce ``+00:00`` offsets — so accept both.
    Naive timestamps are assumed UTC (every template stamps UTC).
    """
    if not isinstance(ts, str) or not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _count_warns_in_window(log_path: Path, cutoff: datetime) -> int:
    """Count ``warn`` events with ``ts >= cutoff`` in one audit log.

    Second-pass read on purpose: ``aggregate_audit_logs`` keeps its
    locked all-time contract; windowed counting only runs for rules
    that actually declare an escalation policy. Unparseable timestamps
    don't count — an attacker who can write the log could inflate the
    count anyway (see the log-poisoning note in docs/v2-enforcement.md);
    skipping garbage keeps honest clocks honest.
    """
    count = 0
    try:
        with log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(entry, dict) or entry.get("event") != "warn":
                    continue
                dt = _parse_ts(entry.get("ts", ""))
                if dt is not None and dt >= cutoff:
                    count += 1
    except OSError:
        return 0
    return count


def load_escalation_configs(memory_dir: Path) -> dict[str, dict[str, Any]]:
    """Map audit-log stem → escalation config for every rule declaring one.

    Walks ``memory_dir`` the same way the enforce CLI does and validates
    each ``enforce:`` block. The join key is the ``audit_log`` basename
    minus ``.audit.jsonl`` — the same stem ``aggregate_audit_logs``
    derives from the log filename. Invalid or escalation-less entries
    are skipped (one broken rule must not take down the audit run).
    """
    # Local imports keep module load light and avoid widening the
    # public dependency surface of the audit CLI.
    from .cli import _iter_memory_files
    from .generator import parse_memory_entry
    from .schema import EnforceValidationError, validate_enforce_block

    configs: dict[str, dict[str, Any]] = {}
    for path in _iter_memory_files(memory_dir):
        try:
            meta, _body = parse_memory_entry(path.read_text(encoding="utf-8"))
        except Exception as exc:  # frontmatter parse failures are non-fatal
            _log.debug("skipping %s (unparseable): %s", path, exc)
            continue
        raw = meta.get("enforce") if isinstance(meta, dict) else None
        if not raw:
            continue
        try:
            enforce = validate_enforce_block(raw)
        except EnforceValidationError as exc:
            _log.warning("skipping %s (invalid enforce block): %s", path, exc)
            continue
        escalation = enforce.get("escalation")
        if not escalation:
            continue
        stem = Path(enforce["audit_log"]).name
        if stem.endswith(AUDIT_SUFFIX):
            stem = stem[: -len(AUDIT_SUFFIX)]
        configs[stem] = {
            "threshold": escalation["threshold"],
            "window_days": escalation["window_days"],
            "rule_path": str(path),
            "hook": enforce["hook"],
        }
    return configs


def evaluate_escalations(
    rules: list[dict[str, Any]],
    configs: dict[str, dict[str, Any]],
    now: Optional[datetime] = None,
) -> list[dict[str, Any]]:
    """Stamp escalation fields on rules with a policy; return READY subset.

    Mutates matching rule dicts in place (warns_in_window,
    escalation_threshold, escalation_window_days, escalation_ready,
    escalation_rule_path). Rules without a declared policy are untouched.
    """
    now = now or datetime.now(timezone.utc)
    ready: list[dict[str, Any]] = []
    for r in rules:
        cfg = configs.get(r["rule"])
        if cfg is None:
            continue
        cutoff = now - timedelta(days=cfg["window_days"])
        count = _count_warns_in_window(Path(r["log_path"]), cutoff)
        r["warns_in_window"] = count
        r["escalation_threshold"] = cfg["threshold"]
        r["escalation_window_days"] = cfg["window_days"]
        r["escalation_rule_path"] = cfg["rule_path"]
        r["escalation_ready"] = count >= cfg["threshold"]
        if r["escalation_ready"]:
            ready.append(r)
    return ready


def aggregate_audit_logs(logs_dir: Path) -> list[dict[str, Any]]:
    """Read every ``*.audit.jsonl`` file under ``logs_dir`` and aggregate.

    Returns a list of per-rule stat dicts, sorted by rule name. Each dict has:
      - rule: str (file stem minus .audit)
      - blocks, allows, skip_overrides, total: int
      - first_seen, last_seen: str (ISO 8601, lex-sorted; empty if no entries)
      - log_path: str (absolute path to the audit file)

    Missing or unreadable directories return an empty list. Malformed JSONL
    lines are skipped silently (parse errors elsewhere in the pipeline are
    the more useful signal).
    """
    if not logs_dir.exists() or not logs_dir.is_dir():
        return []

    # Guard against unreadable directories (permissions, network mounts, etc.)
    try:
        children = sorted(logs_dir.iterdir())
    except (OSError, PermissionError) as exc:
        _log.warning("could not list %s: %s", logs_dir, exc)
        return []

    rules: list[dict[str, Any]] = []
    for path in children:
        if not path.is_file() or not path.name.endswith(AUDIT_SUFFIX):
            continue
        rule_name = path.name[: -len(AUDIT_SUFFIX)]
        stats: dict[str, Any] = {
            "rule": rule_name,
            "warns": 0,
            "blocks": 0,
            "allows": 0,
            "skip_overrides": 0,
            "total": 0,
            "first_seen": "",
            "last_seen": "",
            "log_path": str(path.resolve()),
        }
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue  # malformed lines silently skipped
                    if not isinstance(entry, dict):
                        continue

                    event = entry.get("event")
                    if event == "warn":
                        stats["warns"] += 1
                    elif event == "block":
                        stats["blocks"] += 1
                    elif event == "allow":
                        stats["allows"] += 1
                    elif event == "skip-override":
                        stats["skip_overrides"] += 1
                    stats["total"] += 1

                    ts = entry.get("ts")
                    if isinstance(ts, str):
                        if not stats["first_seen"] or ts < stats["first_seen"]:
                            stats["first_seen"] = ts
                        if ts > stats["last_seen"]:
                            stats["last_seen"] = ts
        except OSError as exc:
            _log.warning("could not read %s: %s", path, exc)
            continue

        rules.append(stats)

    return rules


def apply_escalation(
    rule_path: Path,
    template_dir: Path,
    output_dir: Path,
) -> int:
    """Promote one warn rule to block and regenerate its hook.

    Steps (the rule file stays the single source of truth):
      1. Line-targeted rewrite inside the frontmatter: ``mode: warn`` →
         ``mode: block``; the consumed ``escalation:`` sub-block is
         removed (a block rule with an escalation policy is a schema
         error, and promotion is the policy's terminal state).
      2. Atomic replace (tempfile + os.replace in the same directory).
      3. Re-read + revalidate the rewritten rule (must normalize to
         mode: block) before touching any hook.
      4. Delegate hook regeneration to the enforce CLI single-rule path
         (same atomic-write pipeline every generated hook goes through).

    Returns 0 on success, non-zero on any failure. Never leaves a
    half-rewritten rule file behind.
    """
    from .cli import main as enforce_main
    from .generator import parse_memory_entry
    from .schema import EnforceValidationError, validate_enforce_block

    try:
        original = rule_path.read_text(encoding="utf-8")
    except OSError as exc:
        _log.error("cannot read rule %s: %s", rule_path, exc)
        return 1

    lines = original.splitlines(keepends=True)
    mode_idx: Optional[int] = None
    esc_start: Optional[int] = None
    esc_end: Optional[int] = None

    for i, line in enumerate(lines):
        stripped = line.rstrip("\n")
        if mode_idx is None and stripped.strip() == "mode: warn":
            mode_idx = i
        if esc_start is None and stripped.strip() == "escalation:":
            esc_start = i
            indent = len(stripped) - len(stripped.lstrip())
            j = i + 1
            while j < len(lines):
                nxt = lines[j].rstrip("\n")
                nxt_indent = len(nxt) - len(nxt.lstrip())
                if nxt.strip() and nxt_indent <= indent:
                    break
                if not nxt.strip():
                    break
                j += 1
            esc_end = j

    if mode_idx is None:
        _log.error("rule %s has no `mode: warn` line — refusing to promote", rule_path)
        return 1

    indent = lines[mode_idx][: len(lines[mode_idx]) - len(lines[mode_idx].lstrip())]
    lines[mode_idx] = f"{indent}mode: block\n"
    if esc_start is not None and esc_end is not None:
        del lines[esc_start:esc_end]
    rewritten = "".join(lines)

    # Revalidate BEFORE writing — a promotion that produces an invalid
    # rule must fail with the original file intact.
    try:
        meta, _body = parse_memory_entry(rewritten)
        normalized = validate_enforce_block(meta["enforce"])
    except Exception as exc:  # parse/KeyError/EnforceValidationError — all fatal here
        _log.error("promoted rule %s does not revalidate: %s", rule_path, exc)
        return 1
    if normalized["mode"] != "block":
        _log.error("promotion of %s did not yield mode: block", rule_path)
        return 1

    # Atomic replace in the same directory (house mkstemp + replace
    # pattern — never expose a partially written rule).
    try:
        fd, tmp_name = tempfile.mkstemp(
            dir=str(rule_path.parent), prefix=f".{rule_path.name}.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(rewritten)
            os.replace(tmp_name, rule_path)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise
    except OSError as exc:
        _log.error("atomic rewrite of %s failed: %s", rule_path, exc)
        return 1

    # Regenerate the hook from the now-hard rule via the standard CLI
    # single-rule path.
    rc = enforce_main([
        "--rule", str(rule_path),
        "--output-dir", str(output_dir),
        "--template-dir", str(template_dir),
    ])
    if rc != 0:
        _log.error(
            "rule %s promoted but hook regeneration failed (rc=%d) — "
            "re-run: python -m enforce --rule %s",
            rule_path, rc, rule_path,
        )
    return rc


def _post_webhook(url: str, payload: dict[str, Any]) -> bool:
    """POST one READY notification. Fail-soft: never raises.

    Adds a human-readable ``content`` field (Discord renders it) on top
    of the machine fields, so one payload serves both Discord webhooks
    and generic JSON receivers. Scheme is restricted to http(s) — a
    webhook URL must never become a local file/scheme probe.
    """
    if not url.startswith(("https://", "http://")):
        _log.warning("webhook url scheme not allowed (http/https only): %s", url)
        return False
    body = dict(payload)
    body.setdefault(
        "content",
        "🔺 Mnemosyne: rule {rule!r} READY TO ESCALATE — "
        "{warns} warn(s) in {days}d (threshold {thr}). "
        "Promote with: python -m enforce.audit --apply".format(
            rule=payload.get("rule"),
            warns=payload.get("warns_in_window"),
            days=payload.get("window_days"),
            thr=payload.get("threshold"),
        ),
    )
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        # Scheme is allow-listed above; `# nosec` is bandit's marker and semgrep
        # needs its own, on the line immediately preceding the finding.
        # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
        with urllib.request.urlopen(req, timeout=WEBHOOK_TIMEOUT_SECS) as resp:  # nosec B310 — scheme allow-listed above
            status = getattr(resp, "status", 200)
            return 200 <= status < 300
    except Exception as exc:  # network errors must not break the audit run
        _log.warning("webhook post to %s failed: %s", url, exc)
        return False


def _format_table(rules: list[dict[str, Any]], threshold: Optional[int]) -> str:
    """Render rules as a fixed-width text table for human consumption."""
    if not rules:
        return "(no audit logs found)"

    headers = ("rule", "warns", "blocks", "allows", "skips", "total", "first_seen", "last_seen")
    widths = [
        max(len(h), max((len(str(r.get(h.replace("skips", "skip_overrides"), ""))) for r in rules), default=0))
        for h in headers
    ]

    def fmt_row(values: list[str]) -> str:
        return "  ".join(v.ljust(w) for v, w in zip(values, widths, strict=True))

    lines = [fmt_row(list(headers))]
    lines.append(fmt_row(["-" * w for w in widths]))
    for r in rules:
        lines.append(fmt_row([
            str(r["rule"]),
            str(r.get("warns", 0)),
            str(r["blocks"]),
            str(r["allows"]),
            str(r["skip_overrides"]),
            str(r["total"]),
            str(r["first_seen"]),
            str(r["last_seen"]),
        ]))

    if threshold is not None:
        lines.append("")
        flagged = [r["rule"] for r in rules if r.get("escalation_candidate")]
        if flagged:
            lines.append(
                f"⚠️  {len(flagged)} rule(s) crossed threshold {threshold} (escalation candidates):"
            )
            for name in flagged:
                lines.append(f"  - {name}")
            lines.append(
                "Consider escalating to system prompt (--append-system-prompt) "
                "or CLAUDE.md, or auto-generating an additional tool hook."
            )
        else:
            lines.append(f"(no rules crossed threshold {threshold})")

    return "\n".join(lines)


def _format_ready_section(ready: list[dict[str, Any]]) -> str:
    """Render the READY TO ESCALATE block appended below the table."""
    lines = [
        "",
        f"🔺 READY TO ESCALATE — {len(ready)} rule(s) crossed their warn threshold:",
    ]
    for r in ready:
        lines.append(
            f"  - {r['rule']}: {r['warns_in_window']} warn(s) in "
            f"{r['escalation_window_days']}d (threshold "
            f"{r['escalation_threshold']}) — rule: {r['escalation_rule_path']}"
        )
    lines.append(
        "Promote with: python -m enforce.audit --apply   "
        "(flips mode: warn → block in the rule and regenerates the hook; "
        "review the audit log excerpts first — logs are operator-trust inputs)"
    )
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mnemosyne-audit",
        description=(
            "Aggregate hook firings (allow / block / skip-override) into "
            "per-rule stats. Phase 3 of the v2 enforcement layer — turns the "
            "audit JSONL written by generated hooks into a measurable "
            "feedback signal."
        ),
    )
    p.add_argument(
        "--logs-dir",
        type=Path,
        default=Path(DEFAULT_LOGS_DIR),
        help=f"Directory of *.audit.jsonl files (default: {DEFAULT_LOGS_DIR})",
    )
    def _non_negative_int(s: str) -> int:
        n = int(s)
        if n < 0:
            raise argparse.ArgumentTypeError(f"--threshold must be ≥ 0, got {n}")
        return n

    p.add_argument(
        "--threshold",
        type=_non_negative_int,
        default=None,
        help="Flag rules where blocks >= N as escalation candidates",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON to stdout",
    )
    # ---- v2.1.0: soft-to-hard escalation ----
    p.add_argument(
        "--memory-dir",
        type=Path,
        default=Path(DEFAULT_MEMORY_DIR),
        help=(
            "Memory entries to read escalation policies from "
            f"(default: {DEFAULT_MEMORY_DIR}; absent dir → escalation "
            "evaluation is skipped)"
        ),
    )
    p.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Promote READY rules: mode warn → block in the memory entry, "
            "then regenerate the hook. Prompts per rule unless --yes."
        ),
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="Skip the per-rule confirmation prompt (non-interactive runs)",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=Path(DEFAULT_OUTPUT_DIR),
        help=f"Where regenerated hooks land (default: {DEFAULT_OUTPUT_DIR})",
    )
    p.add_argument(
        "--template-dir",
        type=Path,
        default=None,
        help="Template directory override for hook regeneration",
    )
    p.add_argument(
        "--webhook-url",
        default=os.environ.get(WEBHOOK_ENV_VAR),
        help=(
            "POST a notification per READY rule (JSON; includes a "
            f"Discord-compatible `content` field). Default: ${WEBHOOK_ENV_VAR}"
        ),
    )
    p.add_argument(
        "--fail-on-escalation",
        action="store_true",
        help="Exit 3 when READY rules exist and were not applied (cron/CI alerting)",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose logging",
    )
    return p


def _confirm(prompt: str) -> bool:
    """Interactive y/N gate for --apply (bypassed by --yes)."""
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    _setup_logging(args.verbose)

    rules = aggregate_audit_logs(args.logs_dir)

    # Stamp escalation_candidate flag when threshold is set (legacy,
    # all-time block counting — unchanged contract)
    if args.threshold is not None:
        for r in rules:
            r["escalation_candidate"] = r["blocks"] >= args.threshold

    # v2.1.0 — join declared escalation policies and evaluate windows.
    # Absent memory dir degrades to the legacy report (no new fields).
    ready: list[dict[str, Any]] = []
    configs = load_escalation_configs(args.memory_dir)
    if configs:
        ready = evaluate_escalations(rules, configs)

    if args.json:
        print(json.dumps(rules, indent=2))
    else:
        out = _format_table(rules, args.threshold)
        if ready:
            out += "\n" + _format_ready_section(ready)
        print(out)

    if ready and args.webhook_url:
        for r in ready:
            _post_webhook(args.webhook_url, {
                "rule": r["rule"],
                "warns_in_window": r["warns_in_window"],
                "threshold": r["escalation_threshold"],
                "window_days": r["escalation_window_days"],
                "log_path": r["log_path"],
            })

    apply_failures = 0
    applied = 0
    if ready and args.apply:
        template_dir = args.template_dir
        if template_dir is None:
            from .cli import _default_template_dir
            template_dir = _default_template_dir()
        for r in ready:
            rule_path = Path(r["escalation_rule_path"])
            if not args.yes and not _confirm(
                f"Promote {r['rule']} (mode warn → block, regenerate "
                f"{rule_path.name})? [y/N] "
            ):
                _log.info("skipped %s (operator declined)", r["rule"])
                continue
            rc = apply_escalation(rule_path, template_dir, args.output_dir)
            if rc == 0:
                applied += 1
                _log.info("promoted %s to mode: block", r["rule"])
            else:
                apply_failures += 1

    _log.info("aggregated %d rule(s) from %s", len(rules), args.logs_dir)

    if apply_failures:
        return 1
    if ready and not applied and args.fail_on_escalation:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
