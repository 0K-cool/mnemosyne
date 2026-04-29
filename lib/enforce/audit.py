"""`mnemosyne audit` — aggregate hook firings into rule-level stats.

The hook templates write JSONL audit entries (one per fire) to
``.claude/logs/<rule>.audit.jsonl``. This module reads those files and
reports per-rule stats: allow / block / skip-override counts, first/last
seen timestamps, and (with ``--threshold``) flags rules that have crossed
a violation threshold as escalation candidates.

Usage:
  PYTHONPATH=lib python -m enforce.audit \\
    [--logs-dir DIR]      # default: .claude/logs
    [--threshold N]       # flag rules with blocks >= N
    [--json]              # machine-readable output
    [-v]

Exit codes:
  0 — successful aggregation (regardless of whether any rule crossed
      threshold; threshold flagging is informational only)
  2 — invalid CLI arguments

Behavior contract is locked by tests/test_enforce_audit.py — change carefully.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger("mnemosyne.audit")

DEFAULT_LOGS_DIR = ".claude/logs"
AUDIT_SUFFIX = ".audit.jsonl"


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )


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
                    if event == "block":
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


def _format_table(rules: list[dict[str, Any]], threshold: Optional[int]) -> str:
    """Render rules as a fixed-width text table for human consumption."""
    if not rules:
        return "(no audit logs found)"

    headers = ("rule", "blocks", "allows", "skips", "total", "first_seen", "last_seen")
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
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose logging",
    )
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    _setup_logging(args.verbose)

    rules = aggregate_audit_logs(args.logs_dir)

    # Stamp escalation_candidate flag when threshold is set
    if args.threshold is not None:
        for r in rules:
            r["escalation_candidate"] = r["blocks"] >= args.threshold

    if args.json:
        print(json.dumps(rules, indent=2))
    else:
        print(_format_table(rules, args.threshold))

    _log.info("aggregated %d rule(s) from %s", len(rules), args.logs_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
