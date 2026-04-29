"""`mnemosyne enforce` — generate Claude Code hooks from memory entries.

Walks a directory of markdown memory entries, runs the v2 generator on
every entry that declares an `enforce` block, writes the rendered hook
to the output directory (default: `.claude/hooks/auto/`), and reports
orphan hook files (files in the output dir that no memory entry produced).

Usage:
  python -m enforce [--memory-dir DIR] [--output-dir DIR]
                    [--template-dir DIR] [--rule PATH]
                    [--dry-run] [--force] [-v]

Or via the slash command (Phase 1.3, future): /mnemosyne-enforce

Exit codes:
  0 — all eligible entries generated successfully (orphans are reported but
      do not change exit code)
  1 — at least one memory entry failed (parse / schema / generation error)
  2 — invalid CLI arguments / missing inputs

Behavior contract is locked by tests/test_enforce_cli.py — change carefully.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from pathlib import Path
from typing import Optional

from .generator import GenerationError, generate_hook, parse_memory_entry
from .schema import HOOK_PATH_PREFIX, EnforceValidationError

_log = logging.getLogger("mnemosyne.enforce")

# Default output dir is the convention from the Phase 1 design doc:
# .claude/hooks/auto/ relative to the working dir. Operators can override.
DEFAULT_OUTPUT_DIR = ".claude/hooks/auto"
DEFAULT_TEMPLATE_DIR_NAME = "templates/hooks"


def _default_template_dir() -> Path:
    """Locate the bundled templates dir, relative to this package install."""
    return Path(__file__).resolve().parent.parent.parent / DEFAULT_TEMPLATE_DIR_NAME


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mnemosyne-enforce",
        description=(
            "Generate Claude Code hooks from memory entries that declare an "
            "`enforce` block. Memory becomes the source of truth for runtime "
            "enforcement, not just recall."
        ),
    )
    p.add_argument(
        "--memory-dir",
        type=Path,
        default=Path("memory"),
        help="Directory of *.md memory entries to scan (default: ./memory)",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=Path(DEFAULT_OUTPUT_DIR),
        help=f"Where to write generated hooks (default: {DEFAULT_OUTPUT_DIR})",
    )
    p.add_argument(
        "--template-dir",
        type=Path,
        default=None,
        help="Where to find hook templates (default: bundled templates/hooks)",
    )
    p.add_argument(
        "--rule",
        type=Path,
        default=None,
        help="Generate only the hook for this single memory entry path",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be generated without writing anything",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing hook even if content is unchanged",
    )
    p.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose logging",
    )
    return p


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )


def _iter_memory_files(memory_dir: Path) -> list[Path]:
    """All `*.md` files under memory_dir, recursive, sorted for determinism."""
    if not memory_dir.exists():
        return []
    return sorted(memory_dir.rglob("*.md"))


_GENERATED_AT_RE = re.compile(r"^// Generated at:.*$", re.MULTILINE)


def _content_equivalent(existing: str, fresh: str) -> bool:
    """True iff `existing` and `fresh` differ only in the GENERATED_AT line.

    This lets us be idempotent across runs: if the rule + template haven't
    changed, the hook isn't rewritten just because the timestamp is newer.
    """
    return _GENERATED_AT_RE.sub("", existing) == _GENERATED_AT_RE.sub("", fresh)


def _process_one(
    memory_path: Path,
    output_dir: Path,
    template_dir: Path,
    *,
    dry_run: bool,
    force: bool,
) -> tuple[bool, Optional[str], Optional[Path]]:
    """Generate hook for one memory entry.

    Returns (ok, error_message, hook_output_path).
    Returns (True, None, None) for entries without an `enforce` block —
    those are silently skipped, not failures.
    """
    try:
        md = memory_path.read_text(encoding="utf-8")
    except OSError as exc:
        return False, f"could not read {memory_path}: {exc}", None

    try:
        meta, _ = parse_memory_entry(md)
    except GenerationError as exc:
        return False, f"{memory_path.name}: {exc}", None

    if "enforce" not in meta:
        # Recall-only entry. Not eligible; not an error.
        return True, None, None

    try:
        hook_source = generate_hook(md, template_dir=template_dir)
    except (GenerationError, EnforceValidationError) as exc:
        return False, f"{memory_path.name}: {exc}", None

    # The hook output path comes from the validated enforce block.
    # Schema guarantees it starts with HOOK_PATH_PREFIX. Preserve any
    # nested subpath (e.g. `.claude/hooks/auto/sub/x.ts` keeps `sub/x.ts`)
    # so multiple rules can group hooks without name collisions.
    hook_relpath = meta["enforce"]["hook"]
    rel_under_prefix = hook_relpath[len(HOOK_PATH_PREFIX):] if hook_relpath.startswith(HOOK_PATH_PREFIX) else Path(hook_relpath).name
    out_path = output_dir / rel_under_prefix

    if dry_run:
        _log.info("[dry-run] would write %s (%d bytes)", out_path, len(hook_source))
        return True, None, out_path

    # Idempotent skip: if the existing hook is byte-equivalent (modulo timestamp),
    # don't rewrite. --force overrides.
    if not force and out_path.exists():
        try:
            existing = out_path.read_text(encoding="utf-8")
            if _content_equivalent(existing, hook_source):
                _log.debug("unchanged: %s (skipping write)", out_path)
                return True, None, out_path
        except OSError:
            pass  # fall through to rewrite

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(hook_source, encoding="utf-8")
        # Make the generated hook executable so Claude Code can spawn it.
        # 0o755 (rwxr-xr-x) matches the PAI hook convention; world-read+exec
        # is required because the hook is invoked from contexts where the
        # effective uid may differ. nosec: intentional + matches convention.
        os.chmod(out_path, 0o755)  # nosec B103  # nosemgrep
        _log.info("wrote %s", out_path)
    except OSError as exc:
        return False, f"{memory_path.name}: write failed: {exc}", out_path

    return True, None, out_path


# Sidecar files written next to a generated hook (audit logs). Not hooks.
_AUDIT_SIDECAR_SUFFIXES: tuple[str, ...] = (".audit.jsonl", ".audit.json")


def _report_orphans(output_dir: Path, produced: set[Path]) -> list[Path]:
    """List hook files in output_dir that no memory entry produced this run.

    Walks recursively (nested hook subdirectories are valid) and ignores
    sidecar files (audit logs) that the hooks themselves create at runtime.
    Path comparison is done on resolved/absolute paths so producer-vs-orphan
    matching works regardless of how the caller wrote the path.
    """
    if not output_dir.exists():
        return []

    produced_resolved = {p.resolve() for p in produced}
    orphans: list[Path] = []
    for child in sorted(output_dir.rglob("*")):
        if not child.is_file():
            continue
        if any(child.name.endswith(suffix) for suffix in _AUDIT_SIDECAR_SUFFIXES):
            continue
        if child.resolve() not in produced_resolved:
            orphans.append(child)
    return orphans


def main(argv: Optional[list[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    _setup_logging(args.verbose)

    template_dir = args.template_dir or _default_template_dir()
    if not template_dir.exists():
        _log.error("template-dir does not exist: %s", template_dir)
        return 2

    if args.rule is not None:
        if not args.rule.exists():
            _log.error("--rule path does not exist: %s", args.rule)
            return 2
        memory_files = [args.rule]
    else:
        memory_files = _iter_memory_files(args.memory_dir)
        if not memory_files:
            _log.warning("no memory entries found under %s", args.memory_dir)

    successes = 0
    failures = 0
    eligible = 0
    produced: set[Path] = set()

    for mf in memory_files:
        ok, err, out_path = _process_one(
            mf,
            args.output_dir,
            template_dir,
            dry_run=args.dry_run,
            force=args.force,
        )
        if ok:
            if out_path is not None:
                eligible += 1
                successes += 1
                produced.add(out_path)
        else:
            failures += 1
            # _process_one's contract: when ok is False, err is always set.
            # Use a defensive fallback rather than assert (Bandit B101 — assert
            # can be stripped under -O so production code shouldn't rely on it).
            # Use print() for user-facing errors so they respect the current
            # sys.stderr stream (cooperates with redirect_stderr in tests).
            print(f"ERROR: {err or '<unknown failure>'}", file=sys.stderr)

    # Orphan report — only meaningful when scanning a full memory dir, not
    # for --rule single-entry runs. Use print() instead of logging so the
    # report reaches captured streams in tests.
    if args.rule is None and not args.dry_run:
        orphans = _report_orphans(args.output_dir, produced)
        if orphans:
            print(
                f"WARNING: found {len(orphans)} orphan hook(s) in "
                f"{args.output_dir} (no matching memory entry):",
                file=sys.stderr,
            )
            for o in orphans:
                print(f"  orphan: {o.name}", file=sys.stderr)
            print(
                "orphans are NOT auto-deleted; review and rm by hand if obsolete",
                file=sys.stderr,
            )

    if args.dry_run:
        plan = [str(p.name) for p in sorted(produced)]
        if plan:
            print(f"dry-run: would generate {len(plan)} hook(s): {', '.join(plan)}")
        else:
            print("dry-run: no eligible memory entries found")

    print(
        f"done: {eligible} eligible, {successes} generated, {failures} failed",
        file=sys.stderr,
    )
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
