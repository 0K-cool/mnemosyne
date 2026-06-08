"""`mnemosyne enforce` — generate Claude Code hooks from memory entries.

Walks a directory of markdown memory entries, runs the v2 generator on
every entry that declares an `enforce` block, writes the rendered hook
to the output directory (default: `.claude/hooks/auto/`), and reports
orphan hook files (files in the output dir that no memory entry produced).

Usage:
  python -m enforce [--memory-dir DIR] [--output-dir DIR]
                    [--template-dir DIR] [--rule PATH]
                    [--dry-run] [--force] [--sync] [--yes] [-v]

Or via the slash command (Phase 1.3, future): /mnemosyne-enforce

v2.1.0 — `--sync` upgrades the orphan report into a gated retirement
pass (#29): generated hooks whose source rule was archived/deleted are
offered for deletion (provenance header required; per-file confirmation
unless --yes; audit sidecars kept; with --dry-run, report only).

Exit codes:
  0 — all eligible entries generated successfully (orphans are reported but
      do not change exit code)
  1 — at least one memory entry failed (parse / schema / generation error),
      or a --sync deletion failed
  2 — invalid CLI arguments / missing inputs (incl. --sync with --rule)

Behavior contract is locked by tests/test_enforce_cli.py — change carefully.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import tempfile
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
    # ---- #29: retirement sync ----
    p.add_argument(
        "--sync",
        action="store_true",
        help=(
            "Retirement pass: offer to delete Mnemosyne-generated orphan "
            "hooks whose source rule no longer exists (archived/deleted). "
            "Prompts per file unless --yes; files without the Mnemosyne "
            "header are reported but never touched. With --dry-run, "
            "reports only."
        ),
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="Skip the per-file confirmation prompt for --sync deletions",
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
    reserved_outputs: set[Path],
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
    hook_relpath = Path(meta["enforce"]["hook"])
    try:
        rel_under_prefix = hook_relpath.relative_to(HOOK_PATH_PREFIX)
    except ValueError:
        # Schema-validated paths always start with HOOK_PATH_PREFIX, but be
        # defensive for direct generator users bypassing schema.
        rel_under_prefix = Path(hook_relpath.name)
    out_path = output_dir / rel_under_prefix

    # Reject duplicate hook targets — two memory entries pointing at the
    # same output path silently overwriting each other is a footgun.
    # resolve(strict=False) normalises the path (incl. symlinks like
    # /tmp → /private/tmp on macOS) without requiring the file to exist.
    out_resolved = out_path.resolve(strict=False)
    if out_resolved in reserved_outputs:
        return (
            False,
            f"{memory_path.name}: duplicate hook target {out_path} — already produced by another memory entry",
            out_path,
        )

    if dry_run:
        reserved_outputs.add(out_resolved)
        _log.info("[dry-run] would write %s (%d bytes)", out_path, len(hook_source))
        return True, None, out_path

    # v2.0.0 audit (CRIT-2 + CR follow-up) — refuse to follow a symlink at
    # out_path. This MUST run BEFORE the idempotent-skip read below: if
    # an attacker pre-stages a symlink whose target already contains
    # content equivalent to the rendered hook, the read_text path would
    # otherwise return success and leave the symlink installed for later
    # target-swap. Path.write_text uses open(O_WRONLY|O_CREAT|O_TRUNC)
    # which follows symlinks; the atomic rename below additionally
    # replaces the directory entry without following any symlink that
    # races in after this check.
    if out_path.is_symlink():
        return (
            False,
            f"{memory_path.name}: refusing to write — {out_path} is a "
            f"symlink (potential symlink attack on the hook output path)",
            out_path,
        )

    # Idempotent skip: if the existing hook is byte-equivalent (modulo timestamp),
    # don't rewrite. --force overrides.
    if not force and out_path.exists():
        try:
            existing = out_path.read_text(encoding="utf-8")
            if _content_equivalent(existing, hook_source):
                reserved_outputs.add(out_resolved)
                _log.debug("unchanged: %s (skipping write)", out_path)
                return True, None, out_path
        except OSError:
            pass  # fall through to rewrite

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)

        # Atomic, symlink-safe write (CRIT-2 fix):
        #   1. mkstemp creates a sibling temp file with O_EXCL — attacker
        #      cannot pre-stage it.
        #   2. os.fchmod operates on the fd, bypassing umask interference
        #      (the operator's umask shouldn't downgrade hook executable
        #      bits).
        #   3. os.rename(tmp, out_path) atomically replaces the directory
        #      entry. If out_path is a symlink, rename replaces the
        #      symlink itself (does NOT follow it). POSIX guarantees
        #      atomicity within the same filesystem.
        # 0o755 (rwxr-xr-x) matches the PAI hook convention; world-read+exec
        # required because the hook is invoked from contexts where the
        # effective uid may differ. nosec: intentional + matches convention.
        fd, tmp_str = tempfile.mkstemp(
            prefix=f".{out_path.name}.",
            suffix=".tmp",
            dir=str(out_path.parent),
        )
        tmp_path = Path(tmp_str)
        try:
            os.fchmod(fd, 0o755)  # nosec B103  # nosemgrep
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(hook_source)
            os.rename(tmp_path, out_path)
        except Exception:
            # Best-effort cleanup; the open fd is already closed by fdopen
            # on its own __exit__. If fdopen raised before taking ownership,
            # we still need to close the fd we opened via mkstemp.
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                if tmp_path.exists():
                    tmp_path.unlink()
            except OSError:
                pass
            raise

        reserved_outputs.add(out_resolved)
        _log.info("wrote %s", out_path)
    except OSError as exc:
        return False, f"{memory_path.name}: write failed: {exc}", out_path

    return True, None, out_path


# Sidecar files written next to a generated hook (audit logs). Not hooks.
_AUDIT_SIDECAR_SUFFIXES: tuple[str, ...] = (".audit.jsonl", ".audit.json")


def _relative_to_output(p: Path, output_dir: Path) -> str:
    """Render `p` as a string path relative to `output_dir` when possible.
    Falls back to basename if `p` is outside `output_dir` (defensive)."""
    try:
        return str(p.relative_to(output_dir))
    except ValueError:
        return p.name


_GENERATED_MARKER = "AUTO-GENERATED by Mnemosyne"
_SOURCE_LINE_RE = re.compile(r"Source memory entry:\s*(\S+)")
_PROVENANCE_HEAD_LINES = 10


def _orphan_provenance(path: Path) -> tuple[bool, Optional[str]]:
    """Inspect an orphan's header: (is_mnemosyne_generated, source_path).

    Only the first few lines are read — every generated hook carries the
    AUTO-GENERATED banner and ``Source memory entry:`` attribution in its
    header, regardless of language port. Unreadable files are treated as
    foreign (never eligible for deletion).
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            head = [next(fh, "") for _ in range(_PROVENANCE_HEAD_LINES)]
    except OSError:
        return False, None
    text = "".join(head)
    if _GENERATED_MARKER not in text:
        return False, None
    m = _SOURCE_LINE_RE.search(text)
    return True, m.group(1) if m else None


def _confirm(prompt: str) -> bool:
    """Interactive y/N gate for --sync deletions (bypassed by --yes)."""
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


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

    if args.sync and args.rule is not None:
        # Orphan detection is only sound against a FULL memory walk — a
        # single-rule run would mark every other live hook as orphaned.
        _log.error("--sync is incompatible with --rule (needs a full memory walk)")
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
    # Tracks resolved output paths claimed by an entry processed earlier in
    # this run. Used by _process_one to detect duplicate-target collisions.
    reserved_outputs: set[Path] = set()

    for mf in memory_files:
        ok, err, out_path = _process_one(
            mf,
            args.output_dir,
            template_dir,
            reserved_outputs,
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
            # Defensive `or` fallback ensures we never print a None.
            # print() rather than logging so output respects sys.stderr in
            # tests (cooperates with redirect_stderr).
            print(f"ERROR: {err or '<unknown failure>'}", file=sys.stderr)

    # Orphan report — only meaningful when scanning a full memory dir, not
    # for --rule single-entry runs. Use print() instead of logging so the
    # report reaches captured streams in tests. --sync upgrades the report
    # to a gated retirement pass (#29); with --dry-run it reports only.
    sync_failures = 0
    if args.rule is None and (not args.dry_run or args.sync):
        orphans = _report_orphans(args.output_dir, produced)
        if orphans:
            print(
                f"WARNING: found {len(orphans)} orphan hook(s) in "
                f"{args.output_dir} (no matching memory entry):",
                file=sys.stderr,
            )
            # Anchor for resolving relative `generated_from` paths
            # ("memory/foo.md" is rooted at the memory dir's parent).
            anchor = args.memory_dir.resolve().parent
            for o in orphans:
                # Show the path relative to output_dir so nested orphans
                # (e.g. sub/foo.ts) stay distinguishable from a flat foo.ts.
                rel = _relative_to_output(o, args.output_dir)
                generated, source = _orphan_provenance(o)
                if not generated:
                    print(
                        f"  foreign file (no Mnemosyne header), not touching: {rel}",
                        file=sys.stderr,
                    )
                    continue
                src_state = "unknown source"
                if source:
                    src_exists = (anchor / source).exists()
                    src_state = f"source: {source} — {'present' if src_exists else 'MISSING'}"
                print(f"  orphan: {rel} ({src_state})", file=sys.stderr)

                if not args.sync or args.dry_run:
                    continue
                if not args.yes and not _confirm(f"Delete {rel}? [y/N] "):
                    print(f"  kept {rel} (operator declined)", file=sys.stderr)
                    continue
                try:
                    o.unlink()
                except OSError as exc:
                    print(f"ERROR: could not delete {rel}: {exc}", file=sys.stderr)
                    sync_failures += 1
                    continue
                print(
                    f"  deleted {rel} — audit sidecars kept. If this hook is "
                    f"registered in settings.json hooks config, remove that "
                    f"entry too (Mnemosyne never edits settings.json).",
                    file=sys.stderr,
                )
            if not args.sync:
                print(
                    "orphans are NOT auto-deleted; re-run with --sync for a "
                    "gated retirement pass",
                    file=sys.stderr,
                )

    if args.dry_run:
        plan = sorted(_relative_to_output(p, args.output_dir) for p in produced)
        if plan:
            print(f"dry-run: would generate {len(plan)} hook(s): {', '.join(plan)}")
        else:
            print("dry-run: no eligible memory entries found")

    print(
        f"done: {eligible} eligible, {successes} generated, {failures} failed",
        file=sys.stderr,
    )
    return 0 if failures == 0 and sync_failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
