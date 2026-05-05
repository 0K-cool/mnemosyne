"""Unit tests for lib/enforce/cli.py — `mnemosyne enforce` CLI.

The CLI walks a memory directory, runs the generator on every entry with
an `enforce` block, writes resulting hook source to `.claude/hooks/auto/`,
and reports orphan hooks (files in the output dir not produced by any
memory entry this run).

Behavior contract:
  - Memory entries WITHOUT `enforce` blocks are silently skipped (legal v1 entries).
  - Generation errors on individual entries do NOT halt the run; they are
    logged and the CLI exits non-zero overall.
  - --dry-run prints what would happen without writing anything.
  - --force overwrites existing hook files (default: skip if identical).
  - --rule <path> processes only that single memory file.
  - Orphans are reported but never deleted automatically.
"""

import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

LIB_DIR = Path(__file__).parent.parent / "lib"
TEMPLATE_DIR = Path(__file__).parent.parent / "templates" / "hooks"
sys.path.insert(0, str(LIB_DIR))

from enforce.cli import main as cli_main  # noqa: E402


CR_PREPUSH_RULE = """\
---
name: cr-prepush-rule
type: feedback
enforce:
  tool: Bash
  pattern: "git push -u origin"
  hook: .claude/hooks/auto/cr-prepush.ts
  generated_from: memory/cr-prepush.md
---
Body.
"""

NO_ENFORCE_RULE = """\
---
name: just-prose
type: feedback
description: A normal recall-only memory entry without an enforce block.
---
Body.
"""

INVALID_ENFORCE = """\
---
name: invalid
enforce:
  tool: NotARealTool
  pattern: "x"
  hook: .claude/hooks/auto/x.ts
  generated_from: memory/x.md
---
Body.
"""


def _run_cli(*args: str) -> tuple[int, str, str]:
    """Run the CLI with captured stdout/stderr; return (exit_code, stdout, stderr)."""
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            rc = cli_main(list(args))
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else 1
    return rc, out.getvalue(), err.getvalue()


class TestEnforceCli(unittest.TestCase):
    """End-to-end CLI behavior — no mocks; real files."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.memory_dir = self.tmp / "memory"
        self.memory_dir.mkdir()
        self.output_dir = self.tmp / "hooks_auto"
        # Don't pre-create output_dir — CLI must mkdir on first write.

    def tearDown(self):
        self._tmp.cleanup()

    def _write_memory(self, name: str, body: str) -> Path:
        p = self.memory_dir / name
        p.write_text(body)
        return p

    def test_generates_hook_for_eligible_entry(self):
        self._write_memory("cr.md", CR_PREPUSH_RULE)

        rc, _, err = _run_cli(
            "--memory-dir", str(self.memory_dir),
            "--output-dir", str(self.output_dir),
            "--template-dir", str(TEMPLATE_DIR),
        )

        self.assertEqual(rc, 0, f"stderr: {err}")
        out_file = self.output_dir / "cr-prepush.ts"
        self.assertTrue(out_file.exists(), f"hook missing at {out_file}")
        content = out_file.read_text()
        self.assertIn("AUTO-GENERATED", content)
        self.assertIn("git push", content)

    def test_skips_entries_without_enforce_block(self):
        self._write_memory("plain.md", NO_ENFORCE_RULE)

        rc, _, err = _run_cli(
            "--memory-dir", str(self.memory_dir),
            "--output-dir", str(self.output_dir),
            "--template-dir", str(TEMPLATE_DIR),
        )

        self.assertEqual(rc, 0, f"stderr: {err}")
        # No hook should be produced
        self.assertFalse(self.output_dir.exists() and any(self.output_dir.iterdir()))

    def test_invalid_enforce_block_does_not_halt_run(self):
        self._write_memory("bad.md", INVALID_ENFORCE)
        self._write_memory("good.md", CR_PREPUSH_RULE)

        rc, _, err = _run_cli(
            "--memory-dir", str(self.memory_dir),
            "--output-dir", str(self.output_dir),
            "--template-dir", str(TEMPLATE_DIR),
        )

        # Bad entry: non-zero exit code; good entry: hook still written
        self.assertNotEqual(rc, 0, "expected non-zero exit when an entry fails")
        good_hook = self.output_dir / "cr-prepush.ts"
        self.assertTrue(good_hook.exists(), "good entry should still produce its hook")
        # Failure is reported on stderr
        self.assertIn("bad.md", err)

    def test_dry_run_writes_nothing(self):
        self._write_memory("cr.md", CR_PREPUSH_RULE)

        rc, out, err = _run_cli(
            "--memory-dir", str(self.memory_dir),
            "--output-dir", str(self.output_dir),
            "--template-dir", str(TEMPLATE_DIR),
            "--dry-run",
        )

        self.assertEqual(rc, 0, f"stderr: {err}")
        # Nothing written
        self.assertFalse(self.output_dir.exists() and any(self.output_dir.iterdir()))
        # User-facing summary shows the plan
        combined = out + err
        self.assertIn("cr-prepush.ts", combined)
        self.assertIn("dry-run", combined.lower())

    def test_idempotent_when_content_unchanged(self):
        self._write_memory("cr.md", CR_PREPUSH_RULE)

        rc1, _, _ = _run_cli(
            "--memory-dir", str(self.memory_dir),
            "--output-dir", str(self.output_dir),
            "--template-dir", str(TEMPLATE_DIR),
        )
        self.assertEqual(rc1, 0)
        out_file = self.output_dir / "cr-prepush.ts"
        first_mtime = out_file.stat().st_mtime
        first_content = out_file.read_text()

        # Second run: no input change, no force flag
        rc2, _, _ = _run_cli(
            "--memory-dir", str(self.memory_dir),
            "--output-dir", str(self.output_dir),
            "--template-dir", str(TEMPLATE_DIR),
        )
        self.assertEqual(rc2, 0)
        # Content unchanged (modulo the GENERATED_AT timestamp). Idempotent
        # behavior contract: if nothing material changed, file is not rewritten.
        # We accept either same mtime (skip-on-unchanged) OR matching content
        # body apart from the generated-at line.
        second_content = out_file.read_text()
        # Strip the timestamp-bearing line for stable comparison
        def _strip_timestamp(s: str) -> str:
            return "\n".join(
                line for line in s.splitlines()
                if "Generated at:" not in line
            )
        self.assertEqual(_strip_timestamp(first_content), _strip_timestamp(second_content))

    def test_orphan_hook_reported(self):
        # Pre-create an orphan hook file with no matching memory entry
        self.output_dir.mkdir()
        orphan = self.output_dir / "orphan.ts"
        orphan.write_text("// orphan hook\n")
        self._write_memory("cr.md", CR_PREPUSH_RULE)

        rc, out, err = _run_cli(
            "--memory-dir", str(self.memory_dir),
            "--output-dir", str(self.output_dir),
            "--template-dir", str(TEMPLATE_DIR),
        )

        self.assertEqual(rc, 0)
        # Orphan still exists (CLI never auto-deletes)
        self.assertTrue(orphan.exists())
        # Orphan is named in the report
        combined = out + err
        self.assertIn("orphan.ts", combined)
        self.assertIn("orphan", combined.lower())

    def test_duplicate_hook_targets_rejected(self):
        """Two memory entries pointing at the same output hook fail loudly."""
        # Both entries declare the same `hook` path → second must be rejected.
        rule_a = CR_PREPUSH_RULE  # hook: .claude/hooks/auto/cr-prepush.ts
        rule_b = CR_PREPUSH_RULE.replace(
            "name: cr-prepush-rule",
            "name: cr-prepush-rule-clone",
        )
        self._write_memory("a.md", rule_a)
        self._write_memory("b.md", rule_b)

        rc, _, err = _run_cli(
            "--memory-dir", str(self.memory_dir),
            "--output-dir", str(self.output_dir),
            "--template-dir", str(TEMPLATE_DIR),
        )

        # Exit non-zero because one entry was rejected
        self.assertNotEqual(rc, 0)
        # The collision is reported clearly
        self.assertIn("duplicate hook target", err)
        # The first entry's hook still exists
        self.assertTrue((self.output_dir / "cr-prepush.ts").exists())

    def test_rule_flag_processes_single_file(self):
        self._write_memory("cr.md", CR_PREPUSH_RULE)
        # Plain entry that would normally be skipped — but with --rule we
        # don't even look at it, so a syntactically valid one with no
        # enforce block is fine to leave around.
        self._write_memory("plain.md", NO_ENFORCE_RULE)

        rc, _, err = _run_cli(
            "--rule", str(self.memory_dir / "cr.md"),
            "--output-dir", str(self.output_dir),
            "--template-dir", str(TEMPLATE_DIR),
        )

        self.assertEqual(rc, 0, f"stderr: {err}")
        out_file = self.output_dir / "cr-prepush.ts"
        self.assertTrue(out_file.exists())


class TestEnforceSymlinkDefense(unittest.TestCase):
    """v2.0.0 audit (CRIT-2) — symlink-follow arbitrary file overwrite.

    Pre-fix: ``out_path.write_text()`` and ``os.chmod()`` both follow
    symlinks. An attacker who pre-stages a symlink at the hook output
    path can have ``mnemosyne enforce`` overwrite (and chmod 755) any
    user-writable file on the system.

    Post-fix: pre-check refuses to write when out_path is already a
    symlink, and the write itself uses atomic rename (which replaces
    the directory entry without following any symlink that races in
    after the pre-check).
    """

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.memory_dir = self.tmp / "memory"
        self.memory_dir.mkdir()
        self.output_dir = self.tmp / "hooks_auto"
        self.output_dir.mkdir()

    def tearDown(self):
        self._tmp.cleanup()

    def _write_memory(self, name: str, body: str) -> Path:
        p = self.memory_dir / name
        p.write_text(body)
        return p

    def test_refuses_to_follow_symlink_at_output_path(self):
        """Pre-staged symlink at hook output → write refused, victim untouched."""
        # Set up a victim file the attacker hopes to overwrite via
        # ".claude/hooks/auto/cr-prepush.ts → victim.txt" symlink.
        victim = self.tmp / "victim.txt"
        original_content = "ORIGINAL VICTIM CONTENT"
        victim.write_text(original_content)
        original_mode = 0o644
        victim.chmod(original_mode)

        # Attacker-controlled symlink lands at the path mnemosyne enforce
        # is about to write to.
        target_path = self.output_dir / "cr-prepush.ts"
        target_path.symlink_to(victim)
        self.assertTrue(target_path.is_symlink())

        # Write a memory entry that would cause writing to that path.
        self._write_memory("cr.md", CR_PREPUSH_RULE)

        rc, _, err = _run_cli(
            "--memory-dir", str(self.memory_dir),
            "--output-dir", str(self.output_dir),
            "--template-dir", str(TEMPLATE_DIR),
        )

        # CLI exits non-zero because the entry failed.
        self.assertNotEqual(rc, 0, "expected failure when symlink at output")

        # Victim file content MUST NOT be the rendered hook source.
        self.assertEqual(
            victim.read_text(),
            original_content,
            "CRIT-2: symlink was followed, victim file overwritten",
        )

        # Victim file mode MUST NOT have been chmod'd to 0o755.
        self.assertEqual(
            victim.stat().st_mode & 0o777,
            original_mode,
            "CRIT-2: symlink was followed, victim file mode changed",
        )

        # The error message should clearly identify the symlink as the
        # cause so the operator can investigate (vs a generic IOError).
        self.assertIn("symlink", err.lower())

    def test_atomic_replace_overwrites_regular_file(self):
        """Pre-existing regular file at output path → atomic replace works."""
        target_path = self.output_dir / "cr-prepush.ts"
        target_path.write_text("// stale hook content")

        self._write_memory("cr.md", CR_PREPUSH_RULE)

        rc, _, err = _run_cli(
            "--memory-dir", str(self.memory_dir),
            "--output-dir", str(self.output_dir),
            "--template-dir", str(TEMPLATE_DIR),
            "--force",
        )

        self.assertEqual(rc, 0, f"stderr: {err}")
        # New content lands at the target.
        self.assertIn("AUTO-GENERATED", target_path.read_text())
        # Mode is 0o755 (executable).
        self.assertEqual(target_path.stat().st_mode & 0o777, 0o755)

    def test_no_tmp_files_left_behind_on_success(self):
        """Atomic write must not leak .tmp sidecars on the happy path."""
        self._write_memory("cr.md", CR_PREPUSH_RULE)

        rc, _, err = _run_cli(
            "--memory-dir", str(self.memory_dir),
            "--output-dir", str(self.output_dir),
            "--template-dir", str(TEMPLATE_DIR),
        )

        self.assertEqual(rc, 0, f"stderr: {err}")
        leftover = list(self.output_dir.glob(".*.tmp")) + list(
            self.output_dir.glob("*.tmp")
        )
        self.assertEqual(leftover, [], f"temp files leaked: {leftover}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
