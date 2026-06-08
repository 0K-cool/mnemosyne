"""Tests for #29 — `mnemosyne enforce --sync` retirement pass.

Archiving or deleting a rule must not leave its generated hook
silently enforcing forever (the missing half of the rule↔hook
contract). `--sync` turns the existing orphan WARNING into a gated
cleanup: provenance-checked, operator-confirmed deletion of
Mnemosyne-generated orphans only.
"""

import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock
import shutil
import tempfile

LIB_DIR = Path(__file__).parent.parent / "lib"
TEMPLATE_DIR = Path(__file__).parent.parent / "templates" / "hooks"
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "enforce"
sys.path.insert(0, str(LIB_DIR))

from enforce.cli import main  # noqa: E402


def _run_main(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def _rule_md(name: str) -> str:
    return (
        "---\n"
        f"name: {name}\n"
        "type: feedback\n"
        "enforce:\n"
        "  tool: Bash\n"
        f'  pattern: "{name} --danger"\n'
        f"  hook: .claude/hooks/auto/{name}.ts\n"
        f"  generated_from: memory/{name}.md\n"
        "  template: block-on-match-guard.ts.template\n"
        "---\nBody.\n"
    )


class _SyncTree(unittest.TestCase):
    """memory/ with rule `keep`; output dir seeded with hooks for
    `keep` AND `retired` (whose rule is then deleted → orphan)."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="mnz-sync-"))
        self.memory = self.root / "memory"
        self.out = self.root / "hooks"
        self.memory.mkdir(parents=True)
        (self.memory / "keep.md").write_text(_rule_md("keep"))
        (self.memory / "retired.md").write_text(_rule_md("retired"))
        rc, _, _ = _run_main(self._argv())
        assert rc == 0, "fixture generation failed"
        assert (self.out / "retired.ts").exists()
        # Retire the rule — the generated hook is now an orphan.
        (self.memory / "retired.md").unlink()
        # Simulate runtime history the hook wrote.
        (self.out / "retired.audit.jsonl").write_text('{"event":"block"}\n')

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _argv(self, *extra: str) -> list[str]:
        return [
            "--memory-dir", str(self.memory),
            "--output-dir", str(self.out),
            "--template-dir", str(TEMPLATE_DIR),
            *extra,
        ]


class TestSyncDeletion(_SyncTree):
    def test_sync_yes_deletes_orphan_keeps_live_hook(self):
        rc, _, err = _run_main(self._argv("--sync", "--yes"))
        self.assertEqual(rc, 0)
        self.assertFalse((self.out / "retired.ts").exists(), "orphan not deleted")
        self.assertTrue((self.out / "keep.ts").exists(), "live hook must survive")

    def test_sync_preserves_audit_sidecar(self):
        """Runtime history outlives the hook — sidecars are never deleted."""
        _run_main(self._argv("--sync", "--yes"))
        self.assertTrue((self.out / "retired.audit.jsonl").exists())

    def test_sync_prints_provenance_and_settings_reminder(self):
        rc, _, err = _run_main(self._argv("--sync", "--yes"))
        self.assertIn("memory/retired.md", err)   # source provenance
        self.assertIn("MISSING", err)
        self.assertIn("settings.json", err)        # deregistration reminder
        self.assertIn("retired.ts", err)

    def test_sync_decline_keeps_orphan(self):
        with mock.patch("builtins.input", return_value="n"):
            rc, _, _ = _run_main(self._argv("--sync"))
        self.assertEqual(rc, 0)
        self.assertTrue((self.out / "retired.ts").exists())

    def test_sync_confirm_deletes_orphan(self):
        with mock.patch("builtins.input", return_value="y"):
            rc, _, _ = _run_main(self._argv("--sync"))
        self.assertEqual(rc, 0)
        self.assertFalse((self.out / "retired.ts").exists())


class TestSyncGuards(_SyncTree):
    def test_foreign_file_never_deleted(self):
        """A file without the Mnemosyne header is reported, never touched —
        even under --yes. hooks/auto/ may contain hand-written hooks."""
        foreign = self.out / "hand-written.ts"
        foreign.write_text("#!/usr/bin/env bun\n// my custom hook\n")
        rc, _, err = _run_main(self._argv("--sync", "--yes"))
        self.assertEqual(rc, 0)
        self.assertTrue(foreign.exists(), "foreign file must never be deleted")
        self.assertIn("hand-written.ts", err)
        self.assertIn("no Mnemosyne header", err)

    def test_sync_dry_run_reports_without_deleting(self):
        rc, _, err = _run_main(self._argv("--sync", "--dry-run", "--yes"))
        self.assertEqual(rc, 0)
        self.assertTrue((self.out / "retired.ts").exists())
        self.assertIn("retired.ts", err)

    def test_sync_incompatible_with_rule(self):
        rc, _, _ = _run_main(self._argv(
            "--sync", "--yes", "--rule", str(self.memory / "keep.md"),
        ))
        self.assertEqual(rc, 2)

    def test_no_sync_keeps_legacy_warning_behavior(self):
        """Without --sync, orphans are warned about and untouched."""
        rc, _, err = _run_main(self._argv("--yes"))
        self.assertEqual(rc, 0)
        self.assertTrue((self.out / "retired.ts").exists())
        self.assertIn("orphan", err)


if __name__ == "__main__":
    unittest.main(verbosity=2)
