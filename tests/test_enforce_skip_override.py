"""Behavioral tests for the skip-override path of generated guard hooks.

Issue #30: PreToolUse hooks inherit the *session* environment. An
env-var prefix on the guarded command (`VEX_SKIP_X=1 git push`) applies
to the command's process — which runs after the hook — so a hook that
reads `process.env` can never see it. The documented skip syntax must
be detected by parsing the command string from the hook's stdin
(`tool_input.command`).

Each test renders the cr-prepush template from the canonical fixture,
then invokes the hook as a subprocess (the way Claude Code calls it)
against a throwaway git repo, and asserts on exit code + audit log.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

LIB_DIR = Path(__file__).parent.parent / "lib"
TEMPLATE_DIR = Path(__file__).parent.parent / "templates" / "hooks"
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "enforce"
sys.path.insert(0, str(LIB_DIR))

from enforce.generator import generate_hook  # noqa: E402

SKIP_VAR = "VEX_SKIP_CR_PREPUSH"
AUDIT_REL = ".claude/logs/cr-prepush-enforcement.jsonl"


def _bun() -> str | None:
    bun = shutil.which("bun") or "/Users/kelvinlomboy/.bun/bin/bun"
    return bun if Path(bun).exists() else None


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(  # nosec B603, B607 — test fixture setup, constant args
        ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=15, check=True,
    )


class TestSkipOverride(unittest.TestCase):
    """Skip-override must be detectable from tool_input.command."""

    @classmethod
    def setUpClass(cls):
        if _bun() is None:
            raise unittest.SkipTest("bun not available")
        md = (FIXTURE_DIR / "cr-prepush-rule.md").read_text()
        cls.hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)

    def setUp(self):
        # PAI_DIR — where the hook resolves cache + audit paths.
        self.pai_dir = Path(tempfile.mkdtemp(prefix="mnz-skip-pai-"))
        # Throwaway repo: main + feature branch with a code-file diff,
        # origin matching the fixture's repo_filter (0K-cool org).
        self.repo = Path(tempfile.mkdtemp(prefix="mnz-skip-repo-"))
        _git(self.repo, "init", "-b", "main")
        _git(self.repo, "config", "user.email", "test@example.invalid")
        _git(self.repo, "config", "user.name", "Test")
        (self.repo / "app.ts").write_text("export const a = 1;\n")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-m", "init")
        _git(self.repo, "checkout", "-b", "feat/x")
        (self.repo / "app.ts").write_text("export const a = 2;\n")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-m", "change")
        _git(self.repo, "remote", "add", "origin", "git@github.com:0K-cool/fixture.git")

        self.hook_path = self.pai_dir / "cr-prepush.ts"
        self.hook_path.write_text(self.hook_source)

    def tearDown(self):
        shutil.rmtree(self.pai_dir, ignore_errors=True)
        shutil.rmtree(self.repo, ignore_errors=True)

    def _run_hook(self, command: str, extra_env: dict | None = None) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if k != SKIP_VAR}
        env["PAI_DIR"] = str(self.pai_dir)
        if extra_env:
            env.update(extra_env)
        stdin = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "cwd": str(self.repo),
        })
        return subprocess.run(  # nosec B603 — resolved bun, test subprocess
            [_bun(), str(self.hook_path)],
            input=stdin, capture_output=True, text=True, timeout=30, env=env,
        )

    def _audit_events(self) -> list[dict]:
        audit = self.pai_dir / AUDIT_REL
        if not audit.exists():
            return []
        return [json.loads(line) for line in audit.read_text().splitlines() if line.strip()]

    # ── Regression: issue #30 ───────────────────────────────────────────

    def test_skip_prefix_in_command_allows(self):
        """`VEX_SKIP_X=1 git push ...` as command prefix must skip-allow."""
        r = self._run_hook(f"{SKIP_VAR}=1 git push -u origin feat/x")
        self.assertEqual(r.returncode, 0, f"expected skip-allow, got block:\n{r.stderr}")
        events = self._audit_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "skip-override")
        self.assertEqual(events[0].get("via"), "command-prefix")

    def test_skip_prefix_on_compound_command_allows(self):
        """Prefix on a compound command (`|| fallback push`) still skips."""
        r = self._run_hook(
            f"{SKIP_VAR}=1 git push -u origin feat/x 2>&1 || {SKIP_VAR}=1 git push -u origin feat/x"
        )
        self.assertEqual(r.returncode, 0, f"expected skip-allow, got block:\n{r.stderr}")
        events = self._audit_events()
        self.assertEqual(events[0]["event"], "skip-override")

    def test_session_env_still_honored(self):
        """Var exported in the hook's own env (session-wide opt-out) skips."""
        r = self._run_hook("git push -u origin feat/x", extra_env={SKIP_VAR: "1"})
        self.assertEqual(r.returncode, 0, f"expected skip-allow, got block:\n{r.stderr}")
        events = self._audit_events()
        self.assertEqual(events[0]["event"], "skip-override")
        self.assertEqual(events[0].get("via"), "session-env")

    # ── Guards: conservative matching ───────────────────────────────────

    def test_no_skip_blocks(self):
        """Plain guarded command with no cache must block (control)."""
        r = self._run_hook("git push -u origin feat/x")
        self.assertEqual(r.returncode, 2)
        events = self._audit_events()
        self.assertEqual(events[0]["event"], "block")

    def test_skip_var_mid_command_does_not_skip(self):
        """Mention of the var anywhere but as command prefix must NOT skip."""
        r = self._run_hook(f"git push -u origin feat/x  # {SKIP_VAR}=1")
        self.assertEqual(r.returncode, 2, "mid-command mention must not satisfy the skip")

    def test_skip_var_wrong_value_does_not_skip(self):
        """`VEX_SKIP_X=0` prefix must NOT skip."""
        r = self._run_hook(f"{SKIP_VAR}=0 git push -u origin feat/x")
        self.assertEqual(r.returncode, 2)

    def test_skip_var_on_own_line_does_not_skip(self):
        """Assignment on its own line is a shell statement, not a command
        prefix — the push on the next line runs without the var. Must NOT skip."""
        r = self._run_hook(f"{SKIP_VAR}=1\ngit push -u origin feat/x")
        self.assertEqual(r.returncode, 2, "newline-separated assignment must not satisfy the skip")

    def test_skip_var_trailing_space_newline_does_not_skip(self):
        """Assignment + trailing space + newline is still a standalone
        statement, not a prefix on the next line's push. Must NOT skip."""
        r = self._run_hook(f"{SKIP_VAR}=1 \ngit push -u origin feat/x")
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
