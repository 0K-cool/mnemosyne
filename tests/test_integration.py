"""Integration tests for ok-mnemosyne.

Tests cover:
  - Dual-mode detection in auto-retrieve.py (markdown fallback vs RAG)
  - Plugin structure (files, executability, schema)
"""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

PLUGIN_DIR = Path(__file__).parent.parent
HOOKS_DIR = PLUGIN_DIR / "hooks"
FIXTURES_DIR = Path(__file__).parent / "fixtures"

AUTO_RETRIEVE = str(HOOKS_DIR / "auto-retrieve.py")


class TestDualModeDetection(unittest.TestCase):
    """Test auto-retrieve.py hook in markdown-fallback mode."""

    def setUp(self):
        """Clean up stale session counters from previous runs."""
        import shutil
        state_dir = Path.home() / ".ok-mnemosyne" / "state"
        if state_dir.exists():
            for f in state_dir.glob("auto-retrieve-test-*.count"):
                f.unlink(missing_ok=True)

    def _run_hook(self, stdin_data: str, extra_env: dict | None = None) -> subprocess.CompletedProcess:
        """Run auto-retrieve.py as a subprocess with given stdin."""
        env = os.environ.copy()
        # Force RAG off so we exercise the markdown fallback path
        env["MNEMOSYNE_RAG_ENABLED"] = "false"
        env["MNEMOSYNE_RAG_PATH"] = "/nonexistent"
        env["VEX_RAG_PATH"] = "/nonexistent"
        env["MNEMOSYNE_MEMORY_DIR"] = str(FIXTURES_DIR)
        # Isolate session counter so tests don't bleed into each other
        env["CLAUDE_CODE_SESSION_ID"] = f"test-integration-{id(self)}"
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [sys.executable, AUTO_RETRIEVE],
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )

    def test_markdown_fallback_when_rag_disabled(self):
        """Markdown fallback returns continue=True and injects RSM context."""
        payload = json.dumps({
            "prompt": "I just accepted the RSM Puerto Rico cybersecurity compliance offer starting May 2026",
            "session_id": "test-md-fallback-001",
        })
        result = self._run_hook(payload)
        self.assertEqual(result.returncode, 0, msg=f"Hook exited non-zero: {result.stderr}")

        output = json.loads(result.stdout)
        self.assertTrue(output.get("continue"), "Expected continue=True in output")
        self.assertIn("additionalContext", output, "Expected additionalContext in output")

        ctx = output["additionalContext"]
        # The hook injects a "[Mnemosyne Auto-Retrieved]" header and file-sourced results.
        # "markdown" appears in the stderr progress line (not stdout); the stdout context
        # contains the retrieval header and the matched memory content.
        self.assertIn("Mnemosyne", ctx, "Expected '[Mnemosyne Auto-Retrieved]' header in additionalContext")
        self.assertIn("RSM", ctx, "Expected 'RSM' content in additionalContext")
        # Confirm the source label references a markdown file (ends in .md)
        self.assertIn(".md", ctx, "Expected a .md file source label in additionalContext")

    def test_short_prompt_passes_through(self):
        """Short prompts (< MIN_QUERY_LENGTH) pass through without additionalContext."""
        payload = json.dumps({"prompt": "yes", "session_id": "test-short-001"})
        result = self._run_hook(payload)
        self.assertEqual(result.returncode, 0, msg=f"Hook exited non-zero: {result.stderr}")

        output = json.loads(result.stdout)
        self.assertTrue(output.get("continue"), "Expected continue=True for short prompt")
        self.assertNotIn(
            "additionalContext",
            output,
            "Short prompts should NOT have additionalContext",
        )

    def test_empty_input_passes_through(self):
        """Empty stdin passes through with continue=True and no additionalContext."""
        result = self._run_hook("")
        self.assertEqual(result.returncode, 0, msg=f"Hook exited non-zero: {result.stderr}")

        output = json.loads(result.stdout)
        self.assertTrue(output.get("continue"), "Expected continue=True for empty input")
        self.assertNotIn(
            "additionalContext",
            output,
            "Empty input should NOT have additionalContext",
        )


class TestPluginStructure(unittest.TestCase):
    """Verify all required plugin files exist and are valid."""

    def test_plugin_json_exists(self):
        """plugin.json must exist at the plugin root."""
        self.assertTrue((PLUGIN_DIR / "plugin.json").is_file(), "plugin.json not found")

    def test_plugin_json_valid(self):
        """plugin.json must be valid JSON with name='ok-mnemosyne' and features.mcpServer=False."""
        plugin_path = PLUGIN_DIR / "plugin.json"
        with open(plugin_path) as fh:
            data = json.load(fh)

        self.assertEqual(data.get("name"), "ok-mnemosyne", "plugin.json name mismatch")
        self.assertFalse(
            data.get("features", {}).get("mcpServer"),
            "Expected features.mcpServer=false",
        )

    def test_all_hooks_exist(self):
        """All required hook files must exist in hooks/."""
        required_hooks = [
            "auto-retrieve.py",
            "auto-save-stop.sh",
            "precompact-save.sh",
            "memory-validation.ts",
        ]
        for hook in required_hooks:
            self.assertTrue(
                (HOOKS_DIR / hook).is_file(),
                f"Missing hook: hooks/{hook}",
            )

    def test_all_hooks_executable(self):
        """Python and shell hooks must have the execute bit set."""
        executable_hooks = [
            "auto-retrieve.py",
            "auto-save-stop.sh",
            "precompact-save.sh",
        ]
        for hook in executable_hooks:
            path = HOOKS_DIR / hook
            self.assertTrue(
                path.is_file(),
                f"Hook not found: hooks/{hook}",
            )
            self.assertTrue(
                os.access(path, os.X_OK),
                f"Hook not executable: hooks/{hook}",
            )

    def test_all_skills_exist(self):
        """Required skill SKILL.md files must exist in skills/."""
        required_skills = [
            "gotcha/SKILL.md",
            "mine-session/SKILL.md",
            "setup-rag/SKILL.md",
        ]
        for skill in required_skills:
            self.assertTrue(
                (PLUGIN_DIR / "skills" / skill).is_file(),
                f"Missing skill: skills/{skill}",
            )

    def test_templates_exist(self):
        """Required template files must exist in templates/."""
        required_templates = [
            "MEMORY.md",
            "identity.txt",
            "memory/README.md",
        ]
        for tmpl in required_templates:
            self.assertTrue(
                (PLUGIN_DIR / "templates" / tmpl).is_file(),
                f"Missing template: templates/{tmpl}",
            )

    def test_markdown_retriever_exists(self):
        """lib/markdown_retriever.py must exist."""
        self.assertTrue(
            (PLUGIN_DIR / "lib" / "markdown_retriever.py").is_file(),
            "Missing lib/markdown_retriever.py",
        )


if __name__ == "__main__":
    unittest.main()
