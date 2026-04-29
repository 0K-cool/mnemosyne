"""Unit tests for lib/enforce/generator.py — memory entry → hook source.

The generator reads a memory entry's frontmatter, validates the `enforce`
block, picks a matching template, and substitutes parameters to produce
the hook source code as a string.

Templates (v0.1):
  templates/hooks/cr-prepush-guard.ts.template — git push gate template

Convention: templates use ${PARAM_NAME} placeholders, never positional.
"""

import re
import sys
import tempfile
import unittest
from pathlib import Path

LIB_DIR = Path(__file__).parent.parent / "lib"
TEMPLATE_DIR = Path(__file__).parent.parent / "templates" / "hooks"
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "enforce"
sys.path.insert(0, str(LIB_DIR))

from enforce.generator import (  # noqa: E402
    GenerationError,
    generate_hook,
    parse_memory_entry,
    pick_template,
)


class TestParseMemoryEntry(unittest.TestCase):
    """Memory entries are markdown with YAML frontmatter — parse out the enforce block."""

    def test_parses_frontmatter_and_extracts_enforce_block(self):
        md = (
            "---\n"
            "type: feedback\n"
            "description: Test rule\n"
            "enforce:\n"
            "  tool: Bash\n"
            "  pattern: 'git push -u origin'\n"
            "  hook: .claude/hooks/auto/cr-prepush.ts\n"
            "  generated_from: memory/test.md\n"
            "---\n"
            "\n"
            "Body text of the memory.\n"
        )
        meta, body = parse_memory_entry(md)
        self.assertEqual(meta["type"], "feedback")
        self.assertIn("enforce", meta)
        self.assertEqual(meta["enforce"]["tool"], "Bash")
        self.assertIn("Body text", body)

    def test_no_frontmatter_raises(self):
        with self.assertRaises(GenerationError):
            parse_memory_entry("Just a body, no frontmatter.\n")

    def test_no_enforce_block_returns_meta_without_it(self):
        """A memory entry without an `enforce` block parses but is not enforce-eligible."""
        md = (
            "---\n"
            "type: feedback\n"
            "description: just a note\n"
            "---\n"
            "\n"
            "Body.\n"
        )
        meta, _ = parse_memory_entry(md)
        self.assertNotIn("enforce", meta)


class TestPickTemplate(unittest.TestCase):
    """Templates are picked by tool + a coarse pattern match (e.g. 'git push' → cr-prepush)."""

    def test_git_push_pattern_picks_cr_prepush_template(self):
        path = pick_template(
            tool="Bash",
            pattern=r"git push -u origin",
            template_dir=TEMPLATE_DIR,
        )
        self.assertTrue(path.name.startswith("cr-prepush-guard"))

    def test_unknown_pattern_raises(self):
        with self.assertRaises(GenerationError):
            pick_template(
                tool="Bash",
                pattern=r"some-unknown-command-xyz",
                template_dir=TEMPLATE_DIR,
            )


class TestGenerateHook(unittest.TestCase):
    """End-to-end: memory entry → hook source string."""

    def test_cr_prepush_rule_produces_compilable_hook(self):
        """Given the cr-prepush memory fixture, the generator produces a valid hook."""
        fixture_path = FIXTURE_DIR / "cr-prepush-rule.md"
        self.assertTrue(fixture_path.exists(), f"fixture missing: {fixture_path}")
        md = fixture_path.read_text()

        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)

        # Must contain a shebang
        self.assertTrue(hook_source.startswith("#!"))
        # Must declare it is auto-generated (operator-readable header)
        self.assertIn("AUTO-GENERATED", hook_source)
        # Must reference the source memory entry
        self.assertIn("memory/feedback_zero_drift_cr_prepush.md", hook_source)
        # Must include the pattern from the enforce block
        self.assertIn("git push", hook_source)
        # Must NOT contain unfilled placeholder syntax
        self.assertNotIn("${PATTERN}", hook_source)
        self.assertNotIn("${TOOL}", hook_source)
        self.assertNotIn("${HOOK_PATH}", hook_source)

    def test_generated_hook_is_typescript_syntactically_valid(self):
        """Sanity: bun must accept the generated source."""
        fixture_path = FIXTURE_DIR / "cr-prepush-rule.md"
        md = fixture_path.read_text()
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)

        # Write to a temp file and ask bun to typecheck.
        # B404/B603 nosec: test-only path, hardcoded bun binary, temp file
        # is from tempfile module, arguments are constants — no untrusted input.
        import subprocess  # nosec B404
        with tempfile.NamedTemporaryFile(suffix=".ts", mode="w", delete=False) as fh:
            fh.write(hook_source)
            tmp = fh.name
        try:
            r = subprocess.run(  # nosec B603
                ["/Users/kelvinlomboy/.bun/bin/bun", "build", "--no-bundle", "--target=bun", tmp],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            # bun build returns 0 on syntax-clean files
            self.assertEqual(r.returncode, 0, f"bun build failed:\n{r.stderr}")
        finally:
            Path(tmp).unlink(missing_ok=True)

    def test_missing_enforce_block_raises(self):
        md = (
            "---\n"
            "type: feedback\n"
            "description: no enforce block\n"
            "---\n"
            "Body.\n"
        )
        with self.assertRaises(GenerationError):
            generate_hook(md, template_dir=TEMPLATE_DIR)


if __name__ == "__main__":
    unittest.main(verbosity=2)
