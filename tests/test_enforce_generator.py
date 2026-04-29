"""Unit tests for lib/enforce/generator.py — memory entry → hook source.

The generator reads a memory entry's frontmatter, validates the `enforce`
block, picks a matching template, and substitutes parameters to produce
the hook source code as a string.

Templates (v0.1):
  templates/hooks/cr-prepush-guard.ts.template — git push gate template

Convention: templates use ${PARAM_NAME} placeholders, never positional.
"""

import re
import shutil
import subprocess  # nosec B404 — test-only; resolved bun binary, constant args
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


def _assert_bun_build_clean(test_case: unittest.TestCase, source: str) -> None:
    """Write the rendered TS to a temp file and assert bun accepts it.

    Centralises the temp-file + bun-build dance so each call site stays
    one line. Skips the test when bun isn't available on this machine.
    """
    bun = shutil.which("bun") or "/Users/kelvinlomboy/.bun/bin/bun"
    if not Path(bun).exists():
        test_case.skipTest("bun not available")

    with tempfile.NamedTemporaryFile(suffix=".ts", mode="w", delete=False) as fh:
        fh.write(source)
        tmp = fh.name
    try:
        r = subprocess.run(  # nosec B603 — resolved bun, constant args
            [bun, "build", "--no-bundle", "--target=bun", tmp],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        test_case.assertEqual(r.returncode, 0, f"bun build failed:\n{r.stderr}")
    finally:
        Path(tmp).unlink(missing_ok=True)


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
        _assert_bun_build_clean(self, hook_source)

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

    def test_newline_in_comment_param_does_not_inject_code(self):
        """A memory entry can't break out of `// comment` slots in the template.

        Defense-in-depth: even if a malicious memory entry sets generated_from
        to a value containing newlines (or U+2028 / U+2029 — JS line
        terminators), the substituted value must stay on one line. We verify
        two ways:
          1. No raw newline + JS statement appears outside a comment / string.
          2. The generated hook still compiles cleanly under `bun build`
             (the real invariant — if injection worked, bun would error).
        """
        md = (
            "---\n"
            "name: malicious\n"
            'enforce:\n'
            "  tool: Bash\n"
            '  pattern: "git push -u origin"\n'
            "  hook: .claude/hooks/auto/g.ts\n"
            '  generated_from: "memory/x.md\\nprocess.exit(1); // INJECTED"\n'
            "---\n"
            "Body.\n"
        )
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)

        # Check 1: the literal newline-then-statement sequence must not appear.
        # If it did, the value escaped its quoting (whether comment or string).
        self.assertNotIn("\nprocess.exit", hook_source)

        # Check 2: bun must still accept the source. A successful injection
        # would corrupt syntax (mismatched quotes / unexpected statements);
        # bun build returns non-zero. This is the strongest assertion.
        _assert_bun_build_clean(self, hook_source)


class TestPhase2Injection(unittest.TestCase):
    """Phase 2: generated hook emits additionalContext JSON when inject_on_match=true."""

    def _md(self, *, inject_on_match: bool, inject_text: str | None = None) -> str:
        inject_lines = [
            f"  inject_on_match: {str(inject_on_match).lower()}",
        ]
        if inject_text:
            inject_lines.append(f'  inject_text: "{inject_text}"')
        inject_block = "\n".join(inject_lines)
        return (
            "---\n"
            "name: phase2-test\n"
            "type: feedback\n"
            "enforce:\n"
            "  tool: Bash\n"
            '  pattern: "git push -u origin"\n'
            "  hook: .claude/hooks/auto/cr-prepush.ts\n"
            "  generated_from: memory/phase2-test.md\n"
            f"{inject_block}\n"
            "---\n"
            "Body of the memory entry.\n"
        )

    def test_inject_on_match_false_omits_injection_logic(self):
        """When inject_on_match=false, the hook does not emit additionalContext."""
        hook_source = generate_hook(
            self._md(inject_on_match=False),
            template_dir=TEMPLATE_DIR,
        )
        # No reference to additionalContext in the rendered hook
        self.assertNotIn("additionalContext", hook_source)

    def test_inject_on_match_true_emits_additional_context(self):
        """When inject_on_match=true, the hook contains additionalContext logic."""
        text = "Pre-push reminder: always run coderabbit review first."
        hook_source = generate_hook(
            self._md(inject_on_match=True, inject_text=text),
            template_dir=TEMPLATE_DIR,
        )
        self.assertIn("additionalContext", hook_source)
        # The injection text must be present somewhere in the rendered hook
        # (escaped as a JSON string literal — the template uses JSON.stringify
        # equivalent at generation time).
        self.assertIn("Pre-push reminder", hook_source)

    def test_inject_on_match_true_with_no_inject_text_uses_default(self):
        """When inject_on_match=true and no inject_text, generator falls back to memory body."""
        hook_source = generate_hook(
            self._md(inject_on_match=True, inject_text=None),
            template_dir=TEMPLATE_DIR,
        )
        # Memory body contains "Body of the memory entry."
        self.assertIn("additionalContext", hook_source)
        self.assertIn("Body of the memory entry", hook_source)

    def test_inject_text_with_curly_braces_does_not_trip_placeholder_check(self):
        """User-supplied {{...}} in inject_text must not trigger _render's residue check."""
        # If neutralisation is missing, generate_hook would raise GenerationError
        # because _render rejects rendered output containing {{IDENT}}.
        md = (
            "---\n"
            "name: curly-brace-test\n"
            "enforce:\n"
            "  tool: Bash\n"
            '  pattern: "git push -u origin"\n'
            "  hook: .claude/hooks/auto/cr-prepush.ts\n"
            "  generated_from: memory/cb.md\n"
            "  inject_on_match: true\n"
            "  inject_text: |\n"
            "    Reminder: do not use {{TOOL}}-style placeholders in your edits.\n"
            "---\n"
            "Body.\n"
        )
        # Should NOT raise — and the injected text should appear in flattened form
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        self.assertIn("additionalContext", hook_source)
        # Curly pairs broken with a space so they don't match the placeholder regex
        self.assertNotIn("{{TOOL}}", hook_source)
        self.assertIn("{ {TOOL} }", hook_source)

    def test_truncation_respects_token_budget(self):
        """Truncated inject_text must not exceed inject_token_budget * 4 chars."""
        # Use the smallest legal budget (1) for a tight bound: max 4 chars
        budget = 1
        long_text = "A" * 1000
        md = (
            "---\n"
            "name: trunc-test\n"
            "enforce:\n"
            "  tool: Bash\n"
            '  pattern: "git push -u origin"\n'
            "  hook: .claude/hooks/auto/cr-prepush.ts\n"
            "  generated_from: memory/t.md\n"
            "  inject_on_match: true\n"
            f"  inject_token_budget: {budget}\n"
            "  inject_text: |\n"
            f"    {long_text}\n"
            "---\n"
            "Body.\n"
        )
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # Pull the INJECT_TEXT literal out of the rendered source
        import re
        m = re.search(r'const INJECT_TEXT = "([^"]*)"', hook_source)
        self.assertIsNotNone(m, "INJECT_TEXT constant not found in rendered hook")
        injected = m.group(1)
        # Budget = 1 token = 4 chars. Even with the truncation suffix, total
        # rendered char count must not exceed the budget.
        self.assertLessEqual(len(injected), budget * 4,
            f"truncation exceeded budget: {len(injected)} > {budget * 4} chars")

    def test_injection_hook_compiles_under_bun(self):
        """Sanity: the rendered hook with injection is syntactically valid TS.

        Use a YAML literal-block for inject_text so quotes/backslashes survive
        the YAML round-trip cleanly — they're then escaped by json.dumps in
        the generator before substitution.
        """
        # Build the markdown directly to avoid YAML quoting fragility.
        md = (
            "---\n"
            "name: phase2-bun-test\n"
            "type: feedback\n"
            "enforce:\n"
            "  tool: Bash\n"
            '  pattern: "git push -u origin"\n'
            "  hook: .claude/hooks/auto/cr-prepush.ts\n"
            "  generated_from: memory/phase2-bun.md\n"
            "  inject_on_match: true\n"
            "  inject_text: |\n"
            "    Reminder with \"quotes\" and \\backslashes\\ to test escaping.\n"
            "---\n"
            "Body unused; explicit inject_text wins.\n"
        )
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        _assert_bun_build_clean(self, hook_source)


class TestPhase4PatternLibrary(unittest.TestCase):
    """Phase 4: generator dispatches via explicit `template` field + new block-on-match primitive."""

    def _md(self, *, pattern: str, template: str | None = None) -> str:
        lines = [
            "---",
            "name: phase4-test",
            "type: feedback",
            "enforce:",
            "  tool: Bash",
            f'  pattern: "{pattern}"',
            "  hook: .claude/hooks/auto/test.ts",
            "  generated_from: memory/p4.md",
        ]
        if template:
            lines.append(f"  template: {template}")
        lines.extend(["---", "Body."])
        return "\n".join(lines) + "\n"

    def test_explicit_template_field_overrides_dispatch(self):
        """When enforce.template is set, that template is used regardless of pattern."""
        # `git push` would normally pick cr-prepush-guard via TEMPLATE_PATTERNS,
        # but explicit override wins.
        md = self._md(pattern="git push -u origin", template="block-on-match-guard.ts.template")
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # block-on-match doesn't have CR-specific markers
        self.assertNotIn("CR PRE-PUSH GUARD", hook_source)
        # but does contain the block-on-match marker
        self.assertIn("BLOCK-ON-MATCH GUARD", hook_source)

    def test_block_on_match_template_renders(self):
        """The new primitive template renders for an arbitrary pattern."""
        md = self._md(pattern=r"rm -rf /", template="block-on-match-guard.ts.template")
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        self.assertIn("AUTO-GENERATED", hook_source)
        self.assertIn("BLOCK-ON-MATCH GUARD", hook_source)
        self.assertIn("rm -rf", hook_source)

    def test_block_on_match_template_compiles_under_bun(self):
        """Sanity: the new primitive produces syntactically valid TypeScript."""
        md = self._md(pattern=r"rm -rf /", template="block-on-match-guard.ts.template")
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        _assert_bun_build_clean(self, hook_source)

    def test_explicit_template_with_unknown_filename_raises(self):
        """If the user names a template that doesn't exist, fail loudly."""
        md = self._md(pattern="anything", template="does-not-exist.ts.template")
        with self.assertRaises(GenerationError):
            generate_hook(md, template_dir=TEMPLATE_DIR)

    def test_no_template_field_falls_back_to_pattern_dispatch(self):
        """Without enforce.template, TEMPLATE_PATTERNS is consulted (existing behaviour)."""
        # 'git push' pattern → cr-prepush-guard (existing dispatch)
        md = self._md(pattern="git push -u origin", template=None)
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        self.assertIn("CR PRE-PUSH GUARD", hook_source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
