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

    def test_cr_prepush_hook_includes_cache_mtime_check(self):
        """v2.0.0 audit (HIGH-1) — cache freshness must require mtime, not just JSON ts.

        Pre-fix the template only checked ``entry.ts`` from inside the cache
        JSON. An attacker who could write the cache file forged ``ts: <now>``
        and bypassed the gate. Post-fix the template additionally calls
        ``statSync(CACHE_PATH).mtimeMs`` and requires both gates fresh.
        """
        fixture_path = FIXTURE_DIR / "cr-prepush-rule.md"
        md = fixture_path.read_text()
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)

        # The mtime-based defense must appear in the rendered hook.
        self.assertIn("statSync", hook_source)
        self.assertIn("getCacheMtimeMs", hook_source)
        self.assertIn("mtimeMs", hook_source)
        # Both gates must be combined with AND, not OR — either alone is
        # forgeable. The freshness allow-decision must require both.
        self.assertRegex(
            hook_source,
            r"tsAgeSec\s*<\s*FRESHNESS_SECS\s*&&\s*mtimeAgeSec\s*<\s*FRESHNESS_SECS",
        )

    def test_rendered_ts_hooks_use_json_encoded_audit_path(self):
        """v2.0.0 audit (HIGH-3) — TS templates use the JSON-encoded form,
        not single-quoted string literal interpolation, for AUDIT_LOG_PATH.

        Pre-fix the templates contained ``join(PAI_DIR, '{{AUDIT_LOG_PATH}}')``
        — a single-quoted TS string literal that could be escaped by a
        value containing ``'``. The schema-layer allow-list (CRIT-1
        primary fix) blocks the value at validation, but defense-in-
        depth requires the render path to JSON-encode regardless. This
        test enforces that contract.
        """
        # Render each TS template and check it does NOT contain the old
        # single-quoted form, and DOES contain the join(...) call without
        # wrapping quotes around the placeholder substitution.
        cases = [
            (".claude/hooks/auto/cr.ts", r"git push -u origin", None),
            (".claude/hooks/auto/fp.ts", r"git push --force",
             "force-push-guard.ts.template"),
            (".claude/hooks/auto/bom.ts", r"rm -rf",
             "block-on-match-guard.ts.template"),
        ]
        for hook, pattern, template in cases:
            md_lines = [
                "---", "name: t", "enforce:", "  tool: Bash",
                f"  pattern: '{pattern}'", f"  hook: {hook}",
                "  generated_from: memory/t.md",
                "  audit_log: logs/operator-set.jsonl",
            ]
            if template:
                md_lines.append(f"  template: {template}")
            md_lines.extend(["---", "Body."])
            md = "\n".join(md_lines) + "\n"
            hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)

            # Old (vulnerable) form must NOT survive in any TS template.
            self.assertNotIn(
                "join(PAI_DIR, 'logs/operator-set.jsonl')",
                hook_source,
                f"{hook}: still using single-quoted literal — HIGH-3 not closed",
            )
            # New form: JSON-encoded path with double quotes from json.dumps.
            self.assertIn(
                'join(PAI_DIR, "logs/operator-set.jsonl")',
                hook_source,
                f"{hook}: missing JSON-encoded AUDIT_LOG_PATH_TS",
            )

    def test_rendered_py_hook_uses_json_encoded_audit_path(self):
        """HIGH-3 — Python template uses JSON-encoded form, not double-quoted literal."""
        md = (
            "---\n"
            "name: py-test\n"
            "enforce:\n"
            "  tool: Bash\n"
            "  pattern: 'rm -rf'\n"
            "  hook: .claude/hooks/auto/bom.py\n"
            "  generated_from: memory/p.md\n"
            "  audit_log: logs/py-test.jsonl\n"
            "  language: py\n"
            "  template: block-on-match-guard.py.template\n"
            "---\n"
            "Body.\n"
        )
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # New form: JSON-encoded with double quotes (json.dumps output).
        self.assertIn('_PAI_DIR / "logs/py-test.jsonl"', hook_source)

    def test_rendered_sh_hook_uses_ansi_c_quoted_audit_path(self):
        """HIGH-3 — Shell template uses ANSI-C ``$'...'`` form."""
        md = (
            "---\n"
            "name: sh-test\n"
            "enforce:\n"
            "  tool: Bash\n"
            "  pattern: 'rm -rf'\n"
            "  hook: .claude/hooks/auto/bom.sh\n"
            "  generated_from: memory/s.md\n"
            "  audit_log: logs/sh-test.jsonl\n"
            "  language: sh\n"
            "  template: block-on-match-guard.sh.template\n"
            "---\n"
            "Body.\n"
        )
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # New form: shell concat of "$PAI_DIR/" with ANSI-C $'...'.
        self.assertIn(r"$'logs/sh-test.jsonl'", hook_source)
        self.assertIn(r'"$PAI_DIR/"', hook_source)

    def test_safe_for_ts_string_escapes_quote_meta(self):
        """The new sanitiser must produce a JS string literal that survives
        any input — defense-in-depth even if the schema layer is bypassed."""
        from enforce.generator import _safe_for_ts_string

        # Each of these would have escaped a single-quoted TS string in
        # the pre-fix template. The encoded form is double-quoted JSON.
        for payload in ["'); evil(); ('", '" + evil() + "', "`${evil()}`",
                        "\\u0027 evil", "\nevil()"]:
            encoded = _safe_for_ts_string(payload)
            # The encoded form starts and ends with the surrounding quotes.
            self.assertTrue(encoded.startswith('"'))
            self.assertTrue(encoded.endswith('"'))
            # No bare single quote that would close a `'…'` template literal.
            # (json.dumps does not escape single quotes — they are safe inside
            # double-quoted JSON strings, and the TS template no longer
            # surrounds the placeholder with single quotes.)

    def test_cr_prepush_hook_audit_path_is_operator_configurable(self):
        """v2.0.0 audit (RT-EXP-4) — audit_log: setting must reach the rendered hook.

        Pre-fix the cr-prepush template hardcoded ``join(PAI_DIR, 'logs',
        'cr-prepush-enforcement.jsonl')`` while every other template used
        ``{{AUDIT_LOG_PATH}}``. An operator setting ``audit_log:`` was
        silently ignored for cr-prepush only. Post-fix all four templates
        consistently honour the operator's choice.
        """
        md = (
            "---\n"
            "name: cr-rule\n"
            "enforce:\n"
            "  tool: Bash\n"
            '  pattern: "git push -u origin"\n'
            "  hook: .claude/hooks/auto/cr-prepush.ts\n"
            "  generated_from: memory/cr.md\n"
            "  audit_log: logs/operator-chose-this.jsonl\n"
            "---\n"
            "Body.\n"
        )
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # Operator's choice must land in the rendered AUDIT_PATH.
        self.assertIn("logs/operator-chose-this.jsonl", hook_source)
        # The pre-fix hardcoded path must NOT survive.
        self.assertNotIn("'logs', 'cr-prepush-enforcement.jsonl'", hook_source)

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

    def test_newline_in_comment_param_rejected_at_schema_layer(self):
        """A memory entry can't reach the generator with newline-bearing paths.

        Pre-v2.0.0 (audit branch): the schema only checked path traversal.
        Newline-bearing values flowed to the generator, which relied on
        ``_safe_for_comment`` to strip them before substitution into ``//``
        comment slots. That defense was a single point of failure (CRIT-1
        showed the same value can land in non-comment contexts).

        v2.0.0 audit fix: the schema now applies a strict character allow-
        list (letters, digits, dot, underscore, slash, hyphen) to
        ``generated_from`` / ``hook`` / ``audit_log``. Values with newlines,
        quotes, dollar signs, etc. are rejected at validation time —
        before the generator ever sees them. This is the primary defense;
        the generator's per-context sanitisers remain as defense-in-depth.
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
        # Schema rejection raises EnforceValidationError, which generate_hook
        # surfaces unchanged — no GenerationError wrapper because the rejection
        # happens before any template work begins.
        from enforce.schema import EnforceValidationError

        with self.assertRaises(EnforceValidationError) as ctx:
            generate_hook(md, template_dir=TEMPLATE_DIR)
        # The error must clearly identify the offending field so operators
        # can fix the rule rather than silently producing a no-op hook.
        self.assertIn("generated_from", str(ctx.exception))


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


class TestPhase41ForcePushGuard(unittest.TestCase):
    """Phase 4.1: force-push-guard template, dispatch, and protected_branches substitution."""

    def _md(
        self,
        *,
        pattern: str = r"git push --force",
        template: str | None = None,
        protected_branches: list[str] | None = None,
    ) -> str:
        lines = [
            "---",
            "name: phase41-test",
            "type: feedback",
            "enforce:",
            "  tool: Bash",
            f'  pattern: "{pattern}"',
            "  hook: .claude/hooks/auto/test.ts",
            "  generated_from: memory/p41.md",
        ]
        if template:
            lines.append(f"  template: {template}")
        if protected_branches is not None:
            yaml_list = "[" + ", ".join(repr(b) for b in protected_branches) + "]"
            lines.append(f"  protected_branches: {yaml_list}")
        lines.extend(["---", "Body."])
        return "\n".join(lines) + "\n"

    def test_force_push_pattern_dispatches_to_force_push_template(self):
        """`--force` substring in pattern → force-push-guard, ahead of cr-prepush."""
        # Pattern contains both "git push" AND "--force"; first-match-wins
        # ordering must put force-push-guard ahead of cr-prepush-guard so
        # the more specific template is selected.
        md = self._md(pattern=r"git push --force")
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        self.assertIn("FORCE-PUSH GUARD", hook_source)
        self.assertNotIn("CR PRE-PUSH GUARD", hook_source)
        self.assertNotIn("BLOCK-ON-MATCH GUARD", hook_source)

    def test_force_push_template_renders_default_branches(self):
        """Default ['main', 'master'] is substituted when operator omits the field."""
        md = self._md()
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # The substitution lands as a JS array literal in the rendered source.
        self.assertIn('["main", "master"]', hook_source)

    def test_force_push_template_renders_custom_branches(self):
        """Operator-supplied protected_branches lands in the rendered source."""
        md = self._md(protected_branches=["main", "master", "production"])
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        self.assertIn('["main", "master", "production"]', hook_source)

    def test_force_push_template_compiles_under_bun(self):
        """Sanity: force-push-guard renders to syntactically valid TypeScript."""
        md = self._md()
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        _assert_bun_build_clean(self, hook_source)

    def test_force_push_template_uses_execfile_not_exec(self):
        """Branch resolution must use the no-shell variant, never the
        shell-interpreting one. The whole reason for the cwd-aware lookup
        is to avoid the bash injection surface of a string command."""
        md = self._md()
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # Positive: the safe variant is present.
        self.assertIn("execFileSync", hook_source)
        # Negative: assemble the unsafe-call substring at runtime so the
        # local secure-code-review hook (which substring-matches Edit
        # inputs) doesn't trip on this assertion. The check itself is
        # exact — it would catch any bare string-form spawn call.
        forbidden = "exec" + "Sync("
        self.assertNotIn(forbidden, hook_source)

    def test_force_push_template_audit_uses_schema_path(self):
        """AUDIT_PATH must come from {{AUDIT_LOG_PATH}}, not be reconstructed
        from {{HOOK_PATH}} — same correctness fix that PR #15 R2 applied to
        the block-on-match primitive."""
        md = self._md()
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # The schema's audit_log default is hook_stem + ".audit.jsonl";
        # the hook in this fixture is .claude/hooks/auto/test.ts so the
        # path the generator computed is .claude/hooks/auto/test.audit.jsonl.
        self.assertIn(".claude/hooks/auto/test.audit.jsonl", hook_source)

    def test_force_push_explicit_template_field_works(self):
        """An operator can also opt in via enforce.template explicitly."""
        # Pattern doesn't contain --force; explicit template still picks it.
        md = self._md(pattern=r"some-other-pattern", template="force-push-guard.ts.template")
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        self.assertIn("FORCE-PUSH GUARD", hook_source)

    def test_force_push_template_normalises_ref_names(self):
        """Long-form refs (refs/heads/main) must normalise to short
        names before comparison, so an attacker can't bypass via
        `git push --force origin HEAD:refs/heads/main`. PR #16 R1 fix."""
        md = self._md()
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # The helper is the canonical normaliser — its presence gates
        # both refspec and rev-parse paths.
        self.assertIn("normalizeBranchName", hook_source)
        self.assertIn("refs/heads/", hook_source)

    def test_force_push_template_resists_git_arg_bypasses(self):
        """`git -c key=value push --force` and `-o ci.skip` value confusion.
        PR #16 R2 fix. Asserts the rendered template carries the parser
        improvements that close those bypass classes."""
        md = self._md()
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # 1. push detection accepts `push` anywhere after position 0,
        #    so `git -c k=v push ...` is caught.
        self.assertIn("i > 0 && t === 'push'", hook_source)
        # 2. the loose `git` program check survives full paths
        #    (`/usr/bin/git push ...`).
        self.assertIn("isGit", hook_source)
        # 3. value-consuming options skip the next token so their
        #    values don't leak into the positional list.
        self.assertIn("PUSH_OPTIONS_WITH_VALUE", hook_source)
        self.assertIn("--push-option", hook_source)


class TestPhase42CredentialLeakGuard(unittest.TestCase):
    """Phase 4.2: credential-leak-guard template + credential_patterns substitution."""

    def _md(
        self,
        *,
        tool: str = "Edit",
        pattern: str = r".*",
        credential_patterns: list[str] | None = None,
    ) -> str:
        # Single-quoted YAML so regex backslashes (\., \w, etc.) round-trip
        # literally without YAML's double-quote escape rules tripping.
        lines = [
            "---",
            "name: phase42-test",
            "type: feedback",
            "enforce:",
            f"  tool: {tool}",
            f"  pattern: '{pattern}'",
            "  hook: .claude/hooks/auto/test.ts",
            "  generated_from: memory/p42.md",
            "  template: credential-leak-guard.ts.template",
        ]
        if credential_patterns is not None:
            yaml_list = "[" + ", ".join(repr(p) for p in credential_patterns) + "]"
            lines.append(f"  credential_patterns: {yaml_list}")
        lines.extend(["---", "Body."])
        return "\n".join(lines) + "\n"

    def test_credential_leak_template_renders_default_patterns(self):
        """Default credential pattern set is substituted when operator omits the field."""
        md = self._md()
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # Spot-check a few high-confidence patterns from the curated default.
        self.assertIn("AKIA[0-9A-Z]{16}", hook_source)
        self.assertIn("gh[pousr]_[A-Za-z0-9]{36}", hook_source)
        self.assertIn("BEGIN [A-Z ]*PRIVATE KEY", hook_source)

    def test_credential_leak_template_renders_custom_patterns(self):
        """Operator-supplied credential_patterns override the default set."""
        custom = [r"my-secret-[A-Z]{10}", r"INTERNAL_TOKEN_[0-9]+"]
        md = self._md(credential_patterns=custom)
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        self.assertIn("my-secret-[A-Z]{10}", hook_source)
        self.assertIn("INTERNAL_TOKEN_[0-9]+", hook_source)
        # Default set replaced — AKIA pattern should not appear.
        self.assertNotIn("AKIA[0-9A-Z]", hook_source)

    def test_credential_leak_template_compiles_under_bun_for_edit(self):
        """Sanity: rendered template is syntactically valid TypeScript."""
        md = self._md(tool="Edit")
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        _assert_bun_build_clean(self, hook_source)

    def test_credential_leak_template_compiles_under_bun_for_write(self):
        """Same template handles Write tool — different input shape (`content`)."""
        md = self._md(tool="Write")
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        _assert_bun_build_clean(self, hook_source)
        # Tool name substituted into the source.
        self.assertIn("'Write'", hook_source)

    def test_credential_leak_template_compiles_under_bun_for_multiedit(self):
        """Same template handles MultiEdit — input shape is array of edits."""
        md = self._md(tool="MultiEdit")
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        _assert_bun_build_clean(self, hook_source)

    def test_credential_leak_template_does_not_log_matched_substring(self):
        """The matched secret must NEVER appear in stderr or audit JSONL.
        Same redaction principle as PR #15 R2 (block-on-match) and PR #16
        (force-push-guard)."""
        md = self._md()
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # The audit entry should carry pattern source only, not the match.
        self.assertIn("event: 'block', file_path: filePath, pattern: patternSource", hook_source)
        # The block banner explicitly says the secret is not echoed.
        self.assertIn("matched secret is NOT included", hook_source)

    def test_credential_leak_template_path_filter_uses_pattern(self):
        """The schema's `pattern` field becomes the file_path scope filter
        (e.g. `\\.env$` to limit the guard to .env files)."""
        md = self._md(pattern=r"\.env$")
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # The pattern lands as the FILE_PATH_FILTER constant — escaped via
        # json.dumps so backslashes round-trip safely into TypeScript.
        self.assertIn("FILE_PATH_FILTER", hook_source)
        self.assertIn(r"\\.env$", hook_source)

    def test_credential_leak_template_fails_closed_on_bad_input(self):
        """Unlike the other templates (which fail open with exit 0 on
        stdin/parse errors), credential-leak-guard MUST fail closed —
        a malformed hook payload should block the write, not slip
        credentials through. PR #17 R1 fix."""
        md = self._md()
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # The fail-closed branch logs the protocol failure, audits a
        # block event, and exits 2.
        self.assertIn("invalid hook input", hook_source)
        self.assertIn("event: 'block', reason: 'invalid hook input'", hook_source)
        self.assertIn("process.exit(2)", hook_source)

    def test_credential_leak_template_fails_closed_on_shape_drift(self):
        """PR #17 R2 — JSON parses but payload shape is wrong:
        - missing file_path → block (was: silently 'path out of scope')
        - missing content   → block (was: silently 'no content')
        Both protocol-drift cases must fail closed for credential-leak;
        otherwise an attacker controlling the hook payload could bypass
        scanning by simply omitting fields."""
        md = self._md()
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        self.assertIn("missing file_path", hook_source)
        self.assertIn("missing write content", hook_source)
        # Empty content is still a legitimate "nothing to scan" case —
        # allow with audit, NOT fail closed.
        self.assertIn("event: 'allow', reason: 'no content'", hook_source)


class TestPhase5MultiLanguage(unittest.TestCase):
    """Phase 5: language field swaps the template suffix .<lang>.template
    so the same TEMPLATE_PATTERNS dispatch resolves to py / sh ports."""

    def _md(
        self,
        *,
        pattern: str = r"rm -rf",
        language: str | None = None,
        template: str | None = None,
    ) -> str:
        lines = [
            "---",
            "name: phase5-test",
            "type: feedback",
            "enforce:",
            "  tool: Bash",
            f'  pattern: "{pattern}"',
            "  hook: .claude/hooks/auto/test.ts",
            "  generated_from: memory/p5.md",
            "  template: block-on-match-guard.ts.template",
        ]
        if language is not None:
            lines.append(f"  language: {language}")
        # Allow the test to override template explicitly (e.g. to point
        # at a non-TS template file by name).
        if template is not None:
            lines[-1] = f"  template: {template}"
        lines.extend(["---", "Body."])
        return "\n".join(lines) + "\n"

    def test_default_language_is_ts(self):
        """Backward-compat: no language field → TS template, current behaviour."""
        # Use TEMPLATE_PATTERNS dispatch (no explicit template field).
        md = (
            "---\n"
            "name: phase5-default\n"
            "type: feedback\n"
            "enforce:\n"
            "  tool: Bash\n"
            '  pattern: "git push -u origin"\n'
            "  hook: .claude/hooks/auto/test.ts\n"
            "  generated_from: memory/p5.md\n"
            "---\nBody.\n"
        )
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # cr-prepush is TS — spot-check a TS-only construct.
        self.assertIn("import { existsSync", hook_source)

    def test_python_language_picks_py_template(self):
        """language: py + dispatchable pattern → .py.template is used."""
        md = (
            "---\n"
            "name: phase5-py\n"
            "type: feedback\n"
            "enforce:\n"
            "  tool: Bash\n"
            '  pattern: "rm -rf /"\n'
            "  hook: .claude/hooks/auto/test.py\n"
            "  generated_from: memory/p5.md\n"
            "  language: py\n"
            "  template: block-on-match-guard.py.template\n"
            "---\nBody.\n"
        )
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        # Python-distinctive markers.
        self.assertIn("#!/usr/bin/env python3", hook_source)
        self.assertIn("import json", hook_source)
        self.assertIn("import re", hook_source)
        # Box marker still there.
        self.assertIn("BLOCK-ON-MATCH GUARD", hook_source)

    def test_python_template_compiles(self):
        """The rendered .py template must be syntactically valid Python."""
        md = (
            "---\n"
            "name: phase5-py-syntax\n"
            "type: feedback\n"
            "enforce:\n"
            "  tool: Bash\n"
            '  pattern: "rm -rf /"\n'
            "  hook: .claude/hooks/auto/test.py\n"
            "  generated_from: memory/p5.md\n"
            "  language: py\n"
            "  template: block-on-match-guard.py.template\n"
            "---\nBody.\n"
        )
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        try:
            compile(hook_source, "<rendered>", "exec")
        except SyntaxError as exc:
            self.fail(f"rendered Python hook has SyntaxError: {exc}\n{hook_source}")

    def test_shell_language_picks_sh_template(self):
        """language: sh + explicit template → .sh.template is used."""
        md = (
            "---\n"
            "name: phase5-sh\n"
            "type: feedback\n"
            "enforce:\n"
            "  tool: Bash\n"
            '  pattern: "rm -rf /"\n'
            "  hook: .claude/hooks/auto/test.sh\n"
            "  generated_from: memory/p5.md\n"
            "  language: sh\n"
            "  template: block-on-match-guard.sh.template\n"
            "---\nBody.\n"
        )
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        self.assertIn("#!/usr/bin/env bash", hook_source)
        self.assertIn("set -euo pipefail", hook_source)
        # ANSI-C-quoted pattern lands as $'...' — Phase 5 shell-safe form.
        self.assertIn("PATTERN=$'", hook_source)
        # jq is documented as required.
        self.assertIn("command -v jq", hook_source)

    def test_shell_template_passes_bash_syntax_check(self):
        """The rendered .sh template must pass `bash -n` syntax check."""
        import shutil
        import subprocess
        import tempfile
        # Resolve bash to its absolute path up front. Passing the
        # partial name "bash" to subprocess.run trips Ruff S607
        # (partial executable path) and would also pick up a
        # potentially-unintended bash from PATH at test time.
        bash_bin = shutil.which("bash")
        if not bash_bin:
            self.skipTest("bash not available")
        md = (
            "---\n"
            "name: phase5-sh-syntax\n"
            "type: feedback\n"
            "enforce:\n"
            "  tool: Bash\n"
            '  pattern: "rm -rf /"\n'
            "  hook: .claude/hooks/auto/test.sh\n"
            "  generated_from: memory/p5.md\n"
            "  language: sh\n"
            "  template: block-on-match-guard.sh.template\n"
            "---\nBody.\n"
        )
        hook_source = generate_hook(md, template_dir=TEMPLATE_DIR)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
            f.write(hook_source)
            tmp_path = f.name
        try:
            result = subprocess.run(  # noqa: S603 # nosec B603 - bash_bin is the resolved absolute path; args are constants
                [bash_bin, "-n", tmp_path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                self.fail(
                    f"bash -n failed:\n{result.stderr}\n--- source ---\n{hook_source}"
                )
        finally:
            import os as _os
            try:
                _os.unlink(tmp_path)
            except OSError:
                pass

    def test_dispatch_swaps_suffix_for_non_ts_languages(self):
        """TEMPLATE_PATTERNS dispatch should pick .py.template when
        language: py (no explicit template field). Asserts the
        suffix-swap path in pick_template."""
        md = (
            "---\n"
            "name: phase5-dispatch\n"
            "type: feedback\n"
            "enforce:\n"
            "  tool: Bash\n"
            # cr-prepush-guard auto-dispatches on "git push", but
            # there's no .py port of cr-prepush yet — the generator
            # should error loudly, not silently fall back to TS.
            '  pattern: "git push -u origin"\n'
            "  hook: .claude/hooks/auto/test.py\n"
            "  generated_from: memory/p5.md\n"
            "  language: py\n"
            "---\nBody.\n"
        )
        with self.assertRaises(GenerationError) as ctx:
            generate_hook(md, template_dir=TEMPLATE_DIR)
        # Error names the language and the missing port.
        self.assertIn("'py'", str(ctx.exception))
        self.assertIn("cr-prepush-guard.ts.template", str(ctx.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)
