"""Unit tests for lib/enforce/schema.py — `enforce` block validation.

The `enforce` block is YAML frontmatter on a memory entry that says "this
rule should be enforced as a runtime hook." Mnemosyne v2 reads it and
generates a hook from a template.

Schema (v0.1):
  enforce:
    tool: <Bash|Edit|Write|Read|...>            # required, the Claude Code tool name
    pattern: <regex string>                     # required, matched against tool input
    hook: <relative path>                       # required, where to write the hook
    generated_from: <memory entry path>         # required, source attribution
    freshness_secs: <int>                       # optional, default 1800
    audit_log: <relative path>                  # optional, default <hook>.audit.jsonl
    generator_version: <semver>                 # optional, set by generator
    generated_at: <ISO 8601>                    # optional, set by generator
    repo_filter: <regex>                        # optional, only enforce when repo matches

Security mapping:
  OWASP LLM 2025: LLM06 (Excessive Agency)
  MITRE ATLAS: AML.T0051 (Prompt Injection consequence containment)
"""

import sys
import unittest
from pathlib import Path

# Add lib/ to path so we can import enforce.schema
LIB_DIR = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(LIB_DIR))

from enforce.schema import (  # noqa: E402
    EnforceValidationError,
    validate_enforce_block,
)


class TestValidateEnforceBlockHappyPath(unittest.TestCase):
    """Valid enforce blocks parse and return a normalised dict."""

    def test_minimum_required_fields(self):
        """Block with only the 4 required fields is valid."""
        raw = {
            "tool": "Bash",
            "pattern": r"git push -u origin",
            "hook": ".claude/hooks/auto/cr-prepush.ts",
            "generated_from": "memory/feedback_zero_drift.md",
        }
        result = validate_enforce_block(raw)
        self.assertEqual(result["tool"], "Bash")
        self.assertEqual(result["pattern"], r"git push -u origin")
        self.assertEqual(result["hook"], ".claude/hooks/auto/cr-prepush.ts")
        self.assertEqual(result["generated_from"], "memory/feedback_zero_drift.md")
        # Defaults applied
        self.assertEqual(result["freshness_secs"], 1800)
        self.assertIn("audit_log", result)

    def test_full_block_preserves_all_fields(self):
        """All optional fields pass through unchanged."""
        raw = {
            "tool": "Bash",
            "pattern": r"rm -rf",
            "hook": ".claude/hooks/auto/rm-rf-guard.ts",
            "generated_from": "memory/feedback_no_destructive.md",
            "freshness_secs": 900,
            "audit_log": ".claude/logs/rm-rf-guard.jsonl",
            "generator_version": "2.0.0",
            "repo_filter": r"^/Users/[^/]+/work/",
        }
        result = validate_enforce_block(raw)
        self.assertEqual(result["freshness_secs"], 900)
        self.assertEqual(result["audit_log"], ".claude/logs/rm-rf-guard.jsonl")
        self.assertEqual(result["generator_version"], "2.0.0")
        self.assertEqual(result["repo_filter"], r"^/Users/[^/]+/work/")

    def test_default_audit_log_derived_from_hook_path(self):
        """When audit_log is missing, default is <hook>.audit.jsonl."""
        raw = {
            "tool": "Bash",
            "pattern": r"git push",
            "hook": ".claude/hooks/auto/cr-prepush.ts",
            "generated_from": "memory/feedback.md",
        }
        result = validate_enforce_block(raw)
        # Default audit log lives next to the hook with a clear suffix
        self.assertTrue(result["audit_log"].endswith(".audit.jsonl"))
        self.assertIn("cr-prepush", result["audit_log"])


class TestValidateEnforceBlockRejection(unittest.TestCase):
    """Invalid blocks raise EnforceValidationError with clear reasons."""

    def test_missing_required_field_raises(self):
        """All four required fields must be present."""
        for missing in ("tool", "pattern", "hook", "generated_from"):
            raw = {
                "tool": "Bash",
                "pattern": r"git push",
                "hook": ".claude/hooks/auto/g.ts",
                "generated_from": "memory/x.md",
            }
            del raw[missing]
            with self.assertRaises(EnforceValidationError, msg=f"missing {missing}"):
                validate_enforce_block(raw)

    def test_unknown_tool_rejected(self):
        """Tool name must be one of the Claude Code tool names."""
        raw = {
            "tool": "RunArbitraryCode",  # not a real tool
            "pattern": r"x",
            "hook": ".claude/hooks/auto/g.ts",
            "generated_from": "memory/x.md",
        }
        with self.assertRaises(EnforceValidationError):
            validate_enforce_block(raw)

    def test_invalid_regex_rejected(self):
        """Pattern must be a compilable regex."""
        raw = {
            "tool": "Bash",
            "pattern": "[invalid(",  # unclosed
            "hook": ".claude/hooks/auto/g.ts",
            "generated_from": "memory/x.md",
        }
        with self.assertRaises(EnforceValidationError):
            validate_enforce_block(raw)

    def test_path_traversal_in_hook_path_rejected(self):
        """Hook path must not escape the repo root via traversal."""
        bad_paths = (
            "../../etc/passwd.ts",
            "..\\..\\windows.ts",
            "/etc/passwd.ts",
            "C:\\Windows\\Temp\\hook.ts",  # Windows drive-letter absolute
            "D:/tmp/hook.ts",              # forward-slash drive form
        )
        for bad in bad_paths:
            raw = {
                "tool": "Bash",
                "pattern": r"x",
                "hook": bad,
                "generated_from": "memory/x.md",
            }
            with self.assertRaises(EnforceValidationError, msg=f"path: {bad}"):
                validate_enforce_block(raw)

    def test_hook_must_live_in_auto_directory(self):
        """Generated hooks must be under .claude/hooks/auto/ to mark them as generated."""
        raw = {
            "tool": "Bash",
            "pattern": r"x",
            "hook": ".claude/hooks/cr-prepush.ts",  # NOT in auto/
            "generated_from": "memory/x.md",
        }
        with self.assertRaises(EnforceValidationError):
            validate_enforce_block(raw)

    def test_freshness_secs_must_be_positive_int(self):
        """Freshness window must be a positive integer (and not a bool)."""
        # bool is a subclass of int in Python, so we must explicitly reject it.
        for bad in (0, -1, "30", 30.5, None, True, False):
            raw = {
                "tool": "Bash",
                "pattern": r"x",
                "hook": ".claude/hooks/auto/g.ts",
                "generated_from": "memory/x.md",
                "freshness_secs": bad,
            }
            with self.assertRaises(EnforceValidationError, msg=f"freshness_secs: {bad!r}"):
                validate_enforce_block(raw)

    def test_non_dict_input_rejected(self):
        for bad in (None, "string", 42, [1, 2, 3]):
            with self.assertRaises(EnforceValidationError):
                validate_enforce_block(bad)


class TestInjectionFields(unittest.TestCase):
    """Phase 2: action-time rule re-injection schema fields."""

    def _base(self, **overrides):
        raw = {
            "tool": "Bash",
            "pattern": r"git push",
            "hook": ".claude/hooks/auto/g.ts",
            "generated_from": "memory/x.md",
        }
        raw.update(overrides)
        return raw

    def test_inject_on_match_default_false(self):
        result = validate_enforce_block(self._base())
        self.assertFalse(result["inject_on_match"])

    def test_inject_on_match_must_be_bool(self):
        for bad in ("true", 1, 0, None):
            with self.assertRaises(EnforceValidationError, msg=f"value: {bad!r}"):
                validate_enforce_block(self._base(inject_on_match=bad))

    def test_inject_on_match_true_passes(self):
        result = validate_enforce_block(self._base(inject_on_match=True))
        self.assertTrue(result["inject_on_match"])

    def test_inject_text_must_be_non_empty_string_when_present(self):
        for bad in ("", "   \n", 42, None, [], {}):
            with self.assertRaises(EnforceValidationError, msg=f"value: {bad!r}"):
                validate_enforce_block(self._base(inject_text=bad))

    def test_inject_text_passes_through_when_valid(self):
        text = "Reminder: never run destructive commands without explicit approval."
        result = validate_enforce_block(self._base(inject_text=text))
        self.assertEqual(result["inject_text"], text)

    def test_inject_token_budget_default_256(self):
        result = validate_enforce_block(self._base())
        self.assertEqual(result["inject_token_budget"], 256)

    def test_inject_token_budget_must_be_positive_int_within_cap(self):
        for bad in (0, -1, "256", 256.5, None, True, False, 1025):
            with self.assertRaises(EnforceValidationError, msg=f"value: {bad!r}"):
                validate_enforce_block(self._base(inject_token_budget=bad))

    def test_inject_token_budget_at_max(self):
        result = validate_enforce_block(self._base(inject_token_budget=1024))
        self.assertEqual(result["inject_token_budget"], 1024)


class TestExplicitTemplateField(unittest.TestCase):
    """Phase 4: optional `template` field overrides TEMPLATE_PATTERNS dispatch."""

    def _base(self, **overrides):
        raw = {
            "tool": "Bash",
            "pattern": r"rm -rf",
            "hook": ".claude/hooks/auto/g.ts",
            "generated_from": "memory/x.md",
        }
        raw.update(overrides)
        return raw

    def test_template_field_optional_default_unset(self):
        result = validate_enforce_block(self._base())
        # Not set when the user doesn't provide one — generator falls through
        # to TEMPLATE_PATTERNS dispatch.
        self.assertNotIn("template", result)

    def test_template_field_passes_through_when_valid(self):
        result = validate_enforce_block(self._base(template="block-on-match-guard.ts.template"))
        self.assertEqual(result["template"], "block-on-match-guard.ts.template")

    def test_template_field_must_be_non_empty_string(self):
        for bad in ("", "   ", 42, None, [], {}):
            with self.assertRaises(EnforceValidationError, msg=f"value: {bad!r}"):
                validate_enforce_block(self._base(template=bad))

    def test_template_field_rejects_path_traversal(self):
        for bad in ("../escape.template", "/etc/passwd.template", "..\\evil.template"):
            with self.assertRaises(EnforceValidationError, msg=f"path: {bad!r}"):
                validate_enforce_block(self._base(template=bad))

    def test_template_field_rejects_subdirectory_paths(self):
        """Template names are basename-only; subdirectories are out of scope."""
        with self.assertRaises(EnforceValidationError):
            validate_enforce_block(self._base(template="sub/x.template"))


class TestProtectedBranchesField(unittest.TestCase):
    """Phase 4.1: optional `protected_branches` field for force-push-guard."""

    def _base(self, **overrides):
        raw = {
            "tool": "Bash",
            "pattern": r"git push --force",
            "hook": ".claude/hooks/auto/g.ts",
            "generated_from": "memory/x.md",
        }
        raw.update(overrides)
        return raw

    def test_protected_branches_optional_default_unset(self):
        # Schema stays template-agnostic — the generator applies the
        # ["main", "master"] default at substitution time when this is
        # absent. Asserting absence here pins that contract.
        result = validate_enforce_block(self._base())
        self.assertNotIn("protected_branches", result)

    def test_protected_branches_passes_through_when_valid(self):
        result = validate_enforce_block(
            self._base(protected_branches=["main", "master", "production"])
        )
        self.assertEqual(
            result["protected_branches"], ["main", "master", "production"]
        )

    def test_protected_branches_must_be_a_list(self):
        for bad in ("main", 42, None, {"main": True}):
            with self.assertRaises(EnforceValidationError, msg=f"value: {bad!r}"):
                validate_enforce_block(self._base(protected_branches=bad))

    def test_protected_branches_rejects_empty_list(self):
        with self.assertRaises(EnforceValidationError):
            validate_enforce_block(self._base(protected_branches=[]))

    def test_protected_branches_rejects_non_string_element(self):
        for bad in (["main", 42], ["main", None], ["main", []]):
            with self.assertRaises(EnforceValidationError, msg=f"value: {bad!r}"):
                validate_enforce_block(self._base(protected_branches=bad))

    def test_protected_branches_rejects_empty_string_element(self):
        for bad in (["main", ""], ["main", "   "]):
            with self.assertRaises(EnforceValidationError, msg=f"value: {bad!r}"):
                validate_enforce_block(self._base(protected_branches=bad))

    def test_protected_branches_rejects_whitespace_in_branch_name(self):
        # Branch names with whitespace are invalid in git anyway, and
        # accepting them would let an operator silently no-op the guard.
        for bad in (["main", "feature branch"], ["main", "evil\tbranch"]):
            with self.assertRaises(EnforceValidationError, msg=f"value: {bad!r}"):
                validate_enforce_block(self._base(protected_branches=bad))


class TestCredentialPatternsField(unittest.TestCase):
    """Phase 4.2: optional `credential_patterns` field for credential-leak-guard."""

    def _base(self, **overrides):
        raw = {
            "tool": "Edit",
            "pattern": r".*",
            "hook": ".claude/hooks/auto/g.ts",
            "generated_from": "memory/x.md",
            "template": "credential-leak-guard.ts.template",
        }
        raw.update(overrides)
        return raw

    def test_credential_patterns_optional_default_unset(self):
        # Schema stays template-agnostic — generator applies the default
        # at substitution time when this is absent. Asserting absence
        # here pins that contract.
        result = validate_enforce_block(self._base())
        self.assertNotIn("credential_patterns", result)

    def test_credential_patterns_passes_through_when_valid(self):
        patterns = [r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{36}"]
        result = validate_enforce_block(self._base(credential_patterns=patterns))
        self.assertEqual(result["credential_patterns"], patterns)

    def test_credential_patterns_must_be_a_list(self):
        for bad in ("AKIA", 42, None, {"k": "v"}):
            with self.assertRaises(EnforceValidationError, msg=f"value: {bad!r}"):
                validate_enforce_block(self._base(credential_patterns=bad))

    def test_credential_patterns_rejects_empty_list(self):
        with self.assertRaises(EnforceValidationError):
            validate_enforce_block(self._base(credential_patterns=[]))

    def test_credential_patterns_rejects_non_string_element(self):
        for bad in ([r"AKIA.*", 42], [None]):
            with self.assertRaises(EnforceValidationError, msg=f"value: {bad!r}"):
                validate_enforce_block(self._base(credential_patterns=bad))

    def test_credential_patterns_rejects_invalid_regex(self):
        # Each pattern must compile — unclosed character class fails.
        with self.assertRaises(EnforceValidationError):
            validate_enforce_block(self._base(credential_patterns=[r"[unclosed"]))

    def test_credential_patterns_rejects_python_only_named_group(self):
        # `(?P<name>...)` compiles under Python `re` but throws under
        # JS `new RegExp()`. The schema must catch that asymmetry — the
        # rendered hook would crash at startup.
        with self.assertRaises(EnforceValidationError) as ctx:
            validate_enforce_block(self._base(
                credential_patterns=[r"(?P<token>AKIA[0-9A-Z]{16})"]
            ))
        self.assertIn("Python-only", str(ctx.exception))

    def test_credential_patterns_rejects_python_only_named_backref(self):
        with self.assertRaises(EnforceValidationError):
            validate_enforce_block(self._base(
                credential_patterns=[r"(?P<x>\w+)\s+(?P=x)"]
            ))

    def test_credential_patterns_rejects_python_only_inline_flags(self):
        # `(?aiLmsux:...)` and `(?aiLmsux)` use Python-specific flag
        # letters (a/L/u/x) that JS RegExp doesn't accept.
        for bad in (r"(?ai:secret)", r"(?Lmsux)hidden"):
            with self.assertRaises(EnforceValidationError, msg=f"value: {bad!r}"):
                validate_enforce_block(self._base(credential_patterns=[bad]))

    def test_credential_patterns_accepts_unnamed_groups(self):
        # The portable subset between Python `re` and JS RegExp does NOT
        # include named groups — Python uses `(?P<name>...)` (rejected
        # by JS), JS uses `(?<name>...)` (rejected by Python re). The
        # documented contract is: stick to unnamed groups for cross-
        # syntax patterns. Schema accepts those without complaint.
        result = validate_enforce_block(self._base(
            credential_patterns=[r"(AKIA[0-9A-Z]{16})", r"(\w+)\s+(\w+)"]
        ))
        self.assertEqual(len(result["credential_patterns"]), 2)


class TestLanguageField(unittest.TestCase):
    """Phase 5: optional `language` field for multi-language hook generators."""

    def _base(self, **overrides):
        raw = {
            "tool": "Bash",
            "pattern": r"rm -rf",
            "hook": ".claude/hooks/auto/g.ts",
            "generated_from": "memory/x.md",
        }
        raw.update(overrides)
        return raw

    def test_language_defaults_to_ts(self):
        # Backward-compat: every existing memory entry without
        # `language:` keeps generating TypeScript hooks.
        result = validate_enforce_block(self._base())
        self.assertEqual(result["language"], "ts")

    def test_language_accepts_supported_values(self):
        for lang in ("ts", "py", "sh"):
            result = validate_enforce_block(self._base(language=lang))
            self.assertEqual(result["language"], lang, msg=f"language={lang}")

    def test_language_rejects_unknown_value(self):
        for bad in ("rust", "go", "TypeScript", "", "PY"):
            with self.assertRaises(EnforceValidationError, msg=f"value: {bad!r}"):
                validate_enforce_block(self._base(language=bad))

    def test_language_rejects_non_string(self):
        for bad in (42, None, ["ts"], {"ts": True}):
            with self.assertRaises(EnforceValidationError, msg=f"value: {bad!r}"):
                validate_enforce_block(self._base(language=bad))

    def test_inject_on_match_rejected_with_non_ts_language(self):
        # Phase 2 re-injection only emits TS glue today; combining it
        # with py/sh would emit a broken hook. Cross-field check.
        for lang in ("py", "sh"):
            with self.assertRaises(EnforceValidationError) as ctx:
                validate_enforce_block(self._base(
                    language=lang,
                    inject_on_match=True,
                ))
            self.assertIn("inject_on_match", str(ctx.exception))
            self.assertIn(lang, str(ctx.exception))

    def test_inject_on_match_allowed_with_default_language(self):
        # Default language (ts) + inject_on_match: true is fine.
        result = validate_enforce_block(self._base(inject_on_match=True))
        self.assertTrue(result["inject_on_match"])
        self.assertEqual(result["language"], "ts")


class TestPathStrictAllowList(unittest.TestCase):
    """v2.0.0 audit (CRIT-1) — strict char allow-list on path fields.

    The defender audit found that ``audit_log`` could carry quote / shell
    metachar payloads that survived schema validation (only ``_has_traversal``)
    and landed inside string-literal contexts in the rendered hook. Strict
    allow-list closes the attack at the earliest layer.
    """

    def _base(self, **overrides):
        raw = {
            "tool": "Bash",
            "pattern": r"git push",
            "hook": ".claude/hooks/auto/g.ts",
            "generated_from": "memory/x.md",
        }
        raw.update(overrides)
        return raw

    def test_audit_log_rejects_single_quote_injection(self):
        """The CRIT-1 PoC payload must be rejected at validation time."""
        # Payload from audit: closing single-quote terminates the TS string,
        # then arbitrary code runs.
        payload = ".claude/logs/x.jsonl'); console.error('PWNED'); ('"
        with self.assertRaises(EnforceValidationError) as ctx:
            validate_enforce_block(self._base(audit_log=payload))
        self.assertIn("audit_log", str(ctx.exception))

    def test_audit_log_rejects_quote_meta_chars(self):
        """Single quote, double quote, backtick, dollar, parens, semicolon."""
        forbidden_chars = ["'", '"', "`", "$", "(", ")", ";", "&", "|", "\\"]
        for ch in forbidden_chars:
            with self.assertRaises(EnforceValidationError, msg=f"char {ch!r}"):
                validate_enforce_block(
                    self._base(audit_log=f".claude/logs/x{ch}.jsonl")
                )

    def test_audit_log_rejects_whitespace(self):
        """Whitespace is forbidden in path fields."""
        for ws in [" ", "\t", "\n", "\r"]:
            with self.assertRaises(EnforceValidationError, msg=f"ws {ws!r}"):
                validate_enforce_block(
                    self._base(audit_log=f".claude/logs/x{ws}foo.jsonl")
                )

    def test_audit_log_rejects_unicode_confusables(self):
        """Cyrillic / Greek / fullwidth characters are not allow-listed."""
        for ch in ["а", "α", "ｆｏｏ", "​"]:
            with self.assertRaises(EnforceValidationError, msg=f"ch {ch!r}"):
                validate_enforce_block(
                    self._base(audit_log=f".claude/logs/{ch}.jsonl")
                )

    def test_audit_log_rejects_control_chars(self):
        """NUL and other C0 control chars are forbidden."""
        for code in [0x00, 0x07, 0x1B, 0x7F]:
            with self.assertRaises(EnforceValidationError, msg=f"code {code:#x}"):
                validate_enforce_block(
                    self._base(audit_log=f".claude/logs/x{chr(code)}.jsonl")
                )

    def test_audit_log_rejects_oversize_path(self):
        """Paths > 256 bytes are rejected."""
        long_path = ".claude/logs/" + "a" * 250 + ".jsonl"
        # 13 + 250 + 6 = 269 bytes
        with self.assertRaises(EnforceValidationError) as ctx:
            validate_enforce_block(self._base(audit_log=long_path))
        self.assertIn("256 bytes", str(ctx.exception))

    def test_audit_log_accepts_legitimate_path(self):
        """Letters / digits / dots / underscores / slashes / hyphens pass."""
        ok_path = ".claude/logs/cr-prepush_v2.audit.jsonl"
        result = validate_enforce_block(self._base(audit_log=ok_path))
        self.assertEqual(result["audit_log"], ok_path)

    def test_hook_rejects_quote_meta_chars(self):
        """Hook field gets the same strict allow-list."""
        for ch in ["'", '"', "$", ";", " "]:
            hook_with_meta = f".claude/hooks/auto/foo{ch}.ts"
            with self.assertRaises(EnforceValidationError, msg=f"ch {ch!r}"):
                validate_enforce_block(self._base(hook=hook_with_meta))

    def test_generated_from_rejects_quote_meta_chars(self):
        """generated_from field gets the same strict allow-list."""
        for ch in ["'", '"', "$", ";", " "]:
            gf_with_meta = f"memory/feedback{ch}.md"
            with self.assertRaises(EnforceValidationError, msg=f"ch {ch!r}"):
                validate_enforce_block(self._base(generated_from=gf_with_meta))


class TestPatternSafetyAgainstReDoS(unittest.TestCase):
    """v2.0.0 audit (HIGH-2) — catastrophic-backtracking detection.

    re.compile() validates a pattern's syntax in microseconds, but the
    same compiled pattern can take 88+ seconds to match against a
    crafted input. The schema now rejects the highest-frequency ReDoS
    shapes upfront and caps pattern byte-length.
    """

    def _base(self, **overrides):
        raw = {
            "tool": "Bash",
            "pattern": r"git push",
            "hook": ".claude/hooks/auto/g.ts",
            "generated_from": "memory/x.md",
        }
        raw.update(overrides)
        return raw

    def test_pattern_rejects_audit_redos_payload(self):
        """The HIGH-2 PoC payload — confirmed 88s match — must be blocked."""
        with self.assertRaises(EnforceValidationError) as ctx:
            validate_enforce_block(self._base(pattern="^(a+)+$"))
        self.assertIn("backtracking", str(ctx.exception).lower())

    def test_pattern_rejects_classic_redos_shapes(self):
        """All five canonical nested-quantifier shapes are rejected."""
        for redos in [r"(a+)+", r"(.+)+", r"(.*)+x", r"(a*)+", r"((a+)+)+", r"(a+){2,5}"]:
            with self.assertRaises(EnforceValidationError, msg=f"pattern {redos!r}"):
                validate_enforce_block(self._base(pattern=redos))

    def test_pattern_rejects_oversize(self):
        """Patterns > 512 bytes are rejected."""
        big = "a" * 600
        with self.assertRaises(EnforceValidationError) as ctx:
            validate_enforce_block(self._base(pattern=big))
        self.assertIn("512 bytes", str(ctx.exception))

    def test_pattern_accepts_legitimate_quantifier(self):
        """Single-level quantifiers (no nesting) pass."""
        for ok in [r"a+", r"a*", r"a+b", r"git push", r".*\.env$", r"(?:a|b)c+"]:
            result = validate_enforce_block(self._base(pattern=ok))
            self.assertEqual(result["pattern"], ok)

    def test_repo_filter_rejected_for_redos(self):
        """repo_filter gets the same ReDoS check."""
        with self.assertRaises(EnforceValidationError):
            validate_enforce_block(self._base(repo_filter=r"^(a+)+$"))

    def test_credential_patterns_rejected_for_redos(self):
        """Each credential_patterns[i] is checked."""
        with self.assertRaises(EnforceValidationError) as ctx:
            validate_enforce_block(self._base(
                credential_patterns=[r"AKIA[0-9A-Z]{16}", r"^(a+)+$"]
            ))
        self.assertIn("credential_patterns[1]", str(ctx.exception))


class TestBlockOnMatchToolCompatibility(unittest.TestCase):
    """v2.0.0 audit (HIGH-4) — block-on-match-guard.* requires tool=Bash.

    block-on-match-guard inspects ``tool_input.command``, which only Bash
    exposes. Pairing the template with Edit / Write / Read / etc.
    silently produces a hook that never fires — false sense of security.
    """

    def _base(self, **overrides):
        raw = {
            "tool": "Bash",
            "pattern": r"rm -rf",
            "hook": ".claude/hooks/auto/g.ts",
            "generated_from": "memory/x.md",
            "template": "block-on-match-guard.ts.template",
        }
        raw.update(overrides)
        return raw

    def test_block_on_match_with_bash_passes(self):
        """The supported pairing — block-on-match + Bash — is valid."""
        result = validate_enforce_block(self._base(tool="Bash"))
        self.assertEqual(result["tool"], "Bash")

    def test_block_on_match_rejects_non_bash_tools(self):
        """Edit / Write / Read / Glob with block-on-match are rejected."""
        for tool in ["Edit", "Write", "Read", "Glob", "MultiEdit", "Grep"]:
            with self.assertRaises(EnforceValidationError, msg=f"tool {tool}") as ctx:
                validate_enforce_block(self._base(tool=tool))
            self.assertIn("tool=Bash", str(ctx.exception))

    def test_block_on_match_check_applies_to_all_languages(self):
        """ts/py/sh template variants all require tool=Bash."""
        for lang in ["ts", "py", "sh"]:
            tpl = f"block-on-match-guard.{lang}.template"
            with self.assertRaises(EnforceValidationError, msg=f"lang {lang}"):
                validate_enforce_block(self._base(template=tpl, tool="Edit"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
