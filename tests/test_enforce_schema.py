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


if __name__ == "__main__":
    unittest.main(verbosity=2)
