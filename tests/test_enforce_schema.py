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
        for bad in ("../../etc/passwd.ts", "..\\..\\windows.ts", "/etc/passwd.ts"):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
