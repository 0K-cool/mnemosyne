"""Schema validation for `enforce` frontmatter blocks (Mnemosyne v2).

The `enforce` block on a memory entry says "this rule should be enforced
as a runtime hook." This module validates the structure before any hook
is generated. Invalid blocks raise EnforceValidationError with a clear
reason — bad rules should not silently produce no-op hooks.

Schema v0.1:
  enforce:
    tool: <ClaudeCodeToolName>          # required
    pattern: <regex string>             # required, must compile
    hook: <relative path under .claude/hooks/auto/>  # required
    generated_from: <relative memory path>           # required
    freshness_secs: <positive int>      # optional, default 1800
    audit_log: <relative path>          # optional, default <hook>.audit.jsonl
    generator_version: <semver>         # optional
    generated_at: <ISO 8601>            # optional
    repo_filter: <regex string>         # optional, must compile if present

Security:
  - Path-traversal guard on `hook` and `audit_log`
  - `hook` MUST live under `.claude/hooks/auto/` so generated artifacts
    are clearly distinguished from hand-written hooks
  - Tool name MUST be one of Claude Code's known tools (no custom shells)
"""

from __future__ import annotations

import re
from typing import Any

# Known Claude Code tool names (allow-list — keep tight; expand only when
# new tools ship). See https://code.claude.com/docs/en/tools for the
# canonical list.
KNOWN_TOOLS: frozenset[str] = frozenset(
    {
        "Bash",
        "Edit",
        "Glob",
        "Grep",
        "MultiEdit",
        "NotebookEdit",
        "NotebookRead",
        "Read",
        "Task",
        "TodoWrite",
        "WebFetch",
        "WebSearch",
        "Write",
    }
)

DEFAULT_FRESHNESS_SECS = 1800  # 30 minutes
HOOK_PATH_PREFIX = ".claude/hooks/auto/"
REQUIRED_FIELDS: tuple[str, ...] = ("tool", "pattern", "hook", "generated_from")

# Phase 5 — multi-language hook generators. Operators pick the language
# the generated hook should be emitted in. Default `ts` keeps every
# existing memory entry working unchanged.
SUPPORTED_LANGUAGES: frozenset[str] = frozenset({"ts", "py", "sh"})
DEFAULT_LANGUAGE = "ts"

# Phase 2 — action-time rule re-injection.
# Re-injected text is capped to keep context spend predictable. 1024 tokens
# is a hard upper bound; rough char-budget at generation time is
# 4 * inject_token_budget chars per the standard tokenizer estimate.
DEFAULT_INJECT_TOKEN_BUDGET = 256
MAX_INJECT_TOKEN_BUDGET = 1024


class EnforceValidationError(ValueError):
    """Raised when an `enforce` block is malformed or unsafe."""


_WINDOWS_DRIVE_LETTER_RE = re.compile(r"^[A-Za-z]:[\\/]")

# Phase 4.2: Python-only regex constructs that compile under `re` but
# throw `SyntaxError` under JS `new RegExp(…)`. Used to gate
# `credential_patterns` entries before they land in a generated hook.
#   (?P<name>…)   Python named group        — JS uses (?<name>…)
#   (?P=name)     Python named backref      — JS uses \k<name>
#   (?aiLmsux…)   Python inline flag block  — JS only honours i/m/s/d/u/y/v
_PY_ONLY_REGEX_FORMS = re.compile(r"\(\?P[<=]|\(\?[aiLmsux]+[):]")

# v2.0.0 audit (CRIT-1) — strict character allow-list for path fields used
# in generated hook source. Disallows any character that could escape a
# string-literal context in TS / Python / shell (quotes, $, backticks,
# parens, semicolons, whitespace, control chars, Unicode confusables).
_PATH_STRICT_RE = re.compile(r"^[A-Za-z0-9_./-]+$")
_PATH_MAX_BYTES = 256

# v2.0.0 audit (HIGH-2) — pattern length cap and catastrophic-backtracking
# detection. Both gates are conservative — they catch the highest-frequency
# ReDoS shapes without trying to be a full regex complexity analyser.
_PATTERN_MAX_BYTES = 512
# Nested unbounded quantifiers: a quantifier (`+`, `*`, `{n,}`, `?`) that
# closes a group whose contents already include `+` or `*`. Catches the
# classic shapes (a+)+, (a*)+, (.+)+, (.*)+x, ((a+)+)+, (a+){2,5}.
_NESTED_QUANTIFIER_RE = re.compile(r"[+*]\s*\)\s*[+*?{]")

# v2.0.0 audit (HIGH-4) — the block-on-match-guard.* templates inspect
# tool_input.command, which only exists on the Bash tool. Pairing them
# with Edit / Write / Read / etc. produces a hook that silently never
# fires. Reject the combination at validation time.
_BLOCK_ON_MATCH_GUARD_RE = re.compile(r"^block-on-match-guard\.(ts|py|sh)\.template$")
_BLOCK_ON_MATCH_REQUIRED_TOOLS = frozenset({"Bash"})


def _has_traversal(path: str) -> bool:
    r"""True if a relative path contains traversal segments or is absolute.

    Rejects:
      - POSIX absolute paths (``/etc/...``)
      - UNC / Windows root paths (``\\server\share``, ``\...``)
      - Windows drive-letter absolutes (``C:\...``, ``D:/...``)
      - Any segment of ``.`` or ``..`` (traversal)
    """
    if path.startswith(("/", "\\")):
        return True
    if _WINDOWS_DRIVE_LETTER_RE.match(path):
        return True
    parts = re.split(r"[\\/]+", path)
    return any(p in ("..", ".") for p in parts if p)


def _validate_path_safe(path: str, label: str) -> None:
    if not isinstance(path, str) or not path.strip():
        raise EnforceValidationError(f"{label} must be a non-empty string")
    if _has_traversal(path):
        raise EnforceValidationError(
            f"{label} must be a relative path with no traversal: {path!r}"
        )


def _validate_path_strict_chars(path: str, label: str) -> None:
    """Strict character allow-list + byte-length cap for path fields.

    Tighter than ``_validate_path_safe`` — disallows any character that
    could escape a string-literal context in TS / Python / shell source
    (quotes, ``$``, backtick, parens, semicolons, whitespace, control
    chars, Unicode confusables). The generator additionally JSON-encodes
    these values when they cross into source code, so this is the
    primary defense (validation-time block) plus defense-in-depth at
    generation. v2.0.0 audit (CRIT-1) recommendation.
    """
    if len(path.encode("utf-8")) > _PATH_MAX_BYTES:
        raise EnforceValidationError(
            f"{label} exceeds {_PATH_MAX_BYTES} bytes"
        )
    if not _PATH_STRICT_RE.match(path):
        raise EnforceValidationError(
            f"{label} must match {_PATH_STRICT_RE.pattern} "
            f"(letters, digits, dot, underscore, slash, hyphen only — no "
            f"quotes, dollar signs, parens, or shell metas): {path!r}"
        )


def _validate_pattern_safety(pattern: str, label: str) -> None:
    """Reject regex patterns that risk catastrophic backtracking / DoS.

    Two conservative gates: a 512-byte length cap, and a nested-unbounded-
    quantifier shape detector. v2.0.0 audit (HIGH-2) showed
    ``re.compile()`` accepts ``^(a+)+$`` in microseconds, but
    ``re.search('^(a+)+$', 'a'*30 + 'X')`` runs for 88 seconds. The same
    shape DoSes V8 RegExp and grep ERE. We catch the most common shape
    here; runtime templates additionally enforce a per-match timeout.
    """
    if len(pattern.encode("utf-8")) > _PATTERN_MAX_BYTES:
        raise EnforceValidationError(
            f"{label} exceeds {_PATTERN_MAX_BYTES} bytes"
        )
    if _NESTED_QUANTIFIER_RE.search(pattern):
        raise EnforceValidationError(
            f"{label} contains nested unbounded quantifiers "
            f"(catastrophic backtracking risk): {pattern!r}"
        )


def validate_enforce_block(raw: Any) -> dict[str, Any]:
    """Validate and normalise an enforce block.

    Returns a new dict with defaults applied. Never mutates the input.
    Raises EnforceValidationError with a specific reason on any failure.
    """
    if not isinstance(raw, dict):
        raise EnforceValidationError(
            f"enforce block must be a dict, got {type(raw).__name__}"
        )

    out = dict(raw)  # shallow copy; do not mutate caller

    for field in REQUIRED_FIELDS:
        if field not in out or out[field] in ("", None):
            raise EnforceValidationError(f"missing required field: {field!r}")

    # tool — must be a known Claude Code tool
    if out["tool"] not in KNOWN_TOOLS:
        raise EnforceValidationError(
            f"unknown tool {out['tool']!r}; allowed: {sorted(KNOWN_TOOLS)}"
        )

    # pattern — must compile as a regex, length-capped, no ReDoS shapes
    if not isinstance(out["pattern"], str):
        raise EnforceValidationError("pattern must be a string")
    try:
        re.compile(out["pattern"])
    except re.error as exc:
        raise EnforceValidationError(f"pattern is not a valid regex: {exc}") from exc
    _validate_pattern_safety(out["pattern"], "pattern")

    # hook — relative, no traversal, strict allow-list, under .claude/hooks/auto/
    _validate_path_safe(out["hook"], "hook")
    _validate_path_strict_chars(out["hook"], "hook")
    if not out["hook"].startswith(HOOK_PATH_PREFIX):
        raise EnforceValidationError(
            f"hook must live under {HOOK_PATH_PREFIX} (got: {out['hook']!r}); "
            "this convention marks files as auto-generated"
        )

    # generated_from — relative, no traversal, strict allow-list
    _validate_path_safe(out["generated_from"], "generated_from")
    _validate_path_strict_chars(out["generated_from"], "generated_from")

    # freshness_secs — positive int (strict; reject bools, floats, strings)
    raw_freshness = out.get("freshness_secs", DEFAULT_FRESHNESS_SECS)
    if isinstance(raw_freshness, bool) or not isinstance(raw_freshness, int):
        raise EnforceValidationError(
            f"freshness_secs must be a positive int, got {type(raw_freshness).__name__}"
        )
    if raw_freshness <= 0:
        raise EnforceValidationError(
            f"freshness_secs must be > 0, got {raw_freshness}"
        )
    out["freshness_secs"] = raw_freshness

    # audit_log — optional; default = next to the hook. Strict-allow-list
    # enforced regardless of source (operator-set or generator-derived).
    if "audit_log" in out:
        _validate_path_safe(out["audit_log"], "audit_log")
    else:
        # Derive a sibling path: .claude/hooks/auto/foo.ts -> .../foo.audit.jsonl
        # Strip any trailing extension; if there isn't one the stem == hook path,
        # which is fine — we just append .audit.jsonl to it.
        hook_stem = re.sub(r"\.[^./\\]+$", "", out["hook"])
        out["audit_log"] = hook_stem + ".audit.jsonl"
    _validate_path_strict_chars(out["audit_log"], "audit_log")

    # repo_filter — optional regex, length-capped, no ReDoS shapes
    if "repo_filter" in out:
        if not isinstance(out["repo_filter"], str):
            raise EnforceValidationError("repo_filter must be a string")
        try:
            re.compile(out["repo_filter"])
        except re.error as exc:
            raise EnforceValidationError(
                f"repo_filter is not a valid regex: {exc}"
            ) from exc
        _validate_pattern_safety(out["repo_filter"], "repo_filter")

    # ---- Phase 4: optional explicit template selection ----

    # template — optional basename of a template file. When present,
    # the generator uses this template directly instead of consulting
    # TEMPLATE_PATTERNS for tool/pattern-based dispatch.
    if "template" in out:
        candidate = out["template"]
        if not isinstance(candidate, str) or not candidate.strip():
            raise EnforceValidationError(
                "template must be a non-empty string when present"
            )
        # Reject absolute paths, traversal, and subdirectory paths.
        # Templates are basename-only — they live in the bundled
        # template_dir. Subdirectory layouts can be added in a future
        # phase if a clear use case emerges.
        if _has_traversal(candidate) or "/" in candidate or "\\" in candidate:
            raise EnforceValidationError(
                f"template must be a basename only (no path separators): {candidate!r}"
            )

        # v2.0.0 audit (HIGH-4) — block-on-match-guard.* templates inspect
        # tool_input.command, which only exists on Bash. Pairing them with
        # any other tool produces a hook that silently never fires.
        if (
            _BLOCK_ON_MATCH_GUARD_RE.match(candidate)
            and out["tool"] not in _BLOCK_ON_MATCH_REQUIRED_TOOLS
        ):
            raise EnforceValidationError(
                f"template {candidate!r} requires tool=Bash "
                f"(it inspects tool_input.command which non-Bash tools "
                f"don't expose); got tool={out['tool']!r}. Use a different "
                f"template or change the tool."
            )

    # ---- Phase 2: action-time rule re-injection fields ----

    # inject_on_match — strict bool; default False
    raw_inject = out.get("inject_on_match", False)
    if not isinstance(raw_inject, bool):
        raise EnforceValidationError(
            f"inject_on_match must be a bool, got {type(raw_inject).__name__}"
        )
    out["inject_on_match"] = raw_inject

    # inject_text — optional non-empty string; falls back to memory body at
    # generation time when omitted.
    if "inject_text" in out:
        candidate = out["inject_text"]
        if not isinstance(candidate, str) or not candidate.strip():
            raise EnforceValidationError(
                "inject_text must be a non-empty string when present"
            )

    # inject_token_budget — positive int, capped at MAX_INJECT_TOKEN_BUDGET
    raw_budget = out.get("inject_token_budget", DEFAULT_INJECT_TOKEN_BUDGET)
    if isinstance(raw_budget, bool) or not isinstance(raw_budget, int):
        raise EnforceValidationError(
            f"inject_token_budget must be a positive int, got {type(raw_budget).__name__}"
        )
    if raw_budget <= 0:
        raise EnforceValidationError(
            f"inject_token_budget must be > 0, got {raw_budget}"
        )
    if raw_budget > MAX_INJECT_TOKEN_BUDGET:
        raise EnforceValidationError(
            f"inject_token_budget must be ≤ {MAX_INJECT_TOKEN_BUDGET}, got {raw_budget}"
        )
    out["inject_token_budget"] = raw_budget

    # ---- Phase 5: multi-language hook generation ----

    # language — optional string, must be one of SUPPORTED_LANGUAGES.
    # Default `ts` keeps every existing memory entry working unchanged.
    raw_language = out.get("language", DEFAULT_LANGUAGE)
    if not isinstance(raw_language, str):
        raise EnforceValidationError(
            f"language must be a string, got {type(raw_language).__name__}"
        )
    if raw_language not in SUPPORTED_LANGUAGES:
        raise EnforceValidationError(
            f"language must be one of {sorted(SUPPORTED_LANGUAGES)}, got {raw_language!r}"
        )
    out["language"] = raw_language

    # Cross-field constraint: Phase 2 re-injection (`inject_on_match`)
    # currently only emits TypeScript glue. Reject the combo with
    # non-TS languages until py/sh re-injection ports land — better
    # to fail loud at validation than emit a broken hook.
    if out.get("inject_on_match", False) and raw_language != "ts":
        raise EnforceValidationError(
            f"inject_on_match: true is only supported with language: ts "
            f"in v2 (got language: {raw_language!r}). Re-injection ports "
            f"for py / sh are tracked as a Phase 5.x follow-up."
        )

    # ---- Phase 4.2: credential-leak-guard parameters ----

    # credential_patterns — optional list of non-empty regex strings.
    # Each must compile under Python re AND be portable to JavaScript
    # RegExp (since the rendered hook compiles them via `new RegExp()`).
    # Consumed by credential-leak-guard.ts.template; the generator
    # applies a curated default when this field is omitted, so schema
    # only validates shape when set explicitly.
    if "credential_patterns" in out:
        candidate = out["credential_patterns"]
        if not isinstance(candidate, list):
            raise EnforceValidationError(
                f"credential_patterns must be a list, got {type(candidate).__name__}"
            )
        if not candidate:
            raise EnforceValidationError(
                "credential_patterns must be non-empty when present"
            )
        for i, item in enumerate(candidate):
            if not isinstance(item, str) or not item.strip():
                raise EnforceValidationError(
                    f"credential_patterns[{i}] must be a non-empty string, got {item!r}"
                )
            try:
                re.compile(item)
            except re.error as exc:
                raise EnforceValidationError(
                    f"credential_patterns[{i}] is not a valid regex: {exc}"
                ) from exc
            _validate_pattern_safety(item, f"credential_patterns[{i}]")
            # Reject the most common Python-only regex constructs that
            # compile under `re` but throw under JS `new RegExp()`. We
            # don't try to be exhaustive (a full validator would need
            # a JS runtime), but we catch the highest-frequency
            # footguns: Python named groups `(?P<name>…)` /
            # backreferences `(?P=name)`, and Python inline flags
            # `(?aiLmsux:…)` (JS only honours i/m/s/d/u/y/v).
            #
            # Note: the inverse problem (JS-only syntax like `(?<name>…)`
            # named groups) is caught by the Python re.compile above —
            # Python rejects that form because it expects `(?P<name>…)`.
            # The portable subset documented for credential_patterns is
            # therefore the intersection: no named groups, no Python
            # inline flag blocks. Use unnamed `(…)` groups for
            # cross-syntax patterns.
            if _PY_ONLY_REGEX_FORMS.search(item):
                raise EnforceValidationError(
                    f"credential_patterns[{i}] uses Python-only regex syntax that "
                    f"will fail under JS RegExp at runtime: {item!r}. Stick to the "
                    f"JS-portable subset — use unnamed `(…)` groups instead of "
                    f"the Python `(?P<name>…)` form."
                )

    # ---- Phase 4.1: force-push-guard parameters ----

    # protected_branches — optional list of non-empty branch-name strings.
    # Consumed by force-push-guard.ts.template; the generator applies the
    # default (main, master) when this field is omitted, so schema only
    # validates shape when the operator sets it explicitly.
    if "protected_branches" in out:
        candidate = out["protected_branches"]
        if not isinstance(candidate, list):
            raise EnforceValidationError(
                f"protected_branches must be a list, got {type(candidate).__name__}"
            )
        if not candidate:
            raise EnforceValidationError(
                "protected_branches must be non-empty when present"
            )
        for i, item in enumerate(candidate):
            if not isinstance(item, str) or not item.strip():
                raise EnforceValidationError(
                    f"protected_branches[{i}] must be a non-empty string, got {item!r}"
                )
            if any(c.isspace() for c in item):
                raise EnforceValidationError(
                    f"protected_branches[{i}] must not contain whitespace, got {item!r}"
                )

    return out
