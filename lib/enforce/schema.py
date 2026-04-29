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

# Phase 2 — action-time rule re-injection.
# Re-injected text is capped to keep context spend predictable. 1024 tokens
# is a hard upper bound; rough char-budget at generation time is
# 4 * inject_token_budget chars per the standard tokenizer estimate.
DEFAULT_INJECT_TOKEN_BUDGET = 256
MAX_INJECT_TOKEN_BUDGET = 1024


class EnforceValidationError(ValueError):
    """Raised when an `enforce` block is malformed or unsafe."""


_WINDOWS_DRIVE_LETTER_RE = re.compile(r"^[A-Za-z]:[\\/]")


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

    # pattern — must compile as a regex
    if not isinstance(out["pattern"], str):
        raise EnforceValidationError("pattern must be a string")
    try:
        re.compile(out["pattern"])
    except re.error as exc:
        raise EnforceValidationError(f"pattern is not a valid regex: {exc}") from exc

    # hook — relative, no traversal, must live under .claude/hooks/auto/
    _validate_path_safe(out["hook"], "hook")
    if not out["hook"].startswith(HOOK_PATH_PREFIX):
        raise EnforceValidationError(
            f"hook must live under {HOOK_PATH_PREFIX} (got: {out['hook']!r}); "
            "this convention marks files as auto-generated"
        )

    # generated_from — relative, no traversal
    _validate_path_safe(out["generated_from"], "generated_from")

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

    # audit_log — optional; default = next to the hook
    if "audit_log" in out:
        _validate_path_safe(out["audit_log"], "audit_log")
    else:
        # Derive a sibling path: .claude/hooks/auto/foo.ts -> .../foo.audit.jsonl
        # Strip any trailing extension; if there isn't one the stem == hook path,
        # which is fine — we just append .audit.jsonl to it.
        hook_stem = re.sub(r"\.[^./\\]+$", "", out["hook"])
        out["audit_log"] = hook_stem + ".audit.jsonl"

    # repo_filter — optional regex
    if "repo_filter" in out:
        if not isinstance(out["repo_filter"], str):
            raise EnforceValidationError("repo_filter must be a string")
        try:
            re.compile(out["repo_filter"])
        except re.error as exc:
            raise EnforceValidationError(
                f"repo_filter is not a valid regex: {exc}"
            ) from exc

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

    return out
