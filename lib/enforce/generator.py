"""Hook generator — memory entry → Claude Code hook source code.

Reads a markdown memory entry with YAML frontmatter, validates the
`enforce` block, picks a matching template, and substitutes parameters
to produce ready-to-execute hook source.

Templates use {{PARAM}} placeholders (Jinja-style brackets) — no positional
substitution, no logic blocks. Brackets chosen over ${PARAM} so generated
TypeScript hooks can use template literals (`${expr}`) without escaping.
Keep the generation surface small so generated hooks are auditable
line-by-line.

Public API:
  - parse_memory_entry(md) → (meta, body)
  - pick_template(tool, pattern, template_dir) → Path
  - generate_hook(md, template_dir) → str
  - GenerationError

Security:
  - Frontmatter is loaded with yaml.safe_load (no arbitrary tag exec)
  - Pattern is regex-compiled before use (already enforced in schema)
  - Generated source is plain text — never invoked as code by the generator
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .schema import EnforceValidationError, validate_enforce_block

GENERATOR_VERSION = "2.0.0"

# Mapping from a coarse "what kind of command" to template filename.
# Keep this list small and obvious — each template has a clear role.
# When a new rule shape arrives, add a new template + entry here.
TEMPLATE_PATTERNS: tuple[tuple[str, str, str], ...] = (
    # (tool, pattern_substring, template filename)
    ("Bash", "git push", "cr-prepush-guard.ts.template"),
)


class GenerationError(RuntimeError):
    """Raised when a memory entry cannot be turned into a hook."""


# Match a YAML frontmatter block: opening `---` on a line by itself,
# then content, then a closing `---` on a line by itself. Anchored at
# start of file. DOTALL so `.` matches newlines inside the body capture.
_FRONTMATTER_RE = re.compile(
    r"\A---\s*\n(.*?)\n---\s*(?:\n(.*))?\Z",
    re.DOTALL,
)


def parse_memory_entry(md: str) -> tuple[dict[str, Any], str]:
    """Split a markdown file with YAML frontmatter into (meta, body).

    Frontmatter is the block between an opening `---` on its own line at
    the start of the file and a closing `---` on its own line. A `---`
    string elsewhere (e.g. inside the YAML or the body) is left alone.
    Returns (meta_dict, body_string). Raises GenerationError if the file
    has no frontmatter — every memory entry must have one.
    """
    match = _FRONTMATTER_RE.match(md)
    if not match:
        if not md.startswith("---"):
            raise GenerationError("memory entry has no YAML frontmatter")
        raise GenerationError(
            "frontmatter is not properly closed with '---' on its own line"
        )

    frontmatter_text = match.group(1)
    body = match.group(2) or ""

    try:
        meta = yaml.safe_load(frontmatter_text) or {}
    except yaml.YAMLError as exc:
        raise GenerationError(f"frontmatter is not valid YAML: {exc}") from exc

    if not isinstance(meta, dict):
        raise GenerationError("frontmatter must parse to a mapping")

    return meta, body


def pick_template(tool: str, pattern: str, template_dir: Path) -> Path:
    """Select a template file by (tool, pattern) match.

    First match wins. If no entry matches, raises GenerationError —
    Mnemosyne v2 ships a small library of templates; new rule shapes
    require adding a template + a TEMPLATE_PATTERNS entry.
    """
    for tmpl_tool, needle, filename in TEMPLATE_PATTERNS:
        if tool == tmpl_tool and needle in pattern:
            path = template_dir / filename
            if not path.exists():
                raise GenerationError(
                    f"matched template {filename!r} but file does not exist at {path}"
                )
            return path
    raise GenerationError(
        f"no template matches tool={tool!r} pattern={pattern!r}; "
        f"available templates: {[t[2] for t in TEMPLATE_PATTERNS]}"
    )


_PLACEHOLDER_RE = re.compile(r"\{\{([A-Z_][A-Z0-9_]*)\}\}")

# Characters that can break out of a `// line comment` in TS/JS source.
# Replaced with a single space so the value still appears (truncated) in
# the generated header but cannot inject code on a new line.
_COMMENT_BREAK_RE = re.compile(r"[\r\n  ]+")


def _safe_for_comment(value: object) -> str:
    """Neutralise comment-breaking characters so a malicious memory entry
    cannot inject TypeScript via a `//` line comment in the template."""
    return _COMMENT_BREAK_RE.sub(" ", str(value))


def _render(template_text: str, params: dict[str, str]) -> str:
    """Substitute {{PARAM}} placeholders. Raise on any unfilled placeholders.

    Uses {{PARAM}} (Jinja-style brackets) instead of ${PARAM} so generated
    TypeScript hooks can use template literals (`${expr}`) freely without
    needing to escape them in the template source.
    """
    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in params:
            raise GenerationError(f"template missing parameter for placeholder {{{{{key}}}}}")
        return params[key]

    rendered = _PLACEHOLDER_RE.sub(_replace, template_text)
    # Defensive: ensure no placeholders survived
    if _PLACEHOLDER_RE.search(rendered):
        raise GenerationError(
            "rendered output still contains {{...}} placeholders — refusing to emit"
        )
    return rendered


def _build_injection_snippet(enforce: dict[str, Any], body: str) -> tuple[str, str]:
    """Build the TS code snippets that the template substitutes when
    inject_on_match is enabled.

    Returns ``(inject_block, inject_call)``:
      - ``inject_block``: top-level TS lines (constant + function), or empty
      - ``inject_call``: the line inside main() that triggers re-injection,
        or empty when injection is disabled

    The injected text is capped at ~4 chars/token so context spend stays
    predictable for operators tuning ``inject_token_budget``.
    """
    if not enforce.get("inject_on_match"):
        return "", ""

    text = enforce.get("inject_text") or body.strip()
    if not text:
        # Defensive: if both inject_text and body are empty, no point emitting
        # an empty additionalContext. Treat as disabled.
        return "", ""

    # Neutralise template-like sequences so user text containing literal
    # `{{...}}` cannot trip _render's placeholder-residue guard. The
    # injected JSON literal already escapes quotes/backslashes; we only
    # need to break the `{{` / `}}` pairs the placeholder regex matches.
    text = text.replace("{{", "{ {").replace("}}", "} }")

    # Cap to char budget. Keep the truncation suffix INSIDE the budget so
    # the final string never exceeds inject_token_budget * 4 chars.
    suffix = "…[truncated]"
    char_budget = enforce["inject_token_budget"] * 4
    if len(text) > char_budget:
        keep = max(0, char_budget - len(suffix))
        text = text[:keep].rstrip() + suffix
        # Edge case: if suffix itself overflows the budget, return a
        # tail-truncated suffix so we never exceed char_budget.
        if len(text) > char_budget:
            text = suffix[-char_budget:]

    text_json = json.dumps(text)
    inject_block = (
        f"\nconst INJECT_TEXT = {text_json};\n"
        "function emitInjection(): void {\n"
        "  console.log(JSON.stringify({ additionalContext: INJECT_TEXT }));\n"
        "}\n"
    )
    inject_call = "  emitInjection();\n"
    return inject_block, inject_call


def generate_hook(md: str, template_dir: Path) -> str:
    """End-to-end: memory entry markdown → hook source string."""
    meta, body = parse_memory_entry(md)

    if "enforce" not in meta:
        raise GenerationError(
            "memory entry has no `enforce` block — not eligible for hook generation"
        )

    enforce = validate_enforce_block(meta["enforce"])

    template_path = pick_template(
        tool=enforce["tool"],
        pattern=enforce["pattern"],
        template_dir=template_dir,
    )
    template_text = template_path.read_text(encoding="utf-8")

    inject_block, inject_call = _build_injection_snippet(enforce, body)

    # Build the substitution dict. Use json.dumps for the regex pattern
    # so any quotes / backslashes survive the round-trip into TypeScript
    # source unscathed. For values that land inside `//` line comments
    # in the template, neutralise newlines / CR / line-separator chars so
    # a malicious memory entry cannot break out of the comment and inject
    # code into the generated hook.
    params = {
        "TOOL": enforce["tool"],
        "PATTERN_JSON": json.dumps(enforce["pattern"]),
        "REPO_FILTER_JSON": json.dumps(enforce.get("repo_filter", "")),
        "FRESHNESS_SECS": str(enforce["freshness_secs"]),
        "GENERATED_FROM": _safe_for_comment(enforce["generated_from"]),
        "HOOK_PATH": _safe_for_comment(enforce["hook"]),
        "AUDIT_LOG_PATH": _safe_for_comment(enforce["audit_log"]),
        "GENERATOR_VERSION": _safe_for_comment(
            enforce.get("generator_version", GENERATOR_VERSION)
        ),
        "GENERATED_AT": _safe_for_comment(
            enforce.get(
                "generated_at",
                datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
        ),
        "INJECT_BLOCK": inject_block,
        "INJECT_CALL": inject_call,
    }

    return _render(template_text, params)


# Re-export for convenience so callers can `from enforce.generator import …`
__all__ = [
    "EnforceValidationError",
    "GENERATOR_VERSION",
    "GenerationError",
    "generate_hook",
    "parse_memory_entry",
    "pick_template",
]
