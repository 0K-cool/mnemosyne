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


def parse_memory_entry(md: str) -> tuple[dict[str, Any], str]:
    """Split a markdown file with YAML frontmatter into (meta, body).

    Frontmatter is the block between the first two `---` lines. Returns
    a (meta_dict, body_string) tuple. Raises GenerationError if the file
    has no frontmatter — every memory entry must have one.
    """
    if not md.startswith("---"):
        raise GenerationError("memory entry has no YAML frontmatter")

    parts = md.split("---", 2)
    if len(parts) < 3:
        raise GenerationError("frontmatter is not properly closed with '---'")

    _, frontmatter_text, body = parts
    try:
        meta = yaml.safe_load(frontmatter_text) or {}
    except yaml.YAMLError as exc:
        raise GenerationError(f"frontmatter is not valid YAML: {exc}") from exc

    if not isinstance(meta, dict):
        raise GenerationError("frontmatter must parse to a mapping")

    return meta, body.lstrip("\n")


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


def generate_hook(md: str, template_dir: Path) -> str:
    """End-to-end: memory entry markdown → hook source string."""
    meta, _ = parse_memory_entry(md)

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

    # Build the substitution dict. Use json.dumps for the regex pattern
    # so any quotes / backslashes survive the round-trip into TypeScript
    # source unscathed.
    params = {
        "TOOL": enforce["tool"],
        "PATTERN_JSON": json.dumps(enforce["pattern"]),
        "REPO_FILTER_JSON": json.dumps(enforce.get("repo_filter", "")),
        "FRESHNESS_SECS": str(enforce["freshness_secs"]),
        "GENERATED_FROM": enforce["generated_from"],
        "HOOK_PATH": enforce["hook"],
        "AUDIT_LOG_PATH": enforce["audit_log"],
        "GENERATOR_VERSION": enforce.get("generator_version", GENERATOR_VERSION),
        "GENERATED_AT": enforce.get(
            "generated_at",
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
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
