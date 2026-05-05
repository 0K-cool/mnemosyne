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
    # Order matters — first match wins. Put more specific patterns first
    # so they shadow more general ones (e.g. "--force" must be considered
    # before "git push" because every force push contains both).
    ("Bash", "--force", "force-push-guard.ts.template"),
    ("Bash", "git push", "cr-prepush-guard.ts.template"),
)

# Phase 4.2: curated default credential patterns for credential-leak-guard.
# Conservative list — only high-confidence formats to keep the false-positive
# rate low. AWS secret keys (40-char base64) are intentionally excluded —
# they collide with too many legitimate hashes / build artifacts.
# Operators extend via `enforce.credential_patterns:` in their memory entry.
DEFAULT_CREDENTIAL_PATTERNS: tuple[str, ...] = (
    r"AKIA[0-9A-Z]{16}",                              # AWS access key id
    r"github_pat_[A-Za-z0-9_]{82}",                   # GitHub fine-grained PAT
    r"gh[pousr]_[A-Za-z0-9]{36}",                     # GitHub classic tokens
    r"xox[abprs]-[A-Za-z0-9-]{10,}",                  # Slack tokens
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",            # PEM private key headers
    r"(sk|pk|rk)_live_[A-Za-z0-9]{24,}",              # Stripe live keys
    r"npm_[A-Za-z0-9]{36}",                           # npm publish tokens
    r"glpat-[A-Za-z0-9_-]{20,}",                      # GitLab PATs
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


def _swap_language_suffix(filename: str, language: str) -> str:
    """Convert a `<base>.ts.template` filename into `<base>.<lang>.template`.

    No-op when the requested language is `ts` (the default), or when the
    filename doesn't end in `.ts.template` — in that case we trust the
    operator's explicit choice. Internal helper.
    """
    if language == "ts":
        return filename
    if filename.endswith(".ts.template"):
        return filename[: -len(".ts.template")] + f".{language}.template"
    return filename


def pick_template(
    tool: str,
    pattern: str,
    template_dir: Path,
    language: str = "ts",
) -> Path:
    """Select a template file by (tool, pattern) match, honouring language.

    First match wins. If no entry matches, raises GenerationError —
    Mnemosyne v2 ships a small library of templates; new rule shapes
    require adding a template + a TEMPLATE_PATTERNS entry.

    The TEMPLATE_PATTERNS table is canonically TypeScript; for language
    `py` / `sh` the suffix is swapped to `<base>.<lang>.template`. If
    that file doesn't exist, the error names which language port is
    missing — silent fallback to TS would emit the wrong runtime.
    """
    for tmpl_tool, needle, filename in TEMPLATE_PATTERNS:
        if tool == tmpl_tool and needle in pattern:
            resolved = _swap_language_suffix(filename, language)
            path = template_dir / resolved
            if not path.exists():
                if resolved != filename:
                    raise GenerationError(
                        f"no {language!r} port of {filename!r} available "
                        f"(looked for {resolved!r}); set explicit "
                        f"`template:` or use language: ts"
                    )
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


def _safe_for_line_comment(value: object) -> str:
    """Neutralise line-terminator characters so a malicious memory entry
    cannot inject code by escaping a ``// …`` or ``# …`` line comment.

    SCOPE: comment-line contexts only. Do NOT use this for values that
    land inside string literals, template literals, or shell variable
    expansions — the audit (HIGH-3) showed the four characters this
    function strips are insufficient for those contexts. Use
    ``_safe_for_ts_string`` / ``_safe_for_py_string`` /
    ``_safe_for_shell_dollar_quote`` instead.
    """
    return _COMMENT_BREAK_RE.sub(" ", str(value))


# Backward-compat alias for any external importers; remove in v2.1.0.
_safe_for_comment = _safe_for_line_comment


def _safe_for_ts_string(value: object) -> str:
    """Encode a value as a TypeScript / JavaScript string literal.

    Returns the json.dumps form (with surrounding double quotes). The
    template MUST NOT add its own quotes around the placeholder — the
    encoded value already includes them. Equivalent to a JS string
    literal: any quote, backslash, control char, or line terminator
    inside the value is escaped, so the resulting source parses
    cleanly under ``bun build`` regardless of the input.
    """
    return json.dumps(str(value))


def _safe_for_py_string(value: object) -> str:
    """Encode a value as a Python string literal.

    json.dumps output is also a valid Python string literal (Python
    accepts double-quoted strings with ``\\\\`` / ``\\n`` / ``\\uXXXX``
    escapes the same way JSON does). Same template contract as
    ``_safe_for_ts_string``: do not surround the placeholder with
    additional quotes.
    """
    return json.dumps(str(value))


def _safe_for_shell_dollar_quote(value: object) -> str:
    """Encode a value as a bash ANSI-C ``$'...'`` quoted string.

    Inside ``$'...'``, ``$`` and backticks are literal — regex
    metacharacters and shell metacharacters round-trip without
    expansion. The only chars that need escaping are backslash and
    single-quote. Same template contract: no surrounding quotes in
    the template — the encoded form already provides ``$'...'``.
    """
    return "$'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


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

    # Phase 4: explicit `template` field overrides TEMPLATE_PATTERNS dispatch.
    explicit = enforce.get("template")
    if explicit:
        template_path = template_dir / explicit
        if not template_path.exists():
            raise GenerationError(
                f"explicit template {explicit!r} not found in {template_dir}"
            )
    else:
        template_path = pick_template(
            tool=enforce["tool"],
            pattern=enforce["pattern"],
            template_dir=template_dir,
            language=enforce["language"],
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
        # Phase 5: shell-safe form for the .sh.template port. Uses
        # bash ANSI-C quoting `$'...'` — `$` and backticks are literal
        # inside it, so regex metacharacters round-trip without
        # shell-level mangling. v2.0.0 audit CR follow-up: routed
        # through `_safe_for_shell_dollar_quote` so the escaping logic
        # has a single source of truth (was previously duplicated here).
        "PATTERN_SH": _safe_for_shell_dollar_quote(enforce["pattern"]),
        "REPO_FILTER_JSON": json.dumps(enforce.get("repo_filter", "")),
        "FRESHNESS_SECS": str(enforce["freshness_secs"]),
        # v2.0.0 audit (HIGH-3) — these go into LINE COMMENT contexts only
        # (header banners, ``// Source memory entry: …``). Strict-allow-
        # list at the schema layer guarantees the values are bare paths
        # without quote/meta characters; this sanitiser only neutralises
        # line terminators that would otherwise escape the comment.
        "GENERATED_FROM": _safe_for_line_comment(enforce["generated_from"]),
        "HOOK_PATH": _safe_for_line_comment(enforce["hook"]),
        "AUDIT_LOG_PATH": _safe_for_line_comment(enforce["audit_log"]),
        "GENERATOR_VERSION": _safe_for_line_comment(
            enforce.get("generator_version", GENERATOR_VERSION)
        ),
        "GENERATED_AT": _safe_for_line_comment(
            enforce.get(
                "generated_at",
                datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
        ),
        # v2.0.0 audit (HIGH-3) — context-specific encodings of the same
        # values, for placement inside string-literal contexts in the
        # rendered hook source. Templates that use these MUST NOT add
        # surrounding quotes — the encoded form already provides them.
        # Defense-in-depth on top of the schema-layer allow-list (CRIT-1
        # primary fix).
        "AUDIT_LOG_PATH_TS": _safe_for_ts_string(enforce["audit_log"]),
        "AUDIT_LOG_PATH_PY": _safe_for_py_string(enforce["audit_log"]),
        "AUDIT_LOG_PATH_SH": _safe_for_shell_dollar_quote(enforce["audit_log"]),
        "GENERATED_FROM_TS": _safe_for_ts_string(enforce["generated_from"]),
        "GENERATED_FROM_PY": _safe_for_py_string(enforce["generated_from"]),
        "GENERATED_FROM_SH": _safe_for_shell_dollar_quote(enforce["generated_from"]),
        "INJECT_BLOCK": inject_block,
        "INJECT_CALL": inject_call,
        # Phase 4.1: default applied here so the schema stays template-agnostic.
        "PROTECTED_BRANCHES_JSON": json.dumps(
            enforce.get("protected_branches", ["main", "master"])
        ),
        # Phase 4.2: curated default credential pattern list. Conservative —
        # only high-confidence patterns to keep the FP rate low. Operators
        # extend via enforce.credential_patterns: in their memory entry.
        "CREDENTIAL_PATTERNS_JSON": json.dumps(
            enforce.get("credential_patterns", DEFAULT_CREDENTIAL_PATTERNS)
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
