"""content_scanner.py — read-time injection scanner for retrieved memory.

Mirrors the INJECTION_PATTERNS and normalisation semantics of
hooks/memory-validation.ts so the read path and write path share consistent
detection. Applied to every chunk returned by MarkdownRetriever and to every
`original_chunk` from lancedb RAG results before they reach the LLM via
`additionalContext`.

Architectural rationale: the write-path hook (memory-validation.ts) guards
only Claude Code's own Write/Edit/MultiEdit tools. Every other write channel
(git pull, curl, editor auto-save, other MCP servers, shell redirection,
subagent tool calls) bypasses it. The read path is the trust boundary that
cannot be bypassed — every retrieval necessarily flows through auto-retrieve.
This scanner enforces that boundary.

Security mapping:
  OWASP LLM 2025: LLM01 (Prompt Injection), LLM04 (Data & Model Poisoning)
  MITRE ATLAS: AML.T0051, AML.T0063 (Context Poisoning), AML.T0068 (RAG Poisoning)

Source-code hygiene: all invisible / confusable Unicode characters are
referenced via \\uXXXX escape sequences (Ruff PLE2515 / RUF001) so a
reviewer reading this file can see what's in every pattern without relying
on editor rendering.
"""

import re
import unicodedata
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# Patterns — ported from hooks/memory-validation.ts INJECTION_PATTERNS
# Keep in lock-step until the shared YAML extraction (v1.1.1, MED-4 / M-2).
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
    (
        re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions?", re.IGNORECASE),
        "Prompt injection: ignore previous instructions",
    ),
    (
        re.compile(r"you\s+are\s+now\b", re.IGNORECASE),
        "Identity override: 'you are now'",
    ),
    (
        re.compile(r"\bsystem\s*:", re.IGNORECASE),
        "Fake system prompt marker: 'system:'",
    ),
    (
        re.compile(r"<\s*system\s*>", re.IGNORECASE),
        "XML system tag injection: <system>",
    ),
    (
        re.compile(r"<\s*/\s*system\s*>", re.IGNORECASE),
        "XML system closing tag injection: </system>",
    ),
    (
        re.compile(r"do\s+not\s+follow\s+(?:the\s+)?rules?", re.IGNORECASE),
        "Rule override: 'do not follow rules'",
    ),
    (
        re.compile(r"override\s+(?:all\s+)?polic(?:y|ies)", re.IGNORECASE),
        "Policy override attempt",
    ),
    (
        re.compile(r"act\s+as\s+(?:an?\s+)?admin(?:istrator)?", re.IGNORECASE),
        "Privilege escalation: 'act as admin'",
    ),
    (
        re.compile(r"forget\s+(?:all\s+)?previous(?:\s+context)?", re.IGNORECASE),
        "Context wipe: 'forget previous'",
    ),
    # 0din threat model — fake authorization + semantic injection
    (
        re.compile(
            r"\bauthorized\s*:\s*.{0,30}(?:access|grant|approv|admin|elevat)",
            re.IGNORECASE,
        ),
        "Fake authorization claim",
    ),
    (
        re.compile(
            r"(?:admin|elevated|root|unrestricted)\s+(?:access|privileges?|permissions?|mode)\s+(?:grant|confirm|approv|enabl)",
            re.IGNORECASE,
        ),
        "Privilege escalation: fake access grant",
    ),
    (
        re.compile(
            r"(?:security\s+clearance|approval_policy)\s*:\s*",
            re.IGNORECASE,
        ),
        "Fake security clearance or policy override marker",
    ),
    (
        re.compile(
            r"operate\s+without\s+(?:any\s+)?(?:restrict|limit|constraint|boundar)",
            re.IGNORECASE,
        ),
        "Semantic injection: 'operate without restrictions'",
    ),
    (
        re.compile(
            r"(?:safety|security)\s+concerns?\s+(?:have\s+been|were)\s+(?:resolv|address|clear|remov)",
            re.IGNORECASE,
        ),
        "Fake safety resolution claim",
    ),
    (
        re.compile(
            r"(?:user|owner|operator)\s+has\s+(?:explicitly\s+)?(?:consent|authoriz|approv|grant)",
            re.IGNORECASE,
        ),
        "Fake consent claim",
    ),
)

# ---------------------------------------------------------------------------
# Confusables — Cyrillic + Greek → Latin
# Port of hooks/memory-validation.ts CONFUSABLES. Keys expressed as \uXXXX
# escapes (Ruff RUF001) so a reader can see the codepoint, not render glyphs.
# ---------------------------------------------------------------------------

_CONFUSABLES = {
    # Cyrillic
    "А": "A", "а": "a",  # U+0410 / U+0430
    "В": "B", "в": "b",
    "С": "C", "с": "c",
    "Е": "E", "е": "e",
    "Н": "H", "н": "h",
    "І": "I", "і": "i",
    "Ј": "J",
    "К": "K", "к": "k",
    "М": "M", "м": "m",
    "О": "O", "о": "o",
    "Р": "P", "р": "p",
    "Ѕ": "S", "ѕ": "s",
    "Т": "T", "т": "t",
    "Х": "X", "х": "x",
    "У": "Y", "у": "y",
    # Greek
    "Α": "A", "α": "a",
    "Ε": "E", "ε": "e",
    "Ο": "O", "ο": "o",
    "Ρ": "P", "ρ": "p",
}

_CONFUSABLES_RE = re.compile("[" + "".join(_CONFUSABLES.keys()) + "]")

# Zero-width + bidi + format characters stripped to empty.
# Expanded per CodeRabbit review to cover bidi overrides / isolates that can
# invisibly reorder text:
#   U+200B-U+200D  ZWS / ZWNJ / ZWJ
#   U+200E-U+200F  LRM / RLM (left/right-to-left marks)
#   U+202A-U+202E  LRE / RLE / PDF / LRO / RLO (bidi embedding + override)
#   U+2060         WORD JOINER
#   U+2066-U+2069  LRI / RLI / FSI / PDI (isolate controls)
#   U+FEFF         BYTE ORDER MARK / ZWNBSP
# F-08 fix: stripped to empty, not mapped to space (space-mapping splits
# "ignore" into "ig nore" and defeats the \\s+ regex).
_ZERO_WIDTH_RE = re.compile(
    "["
    "\\u200B-\\u200F"   # ZWS / ZWNJ / ZWJ / LRM / RLM
    "\\u202A-\\u202E"   # LRE / RLE / PDF / LRO / RLO (bidi override)
    "\\u2060"           # WORD JOINER
    "\\u2066-\\u2069"   # LRI / RLI / FSI / PDI (isolate controls)
    "\\uFEFF"           # BYTE ORDER MARK / ZWNBSP
    "]"
)

# Non-breaking space (U+00A0) → regular space (legitimate word separator).
_NBSP_RE = re.compile(" ")

# Label sanitization — strip bracket/paren/angle-bracket chars that break
# "[source (project)]: content" formatting and XML delimiters.
_LABEL_STRIP_RE = re.compile(r'[\[\]\(\)<>"\n\r]')

# Wrapper delimiter tag name — single source of truth for the neutraliser
# below, so wrap_untrusted() and _WRAP_BREAKOUT_RE cannot drift apart.
_WRAP_TAG = "untrusted-retrieved-memory"

# Delimiter-collision neutraliser (CRITICAL finding, CodeRabbit review of
# PR #3). A stored chunk containing "</untrusted-retrieved-memory>" would
# otherwise prematurely close the wrapper and place attacker-controlled
# text outside the "untrusted" boundary. We neutralise BOTH closing and
# opening occurrences of the tag so the wrapper cannot be prematurely
# closed OR nested-confused by attacker-controlled content.
#   - Closing breakout: `</tag` → `&lt;/tag-escaped`
#   - Opening collision: `<tag ` or `<tag>` → `&lt;tag-escaped`
# `<` becomes `&lt;` so the tag cannot be parsed. A suffix marker is
# appended to make intentional neutralisation visible to human reviewers.
_WRAP_CLOSING_RE = re.compile(
    r"<\s*/\s*" + re.escape(_WRAP_TAG),
    re.IGNORECASE,
)
_WRAP_CLOSING_REPLACEMENT = "&lt;/" + _WRAP_TAG + "-escaped"

_WRAP_OPENING_RE = re.compile(
    r"<\s*" + re.escape(_WRAP_TAG) + r"\b",
    re.IGNORECASE,
)
_WRAP_OPENING_REPLACEMENT = "&lt;" + _WRAP_TAG + "-escaped"

# HTML entity decoder — mirrors hooks/memory-validation.ts decodeHtmlEntities.
# Covers numeric (decimal + hex) and a small named set. Deliberately not
# full HTML decoding — just enough to close cheap entity-encoded bypasses.
_NAMED_ENTITIES = {
    "lt": "<",
    "gt": ">",
    "amp": "&",
    "quot": '"',
    "apos": "'",
    "nbsp": " ",
}
_HTML_ENTITY_RE = re.compile(r"&(?:#(?:([0-9]+)|x([0-9A-Fa-f]+))|([A-Za-z]+));")


def _decode_html_entities(text: str) -> str:
    """Decode numeric + small named HTML entities. Unknown entities pass
    through unchanged so partial / malformed entities don't corrupt content."""

    def _sub(m: re.Match) -> str:
        dec, hex_, named = m.group(1), m.group(2), m.group(3)
        try:
            if dec:
                cp = int(dec, 10)
                if 0 <= cp <= 0x10FFFF:
                    return chr(cp)
            elif hex_:
                cp = int(hex_, 16)
                if 0 <= cp <= 0x10FFFF:
                    return chr(cp)
            elif named:
                lowered = named.lower()
                if lowered in _NAMED_ENTITIES:
                    return _NAMED_ENTITIES[lowered]
        except (ValueError, OverflowError):
            pass
        return m.group(0)

    return _HTML_ENTITY_RE.sub(_sub, text)


def normalise_text(text: str) -> str:
    """Decode entities -> NFKC -> ZWS/bidi strip -> NBSP->space -> confusables.

    ORDER MATTERS (CodeRabbit PR #4 finding): entities decode FIRST so that
    encoded invisibles (e.g. `&#8203;` -> ZWS) and encoded fullwidth chars
    (e.g. `&#xFF59;` -> fullwidth y) get folded by the normalisation layers
    that follow. Decoding after would leave post-strip ZWS or un-normalised
    fullwidth in the output.

    F-08 fix: zero-width chars are stripped to empty string, not replaced with
    space. Space-replacement breaks "ignore" into two tokens and defeats
    /ignore\\s+previous/.
    """
    if not isinstance(text, str):
        return ""
    normalised = _decode_html_entities(text)
    normalised = unicodedata.normalize("NFKC", normalised)
    normalised = _ZERO_WIDTH_RE.sub("", normalised)
    normalised = _NBSP_RE.sub(" ", normalised)
    normalised = _CONFUSABLES_RE.sub(lambda m: _CONFUSABLES[m.group(0)], normalised)
    return normalised


def scan_content(text: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Return (blocked, reason). False/None means content is safe.

    Fail-closed on (1) non-str input, (2) normalise_text() errors.

    Non-str rejection — bytes/int/etc. would otherwise short-circuit through
    normalise_text's `if not isinstance(text, str)` to an empty normalised
    string, returning (False, None) and letting the raw value reach
    wrap_untrusted() where re.sub() crashes on bytes (CodeRabbit R3 finding).

    Normalise exception fail-closed — if an attacker can craft input that
    reliably throws on normalisation, fail-open would hand them a scanner
    bypass. DoS risk is acceptable: the chunk is dropped, the user sees no
    context, the scanner log captures the reason.
    """
    if text is None or text == "":
        return (False, None)
    if not isinstance(text, str):
        return (True, "Non-string retrieval content dropped")
    try:
        normalised = normalise_text(text)
    except Exception:  # noqa: BLE001 — deliberate fail-closed guard
        return (True, "Content normalisation failed — dropped as precaution")

    for pattern, description in _INJECTION_PATTERNS:
        if pattern.search(normalised):
            return (True, description)
    return (False, None)


def sanitize_label(value: Optional[str], max_len: int = 80) -> str:
    """Neutralise attacker-controlled RAG metadata labels.

    Strips brackets, parens, angle brackets, quotes, newlines. Replaces with
    underscore so length is preserved. Caps length at max_len. Empty / None
    returns "unknown" for deterministic output.

    Addresses F-10: lancedb metadata like source_file=']: fake [injected'
    would otherwise break the "[source (project)]: content" label structure.
    """
    if value is None or value == "":
        return "unknown"
    sanitized = _LABEL_STRIP_RE.sub("_", str(value))
    sanitized = sanitized.strip()
    if not sanitized:
        return "unknown"
    if len(sanitized) > max_len:
        sanitized = sanitized[:max_len]
    return sanitized


def _neutralise_wrapper_breakout(content: str) -> str:
    """Rewrite any `</untrusted-retrieved-memory` or
    `<untrusted-retrieved-memory` substring in content so the wrapper
    inserted by wrap_untrusted() cannot be closed prematurely or
    nested-confused by attacker-controlled content.

    Two-stage: close first (most common breakout), then open. Running close
    first avoids the open-pass spuriously matching the `</` in closing
    tags (the regexes are disjoint thanks to `<\\s*/` vs `<\\s*tag\\b`,
    but running close first makes the ordering self-evident).

    This is the second layer of the delimiter-collision defence (the first
    layer is scan_content() dropping chunks that match INJECTION_PATTERNS).
    Even for chunks that pass scan_content, this neutraliser guarantees
    the wrapper cannot be escaped.
    """
    if not content:
        return content
    neutralised = _WRAP_CLOSING_RE.sub(_WRAP_CLOSING_REPLACEMENT, content)
    neutralised = _WRAP_OPENING_RE.sub(_WRAP_OPENING_REPLACEMENT, neutralised)
    return neutralised


def wrap_untrusted(content: str, source: str, project: str = "unknown") -> str:
    """Wrap retrieved content in an XML-like untrusted-content delimiter.

    Replaces the weak "[Mnemosyne Auto-Retrieved]" header with an explicit
    marker so the model treats the content as reference material, not as
    system guidance. Source and project labels are sanitized. Content is
    neutralised against delimiter-collision escapes before wrapping.

    Note: this is advisory-level defence. A sufficiently motivated model-side
    attack can still ignore the delimiter semantically. Pair with
    scan_content() which drops known-bad content before wrapping.
    """
    safe_source = sanitize_label(source)
    safe_project = sanitize_label(project)
    safe_content = _neutralise_wrapper_breakout(content)
    return (
        f'<{_WRAP_TAG} source="{safe_source}" project="{safe_project}">\n'
        f"{safe_content}\n"
        f"</{_WRAP_TAG}>"
    )
