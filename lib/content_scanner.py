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
# Port of hooks/memory-validation.ts CONFUSABLES
# ---------------------------------------------------------------------------

_CONFUSABLES = {
    # Cyrillic
    "А": "A", "а": "a",
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

# Zero-width characters stripped to empty (F-08 fix vs TS version that maps to space)
_ZERO_WIDTH_RE = re.compile(r"[​-‍﻿⁠]")

# Non-breaking space → regular space (legitimate word separator)
_NBSP_RE = re.compile(r" ")

# Label sanitization — strip bracket/paren/angle-bracket chars that break
# "[source (project)]: content" formatting and XML delimiters.
_LABEL_STRIP_RE = re.compile(r'[\[\]\(\)<>"\n\r]')


def normalise_text(text: str) -> str:
    """NFKC → ZWS strip → NBSP→space → confusables map.

    F-08 fix: zero-width chars are stripped to empty string, not replaced with
    space. The TS version's space-replacement breaks the word into two tokens
    (`ig nore`) which then fails to match `/ignore\\s+previous/`.
    """
    if not isinstance(text, str):
        return ""
    normalised = unicodedata.normalize("NFKC", text)
    normalised = _ZERO_WIDTH_RE.sub("", normalised)
    normalised = _NBSP_RE.sub(" ", normalised)
    normalised = _CONFUSABLES_RE.sub(lambda m: _CONFUSABLES[m.group(0)], normalised)
    return normalised


def scan_content(text: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Return (blocked, reason). False/None means content is safe."""
    if not text:
        return (False, None)
    try:
        normalised = normalise_text(text)
    except Exception:
        return (False, None)

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


def wrap_untrusted(content: str, source: str, project: str = "unknown") -> str:
    """Wrap retrieved content in an XML-like untrusted-content delimiter.

    Replaces the weak "[Mnemosyne Auto-Retrieved]" header with an explicit
    marker so the model treats the content as reference material, not as
    system guidance. Source and project labels are sanitized.

    Note: this is advisory-level defense. A sufficiently motivated model-side
    attack can still ignore the delimiter. Pair with scan_content() which
    drops known-bad content before wrapping.
    """
    safe_source = sanitize_label(source)
    safe_project = sanitize_label(project)
    return (
        f'<untrusted-retrieved-memory source="{safe_source}" project="{safe_project}">\n'
        f"{content}\n"
        f"</untrusted-retrieved-memory>"
    )
