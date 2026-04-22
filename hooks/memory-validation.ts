#!/usr/bin/env bun

/**
 * memory-validation.ts — PreToolUse hook for Mnemosyne.
 *
 * Blocks memory poisoning attempts targeting Write/Edit tool calls that write
 * to memory files (paths containing "/memory/" or ending with "MEMORY.md").
 *
 * Checks:
 *   - Injection pattern detection (case-insensitive, Unicode-normalised)
 *   - File size cap: 50 KB
 *
 * Output:
 *   {"decision": "allow"}                        — pass through
 *   {"decision": "block", "reason": "..."}       — block the write
 *
 * Fail-open: any parse error or unexpected exception returns allow.
 *
 * Security mapping:
 *   OWASP Agentic 2026 ASI06 (Memory and Context Manipulation)
 *   MITRE ATLAS AML.T0064 (Data Poisoning)
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HookInput {
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  session_id?: string;
  [key: string]: unknown;
}

export interface AllowDecision {
  decision: "allow";
}

export interface BlockDecision {
  decision: "block";
  reason: string;
}

export type Decision = AllowDecision | BlockDecision;

interface InjectionPattern {
  pattern: RegExp;
  description: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const MAX_FILE_SIZE_BYTES = 50 * 1024; // 50 KB

// Tools that write file content
const WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit"]);

// ---------------------------------------------------------------------------
// Injection pattern definitions
// ---------------------------------------------------------------------------

export const INJECTION_PATTERNS: InjectionPattern[] = [
  {
    pattern: /ignore\s+(?:all\s+)?previous\s+instructions?/i,
    description: "Prompt injection: ignore previous instructions",
  },
  {
    pattern: /you\s+are\s+now\b/i,
    description: "Identity override: 'you are now'",
  },
  {
    pattern: /\bsystem\s*:/i,
    description: "Fake system prompt marker: 'system:'",
  },
  {
    pattern: /<\s*system\s*>/i,
    description: "XML system tag injection: <system>",
  },
  {
    pattern: /<\/\s*system\s*>/i,
    description: "XML system closing tag injection: </system>",
  },
  {
    pattern: /do\s+not\s+follow\s+(?:the\s+)?rules?/i,
    description: "Rule override: 'do not follow rules'",
  },
  {
    pattern: /override\s+(?:all\s+)?polic(?:y|ies)/i,
    description: "Policy override attempt",
  },
  {
    pattern: /act\s+as\s+(?:an?\s+)?admin(?:istrator)?/i,
    description: "Privilege escalation: 'act as admin'",
  },
  {
    pattern: /forget\s+(?:all\s+)?previous(?:\s+context)?/i,
    description: "Context wipe: 'forget previous'",
  },
  // --- 0din threat model patterns (authorization claim + semantic injection) ---
  {
    pattern: /\bauthorized\s*:\s*.{0,30}(?:access|grant|approv|admin|elevat)/i,
    description: "Fake authorization claim: 'AUTHORIZED: ... access/granted'",
  },
  {
    pattern: /(?:admin|elevated|root|unrestricted)\s+(?:access|privileges?|permissions?|mode)\s+(?:grant|confirm|approv|enabl)/i,
    description: "Privilege escalation: fake access grant",
  },
  {
    pattern: /(?:security\s+clearance|approval_policy)\s*:\s*/i,
    description: "Fake security clearance or policy override marker",
  },
  {
    pattern: /operate\s+without\s+(?:any\s+)?(?:restrict|limit|constraint|boundar)/i,
    description: "Semantic injection: 'operate without restrictions'",
  },
  {
    pattern: /(?:safety|security)\s+concerns?\s+(?:have\s+been|were)\s+(?:resolv|address|clear|remov)/i,
    description: "Semantic injection: fake safety resolution claim",
  },
  {
    pattern: /(?:user|owner|operator)\s+has\s+(?:explicitly\s+)?(?:consent|authoriz|approv|grant)/i,
    description: "Fake consent claim: 'user has consented'",
  },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Cyrillic → Latin confusables map.
 * Covers the most abused homoglyphs used to bypass regex pattern matching.
 * Source: Unicode confusables.txt (focused subset for Latin↔Cyrillic).
 */
const CONFUSABLES: Record<string, string> = {
  "\u0410": "A", "\u0430": "a", // А/а → A/a
  "\u0412": "B", "\u0432": "b", // В/в → B/b  (visual, not phonetic)
  "\u0421": "C", "\u0441": "c", // С/с → C/c
  "\u0415": "E", "\u0435": "e", // Е/е → E/e
  "\u041d": "H", "\u043d": "h", // Н/н → H/h
  "\u0406": "I", "\u0456": "i", // І/і → I/i  (Ukrainian)
  "\u0408": "J",                 // Ј → J      (Serbian)
  "\u041a": "K", "\u043a": "k", // К/к → K/k
  "\u041c": "M", "\u043c": "m", // М/м → M/m  (visual)
  "\u041e": "O", "\u043e": "o", // О/о → O/o
  "\u0420": "P", "\u0440": "p", // Р/р → P/p
  "\u0405": "S", "\u0455": "s", // Ѕ/ѕ → S/s  (Macedonian)
  "\u0422": "T", "\u0442": "t", // Т/т → T/t
  "\u0425": "X", "\u0445": "x", // Х/х → X/x
  "\u0423": "Y", "\u0443": "y", // У/у → Y/y  (visual)
  // Greek homoglyphs (bonus — commonly mixed with Cyrillic attacks)
  "\u0391": "A", "\u03B1": "a", // Α/α → A/a
  "\u0395": "E", "\u03B5": "e", // Ε/ε → E/e
  "\u039F": "O", "\u03BF": "o", // Ο/ο → O/o
  "\u03A1": "P", "\u03C1": "p", // Ρ/ρ → P/p
};

/** Build a single regex that matches any confusable character. */
const CONFUSABLES_RE = new RegExp(
  "[" + Object.keys(CONFUSABLES).join("") + "]",
  "g"
);

/**
 * Zero-width / bidi / format characters. v1.1.0 MED-1 (F-08) — stripped to
 * empty, NOT replaced with a space. The prior behaviour replaced these with
 * " " which broke /ignore\s+previous/ matching when an attacker inserted a
 * ZWS between letters (ZWS-split "ignore" passed the regex).
 *
 * Expanded to match the Python scanner (lib/content_scanner.py):
 *   U+200B-U+200D  ZWS / ZWNJ / ZWJ
 *   U+200E-U+200F  LRM / RLM
 *   U+202A-U+202E  LRE / RLE / PDF / LRO / RLO (bidi override)
 *   U+2060         WORD JOINER
 *   U+2066-U+2069  LRI / RLI / FSI / PDI (isolate controls)
 *   U+FEFF         BYTE ORDER MARK / ZWNBSP
 */
const ZERO_WIDTH_RE = new RegExp(
  "[" +
    "\\u200B-\\u200F" +
    "\\u202A-\\u202E" +
    "\\u2060" +
    "\\u2066-\\u2069" +
    "\\uFEFF" +
    "]",
  "g",
);

/** Non-breaking space (U+00A0) — legitimate word separator, mapped to space. */
const NBSP_RE = / /g;

/**
 * HTML entity decoder — v1.1.0 MED-2 (F-09). Numeric (dec + hex) + small
 * named set. Closes the &#105;gnore-previous-instructions bypass.
 * Deliberately NOT full HTML decoding; just enough to defeat cheap
 * escape-encoded payloads. Unknown entities pass through unchanged.
 */
const NAMED_ENTITIES: Record<string, string> = {
  "lt": "<",
  "gt": ">",
  "amp": "&",
  "quot": "\"",
  "apos": "'",
  "nbsp": " ",
};

export function decodeHtmlEntities(text: string): string {
  return text.replace(
    /&(?:#(?:([0-9]+)|[xX]([0-9A-Fa-f]+))|([A-Za-z]+));/g,
    (match: string, dec?: string, hex?: string, named?: string) => {
      try {
        if (dec) {
          const cp = parseInt(dec, 10);
          if (Number.isFinite(cp) && cp >= 0 && cp <= 0x10FFFF) {
            return String.fromCodePoint(cp);
          }
        }
        if (hex) {
          const cp = parseInt(hex, 16);
          if (Number.isFinite(cp) && cp >= 0 && cp <= 0x10FFFF) {
            return String.fromCodePoint(cp);
          }
        }
        if (named && NAMED_ENTITIES[named.toLowerCase()] !== undefined) {
          return NAMED_ENTITIES[named.toLowerCase()];
        }
      } catch {
        // Fall through to original match
      }
      return match;
    },
  );
}

/** Normalise Unicode to NFKC, strip zero-width/bidi chars, decode HTML
 * entities, and map confusables. */
export function normaliseText(text: string): string {
  // ORDER MATTERS (CodeRabbit PR #4 critical finding):
  // Decode entities FIRST so encoded invisibles (`&#8203;` = ZWS) and
  // encoded fullwidth chars (`&#xFF59;` = ｙ) get folded by the
  // normalisation layers that follow. Decoding after would leave a
  // post-strip ZWS or unnormalised fullwidth in the output.
  let normalised = decodeHtmlEntities(text);
  normalised = normalised.normalize("NFKC");
  // Strip zero-width and bidi/format characters (to empty — F-08 fix)
  normalised = normalised.replace(ZERO_WIDTH_RE, "");
  // Non-breaking space -> regular space (legitimate word separator)
  normalised = normalised.replace(NBSP_RE, " ");
  // Map Cyrillic/Greek homoglyphs to Latin equivalents
  normalised = normalised.replace(CONFUSABLES_RE, (ch) => CONFUSABLES[ch] ?? ch);
  return normalised;
}

/** Return true if the file path targets a memory file. */
export function isMemoryFile(filePath: string): boolean {
  if (!filePath) return false;
  // Matches /memory/ anywhere in path, or filename is MEMORY.md
  return filePath.includes("/memory/") || filePath.endsWith("MEMORY.md");
}

/** Extract the file path from tool_input regardless of which write tool is used. */
function extractFilePath(toolName: string, input: Record<string, unknown>): string {
  return (input.file_path as string) || "";
}

/** Extract the content to be written from tool_input. */
export function extractContent(toolName: string, input: Record<string, unknown>): string {
  // Write tool uses "content"
  const content = input.content;
  if (typeof content === "string") return content;

  // Edit tool uses "new_string"
  const newString = input.new_string;
  if (typeof newString === "string") return newString;

  // MultiEdit: array of edits, each with new_string
  const edits = input.edits;
  if (Array.isArray(edits)) {
    return edits
      .map((e: unknown) => {
        if (typeof e === "object" && e !== null) {
          const edit = e as Record<string, unknown>;
          return typeof edit.new_string === "string" ? edit.new_string : "";
        }
        return "";
      })
      .join("\n");
  }

  return "";
}

// ---------------------------------------------------------------------------
// Encoding decode helpers
// ---------------------------------------------------------------------------

/** URL-decode a string (percent-encoded sequences → characters). */
export function urlDecode(text: string): string {
  try {
    return decodeURIComponent(text);
  } catch {
    // Malformed percent sequences — return original
    return text;
  }
}

/** Minimum length for a base64 chunk to be worth decoding. */
const MIN_BASE64_LENGTH = 20;

/**
 * Detect base64-encoded chunks, decode them, and return decoded text.
 * Only returns chunks that decode to valid UTF-8 text (not binary).
 */
export function decodeBase64Chunks(text: string): string {
  const b64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;
  const decoded: string[] = [];

  for (const match of text.matchAll(b64Pattern)) {
    const chunk = match[0];
    if (chunk.length < MIN_BASE64_LENGTH) continue;
    try {
      const bytes = Uint8Array.from(atob(chunk), (c) => c.charCodeAt(0));
      const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      // Only keep chunks that look like text (not binary noise)
      if (/^[\x20-\x7e\t\n\r]+$/.test(text)) {
        decoded.push(text);
      }
    } catch {
      // Not valid base64 or not valid UTF-8 — skip
    }
  }

  return decoded.join(" ");
}

// ---------------------------------------------------------------------------
// Core validation
// ---------------------------------------------------------------------------

export function validateMemoryWrite(
  filePath: string,
  content: string
): Decision {
  // File size check
  const sizeBytes = new TextEncoder().encode(content).length;
  if (sizeBytes > MAX_FILE_SIZE_BYTES) {
    return {
      decision: "block",
      reason: `Memory file write exceeds 50 KB size limit (${Math.round(sizeBytes / 1024)} KB). Possible data stuffing attack.`,
    };
  }

  // Pattern scan on normalised content
  const normalised = normaliseText(content);
  for (const { pattern, description } of INJECTION_PATTERNS) {
    pattern.lastIndex = 0;
    if (pattern.test(normalised)) {
      return {
        decision: "block",
        reason: `Memory poisoning pattern detected in write to '${filePath}': ${description}`,
      };
    }
  }

  // Scan URL-decoded content (catches %20-style obfuscation)
  const urlDecoded = normaliseText(urlDecode(content));
  if (urlDecoded !== normalised) {
    for (const { pattern, description } of INJECTION_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(urlDecoded)) {
        return {
          decision: "block",
          reason: `Memory poisoning pattern detected in URL-encoded content in '${filePath}': ${description}`,
        };
      }
    }
  }

  // Scan base64-decoded chunks (catches encoded payloads)
  const b64Decoded = decodeBase64Chunks(content);
  if (b64Decoded) {
    const b64Normalised = normaliseText(b64Decoded);
    for (const { pattern, description } of INJECTION_PATTERNS) {
      pattern.lastIndex = 0;
      if (pattern.test(b64Normalised)) {
        return {
          decision: "block",
          reason: `Memory poisoning pattern detected in base64-encoded content in '${filePath}': ${description}`,
        };
      }
    }
  }

  return { decision: "allow" };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  let raw = "";

  try {
    raw = await Bun.stdin.text();
  } catch {
    // Stdin read failure — fail-open
    console.log(JSON.stringify({ decision: "allow" }));
    return;
  }

  if (!raw.trim()) {
    console.log(JSON.stringify({ decision: "allow" }));
    return;
  }

  let data: HookInput;
  try {
    data = JSON.parse(raw) as HookInput;
  } catch {
    // Parse error — fail-open, never block the user
    console.log(JSON.stringify({ decision: "allow" }));
    return;
  }

  const toolName = data.tool_name ?? "";

  // Only gate Write/Edit tools
  if (!WRITE_TOOLS.has(toolName)) {
    console.log(JSON.stringify({ decision: "allow" }));
    return;
  }

  const input = data.tool_input ?? {};
  const filePath = extractFilePath(toolName, input);

  // Only check memory files
  if (!isMemoryFile(filePath)) {
    console.log(JSON.stringify({ decision: "allow" }));
    return;
  }

  const content = extractContent(toolName, input);
  if (!content) {
    // No content to check
    console.log(JSON.stringify({ decision: "allow" }));
    return;
  }

  try {
    const decision = validateMemoryWrite(filePath, content);
    console.log(JSON.stringify(decision));
  } catch {
    // Unexpected failure — fail-open
    console.log(JSON.stringify({ decision: "allow" }));
  }
}

if (import.meta.main) {
  main();
}
