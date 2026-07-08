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
 * Output (Claude Code PreToolUse contract — top-level `decision` is NOT honored
 * for PreToolUse and fails schema validation, causing the harness to fail open):
 *   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}
 *   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
 *     "permissionDecisionReason":"..."}}  + exit code 2
 *
 * Fail-open: any parse error or unexpected exception returns allow.
 *
 * Security mapping:
 *   OWASP Agentic 2026 ASI06 (Memory and Context Manipulation)
 *   MITRE ATLAS AML.T0064 (Data Poisoning)
 */

import { writeSync } from "node:fs";

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

// Claude Code PreToolUse hook output contract. The verdict MUST be emitted in
// this envelope — a top-level {"decision":...} fails PreToolUse schema
// validation, which the harness treats as a non-blocking hook failure (fails
// open: the tool call proceeds even on a block verdict).
export interface PreToolUseOutput {
  hookSpecificOutput: {
    hookEventName: "PreToolUse";
    permissionDecision: "allow" | "deny" | "ask";
    permissionDecisionReason?: string;
  };
}

/** Translate the internal Decision into the PreToolUse output envelope. */
export function toPreToolUseOutput(d: Decision): PreToolUseOutput {
  if (d.decision === "block") {
    return {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: d.reason,
      },
    };
  }
  return {
    hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow" },
  };
}

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

const MAX_ENTITY_DECODE_PASSES = 3;

/** Bounded multi-pass entity decode — collapses double-encoding like
 * `&amp;#105;` -> `&#105;` -> `i`. Stops early on no-op pass. */
export function decodeHtmlEntities(text: string): string {
  const ENTITY_RE = /&(?:#(?:([0-9]+)|[xX]([0-9A-Fa-f]+))|([A-Za-z]+));/g;
  const replacer = (
    match: string,
    dec?: string,
    hex?: string,
    named?: string,
  ): string => {
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
  };
  let current = text;
  for (let i = 0; i < MAX_ENTITY_DECODE_PASSES; i++) {
    ENTITY_RE.lastIndex = 0;
    const decoded = current.replace(ENTITY_RE, replacer);
    if (decoded === current) break;
    current = decoded;
  }
  return current;
}

/** Normalise Unicode to NFKC, strip zero-width/bidi chars, decode HTML
 * entities, and map confusables. */
export function normaliseText(text: string): string {
  // ORDER MATTERS (two CodeRabbit PR #4 findings):
  //   (a) Decode entities BEFORE ZWS strip + confusables so that
  //       `&#8203;` -> ZWS gets stripped, `&#xFF59;` -> fullwidth -> y.
  //   (b) NFKC-fold BEFORE entity decode so that fullwidth `＆#105;`
  //       (U+FF06 disguised ampersand) collapses to ASCII `&#105;` and
  //       the entity regex can then match it.
  // Final sequence: NFKC -> decode -> NFKC -> ZWS -> NBSP -> confusables.
  let normalised = text.normalize("NFKC");
  normalised = decodeHtmlEntities(normalised);
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
  // Normalize Windows backslash separators FIRST. The tool payload's file_path
  // uses OS-native separators, so a bare "/memory/" match silently misses on
  // native Windows (C:\...\memory\evil.md) — the L3 anti-poisoning scan would
  // never run and the write would be allowed. (Security fix, v2.3.2.)
  const p = filePath.replace(/\\/g, "/").toLowerCase();
  // Prefer matching against the configured store — covers memory dirs not
  // literally named "memory/" (the retriever supports arbitrary dirs).
  const memDir = (process.env.MNEMOSYNE_MEMORY_DIR ?? "")
    .replace(/\\/g, "/")
    .toLowerCase()
    .replace(/\/+$/, "");
  if (memDir && (p === memDir || p.startsWith(memDir + "/"))) return true;
  return p.includes("/memory/") || p.endsWith("/memory.md") || p === "memory.md";
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

/**
 * Synchronous, drain-safe write to a file descriptor (1=stdout, 2=stderr).
 * console.log/console.error are async and can truncate on a piped fd when
 * followed immediately by process.exit — Bun does not guarantee a flush before
 * exit. writeSync blocks until the bytes are written, looping on partial writes.
 */
function writeAllSync(fd: number, text: string): void {
  const buf = Buffer.from(text, "utf-8");
  let off = 0;
  while (off < buf.length) {
    off += writeSync(fd, buf, off, buf.length - off);
  }
}

/** Emit an allow verdict in the PreToolUse envelope (exit 0). */
function emitAllow(): void {
  writeAllSync(1, JSON.stringify(toPreToolUseOutput({ decision: "allow" })) + "\n");
}

/**
 * Emit a verdict. On block: writes the deny envelope to stdout AND the reason
 * to stderr, then exits 2 — covers both harness interpretations (structured
 * permissionDecision:deny and the exit-code-2 block path). Uses drain-safe
 * synchronous writes so process.exit(2) cannot truncate the deny envelope.
 */
function emitDecision(d: Decision): void {
  writeAllSync(1, JSON.stringify(toPreToolUseOutput(d)) + "\n");
  if (d.decision === "block") {
    writeAllSync(2, `Mnemosyne blocked a memory write: ${d.reason}\n`);
    process.exit(2);
  }
}

export async function runHook(): Promise<void> {
  let raw = "";

  try {
    raw = await Bun.stdin.text();
  } catch {
    // Stdin read failure — fail-open
    emitAllow();
    return;
  }

  if (!raw.trim()) {
    emitAllow();
    return;
  }

  let data: HookInput;
  try {
    data = JSON.parse(raw) as HookInput;
  } catch {
    // Parse error — fail-open, never block the user
    emitAllow();
    return;
  }

  const toolName = data.tool_name ?? "";

  // Only gate Write/Edit tools
  if (!WRITE_TOOLS.has(toolName)) {
    emitAllow();
    return;
  }

  const input = data.tool_input ?? {};
  const filePath = extractFilePath(toolName, input);

  // Only check memory files
  if (!isMemoryFile(filePath)) {
    emitAllow();
    return;
  }

  const content = extractContent(toolName, input);
  if (!content) {
    // No content to check
    emitAllow();
    return;
  }

  try {
    emitDecision(validateMemoryWrite(filePath, content));
  } catch {
    // Unexpected failure — fail-open
    emitAllow();
  }
}

// This module holds the hook logic and is imported by the entrypoint
// (memory-validation.ts) and by the test suite. It never runs itself — the
// entrypoint calls runHook() unconditionally, which is the only reliable
// cross-platform way to invoke a Bun hook (import.meta.main is unreliable on
// Windows).
