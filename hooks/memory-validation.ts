#!/usr/bin/env bun

/**
 * memory-validation.ts — PreToolUse hook for ok-mnemosyne.
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

interface HookInput {
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  session_id?: string;
  [key: string]: unknown;
}

interface AllowDecision {
  decision: "allow";
}

interface BlockDecision {
  decision: "block";
  reason: string;
}

type Decision = AllowDecision | BlockDecision;

interface InjectionPattern {
  pattern: RegExp;
  description: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_FILE_SIZE_BYTES = 50 * 1024; // 50 KB

// Tools that write file content
const WRITE_TOOLS = new Set(["Write", "Edit", "MultiEdit"]);

// ---------------------------------------------------------------------------
// Injection pattern definitions
// ---------------------------------------------------------------------------

const INJECTION_PATTERNS: InjectionPattern[] = [
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
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Normalise Unicode to NFKC and strip zero-width characters for pattern matching. */
function normaliseText(text: string): string {
  let normalised = text.normalize("NFKC");
  // Strip zero-width and invisible characters
  normalised = normalised.replace(/[\u200b-\u200d\ufeff\u00a0]/g, " ");
  return normalised;
}

/** Return true if the file path targets a memory file. */
function isMemoryFile(filePath: string): boolean {
  if (!filePath) return false;
  // Matches /memory/ anywhere in path, or filename is MEMORY.md
  return filePath.includes("/memory/") || filePath.endsWith("MEMORY.md");
}

/** Extract the file path from tool_input regardless of which write tool is used. */
function extractFilePath(toolName: string, input: Record<string, unknown>): string {
  return (input.file_path as string) || "";
}

/** Extract the content to be written from tool_input. */
function extractContent(toolName: string, input: Record<string, unknown>): string {
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
// Core validation
// ---------------------------------------------------------------------------

function validateMemoryWrite(
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
    // Reset stateful regex
    pattern.lastIndex = 0;
    if (pattern.test(normalised)) {
      return {
        decision: "block",
        reason: `Memory poisoning pattern detected in write to '${filePath}': ${description}`,
      };
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

main();
