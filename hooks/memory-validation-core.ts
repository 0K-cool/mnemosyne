#!/usr/bin/env bun

/**
 * memory-validation-core.ts — Bun/Claude-Code harness over the pure scanner.
 *
 * The scanning logic (patterns, normalisation, validateMemoryWrite, memory-file
 * detection) lives in ./memory-scanner-core.ts — the pure, vendorable canonical.
 * This file is the Mnemosyne-specific harness: it reads the PreToolUse stdin,
 * runs the scanner, and emits the verdict in Claude Code's PreToolUse output
 * contract (hookSpecificOutput.permissionDecision — a top-level {"decision":...}
 * fails PreToolUse schema validation and the harness fails open).
 *
 * All scanner symbols are re-exported so existing imports/tests keep working.
 *
 * Fail-open: any parse error or unexpected exception returns allow.
 *
 * Security mapping:
 *   OWASP Agentic 2026 ASI06 (Memory and Context Manipulation)
 *   MITRE ATLAS AML.T0064 (Data Poisoning)
 */

import { writeSync } from "node:fs";
import {
  type Decision,
  type HookInput,
  WRITE_TOOLS,
  extractFilePath,
  extractContent,
  isMemoryFile,
  validateMemoryWrite,
} from "./memory-scanner-core";

// Re-export the pure scanner surface so existing consumers/tests that import
// from this module continue to work unchanged.
export * from "./memory-scanner-core";

// ---------------------------------------------------------------------------
// PreToolUse output contract (Mnemosyne harness — not part of the shared core)
// ---------------------------------------------------------------------------

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

  // Only check memory files. The configured store dir is resolved HERE (harness)
  // and passed into the pure core, which never reads process.env itself.
  if (!isMemoryFile(filePath, process.env.MNEMOSYNE_MEMORY_DIR ?? "")) {
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
