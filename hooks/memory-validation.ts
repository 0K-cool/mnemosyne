#!/usr/bin/env bun
/**
 * memory-validation.ts — PreToolUse hook entrypoint for Mnemosyne.
 *
 * Thin entrypoint: it unconditionally runs the hook. All logic (and the
 * exports the test suite imports) lives in memory-validation-core.ts.
 *
 * Why unconditional: it is the only reliable cross-platform way to invoke a
 * Bun hook. Entrypoint auto-detection (import.meta.main, or comparing the
 * script path) is unreliable on Windows/Bun and would leave the hook
 * producing no output. This file is never imported, so running on load is
 * safe.
 */
import { runHook } from "./memory-validation-core";

// Top-level await is required: an un-awaited async call lets Bun exit (code
// 0) before runHook finishes reading stdin and writing its decision on
// Windows, producing empty output. Awaiting keeps the process alive until the
// hook has emitted its result.
await runHook();
