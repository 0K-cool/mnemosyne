---
name: zero-drift CR pre-push enforcement
description: |
  On private 0K-cool repos, run `coderabbit review --plain --base main`
  before `git push -u origin <branch>`. Memory-only enforcement of this
  rule failed twice in one session (PRs #40 and #44 of vex on 2026-04-29);
  this enforce block converts it to a runtime hook.
type: feedback
date: 2026-04-29
enforce:
  tool: Bash
  pattern: "git push -u origin"
  hook: .claude/hooks/auto/cr-prepush.ts
  generated_from: memory/feedback_zero_drift_cr_prepush.md
  freshness_secs: 1800
  audit_log: .claude/logs/cr-prepush-enforcement.jsonl
  generator_version: 2.0.0
  repo_filter: "github\\.com[:/]0K-cool/"
---

# zero-drift: CR pre-push enforcement

This memory entry is the canonical source for the CR pre-push rule.
Mnemosyne v2 reads the `enforce` block above and generates the hook
at `.claude/hooks/auto/cr-prepush.ts`. Edit the rule here; regenerate
the hook with `mnemosyne enforce`. Never edit the generated hook by
hand — it is overwritten on regeneration.

## Why this rule exists

Recurring failure: agents read the rule from memory, then rationalize
past it at execution time. Anthropic's docs explicitly state CLAUDE.md
and memory files are advisory, not enforcement. This hook closes that
gap for one rule.
