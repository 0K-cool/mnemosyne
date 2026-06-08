---
name: API token batching nudge
description: |
  Soft enforcement of the PR-batching directive. Memory-only versions
  of this rule were bypassed repeatedly; this is the warn-tier hook
  with an escalation policy — if the nudge keeps getting ignored, the
  audit aggregator flags it for promotion to a hard block.
type: feedback
date: 2026-06-07
enforce:
  tool: Bash
  pattern: "gh pr create"
  hook: .claude/hooks/auto/pr-rate.ts
  generated_from: memory/feedback_api_batching.md
  template: block-on-match-guard.ts.template
  mode: warn
  escalation:
    threshold: 3
    window_days: 7
---

# API token batching

Batch related work: 1–2 PRs per session max, grouped by concern. One
branch → one commit-per-concern → one PR → one CI run. Split only when
fixes need independent revert capability.
