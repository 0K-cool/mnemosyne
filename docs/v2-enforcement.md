# Mnemosyne v2 — Memory-Driven Enforcement Layer (design)

> **Status:** v2.0 alpha — Phase 1 scaffolding (schema + generator + first template). Subsequent PRs implement the CLI, action-time injection, and telemetry loop.

## The gap v2 closes

Mnemosyne v1 makes memory *recallable* — agents can find structured rules and prior decisions. But recall ≠ enforcement. An agent that has read the rule `"never run destructive commands without permission"` may still run a destructive command, rationalizing the local context as an exception.

This isn't speculative. Anthropic's own docs ([code.claude.com/docs/en/memory](https://code.claude.com/docs/en/memory)) state explicitly:

> *"CLAUDE.md content is delivered as a user message after the system prompt, not as part of the system prompt itself. Claude reads it and tries to follow it, but **there's no guarantee of strict compliance**. Settings rules are enforced by the client regardless of what Claude decides to do. CLAUDE.md instructions shape Claude's behavior but are **not a hard enforcement layer**."*

Recent empirical work confirms the failure mode is structural, not idiosyncratic:

| Source | Finding |
|---|---|
| LIFBench | ~50% instruction-failure rate at 32k context tokens |
| Anthropic, "Many-Shot Jailbreaking" (2024) | Rule-override probability scales with context length |
| AgentSpec (2024) | Runtime hooks prevent >90% of policy violations vs <40% for prompt-only |
| AgentPRM | Step-level verification raises adherence 73.9% → 85.8% |

Prompt-level rules are not enforcement. Hooks are.

Mnemosyne v2 closes the gap by treating memory entries as *the source of truth for runtime enforcement*: when a memory entry declares an `enforce` block, Mnemosyne can generate a Claude Code hook that intercepts the matching tool boundary.

## How it works

### 1. The `enforce` frontmatter block

Memory entries that should enforce gain an `enforce` block in their YAML frontmatter:

```yaml
---
name: example-rule
type: feedback
description: |
  Rule prose stays here for human readers and recall.
enforce:
  tool: Bash                                             # required
  pattern: "git push -u origin"                          # required, regex
  hook: .claude/hooks/auto/cr-prepush.ts                 # required, must live under .claude/hooks/auto/
  generated_from: memory/feedback_zero_drift.md          # required, attribution
  freshness_secs: 1800                                   # optional, default 1800
  audit_log: .claude/logs/cr-prepush-enforcement.jsonl   # optional, default <hook>.audit.jsonl
  generator_version: 2.0.0                               # optional
  repo_filter: "github\\.com[:/]0K-cool/"                # optional, regex on origin URL
---
```

The schema is validated by `lib/enforce/schema.py`. Invalid blocks raise `EnforceValidationError` with a specific reason — bad rules don't silently produce no-op hooks. Validations include:
- All four required fields present
- `tool` must be a known Claude Code tool name
- `pattern` and `repo_filter` must compile as regexes
- `hook` must live under `.claude/hooks/auto/` (so generated artifacts are always distinguishable from hand-written ones)
- No path traversal in `hook` / `audit_log`
- `freshness_secs` is a positive int

### 2. The generator

`lib/enforce/generator.py` reads a memory entry, validates its `enforce` block, picks a matching template, and substitutes parameters to produce ready-to-execute hook source.

```python
from enforce import generate_hook
from pathlib import Path

source = generate_hook(memory_md_text, template_dir=Path("templates/hooks"))
# Write `source` to the hook path declared in the enforce block.
```

Templates use `{{PARAM}}` (Jinja-style brackets) for substitution rather than `${PARAM}` — TypeScript template literals already use `${...}` heavily, so the alternate delimiter avoids collisions in the generated source.

### 3. The first template — `cr-prepush-guard.ts.template`

Ships with Phase 1. Generates a PreToolUse hook that gates `git push` on private 0K-cool repos behind a fresh CodeRabbit review. The original hand-written hook lives in [PAI PR #45](https://github.com/0K-cool/vex/pull/45); the template is the parameterized form of that hook, ready to be regenerated for any compatible memory entry.

Test fixture proves end-to-end: `tests/fixtures/enforce/cr-prepush-rule.md` generates a hook that compiles cleanly under `bun build`.

## What v2 Phase 1 ships (this PR)

- `lib/enforce/schema.py` — `enforce` block validation
- `lib/enforce/generator.py` — memory entry → hook source
- `templates/hooks/cr-prepush-guard.ts.template` — first hook template
- `tests/fixtures/enforce/cr-prepush-rule.md` — sample memory entry
- `tests/test_enforce_schema.py` — 10 tests (happy path + rejection cases)
- `tests/test_enforce_generator.py` — 8 tests (parsing, template matching, end-to-end + bun syntax verification)
- `docs/v2-enforcement.md` — this document

**18/18 tests pass.** The generator produces a TypeScript hook that bun accepts as syntactically valid.

## Phase 1.2 — `mnemosyne enforce` CLI (shipped)

The CLI walks a memory directory, runs the generator on every entry with an `enforce` block, and writes the resulting hook source to `.claude/hooks/auto/`. Reports orphan hooks (files in the output dir not produced by any memory entry) but never auto-deletes them.

```
PYTHONPATH=lib python -m enforce \
  --memory-dir memory \
  --output-dir .claude/hooks/auto \
  [--template-dir templates/hooks] \
  [--rule memory/specific-rule.md] \
  [--dry-run] [--force] [-v]
```

Behavior contract (locked by `tests/test_enforce_cli.py`):
- Memory entries without `enforce` blocks are silently skipped.
- A failure on one entry does NOT halt the run — other entries still process; CLI exits non-zero overall.
- Idempotent: re-running with no input change does not rewrite the hook (modulo the `Generated at:` timestamp). `--force` overrides.
- `--dry-run` prints the plan without writing anything.
- `--rule <path>` processes one entry only (skips orphan reporting).
- Generated hooks are `chmod 0o755` so Claude Code can spawn them.

The `PYTHONPATH=lib` prefix is needed until the pyproject.toml restructure lands (issue #10).

## What's still TODO (subsequent PRs)
- **Phase 2 — action-time rule re-injection**: a PostToolUse-side companion that, before high-stakes tool calls, re-injects the rule text into context as fresh content. Addresses the "I read the rule 5 hours ago and forgot" failure mode by removing the temporal gap between recall and decision.
- **Phase 3 — violation telemetry → reinforcement loop**: append every hook firing (allow / block / skip-override) to a JSONL audit log. After N violations of the same rule, suggest escalation: auto-generate a tool hook, move to system prompt, escalate to CLAUDE.md.
- **Phase 4 — pattern library**: 5-10 common rule shapes (destructive command, credential leak, force push, …) each with a dedicated template + a TEMPLATE_PATTERNS entry in the generator.
- **Phase 5 — multi-language hook gen**: Python and shell hook generators for environments without bun.

## Why opt-in / why now

Mnemosyne v2 is opt-in: memory entries without an `enforce` block behave exactly as v1 — recall-only, no enforcement. Operators add `enforce` blocks deliberately. This preserves backward compatibility and lets users adopt enforcement one rule at a time.

Phase 1 ships now because it sets up the contract. The rest of v2 builds on this foundation. Without the schema and generator, none of the downstream phases work.

## Risk register

| Risk | Mitigation |
|---|---|
| Generator emits unsafe code | Templates are static, parameterized. Generator writes only to `.claude/hooks/auto/`. CR + linting on every generated hook. |
| Schema drift between v1 and v2 memory entries | `enforce` block is additive — v1 entries continue to work unchanged. |
| Template / memory entry drift | Generated hook header includes `generated_from` path; orphan detection in the upcoming `mnemosyne audit` command (Phase 3). |
| False-positive blocks waste operator time | Per-rule `freshness_secs`; documented `VEX_SKIP_*` env override with audit logging. |

## References

- PAI working prototype: https://github.com/0K-cool/vex/pull/45
- Anthropic memory docs: https://code.claude.com/docs/en/memory
- Anthropic hooks docs: https://code.claude.com/docs/en/hooks
- Cursor / PocketOS database deletion incident, April 26 2026: https://www.theregister.com/2026/04/27/cursoropus_agent_snuffs_out_pocketos/
