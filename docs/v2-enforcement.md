# Mnemosyne v2 — Memory-Driven Enforcement Layer (design)

> **Status:** v2.0 alpha — Phases 1, 1.2, 2, 3, 4, and 4.1 shipped. Phases 4.2 (credential-leak-guard) and 5 (multi-language hook generators) still queued.

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

```bash
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

## Phase 2 — action-time rule re-injection (shipped)

Before high-stakes tool calls match the rule's pattern, the generated hook can re-inject the rule's text into the agent's context as fresh content. Closes the temporal gap between when the rule was first read and when the action is being decided.

The `enforce` block gains three optional fields:

```yaml
enforce:
  ... existing fields ...
  inject_on_match: true              # default false; emit additionalContext on match
  inject_text: |                     # optional override; falls back to memory body
    Reminder text shown at action time.
  inject_token_budget: 256           # default 256, max 1024 — caps re-injection size
```

When `inject_on_match: true`, the generated hook calls `console.log(JSON.stringify({ additionalContext: <text> }))` immediately after the pattern match, before any allow/block decision. Claude Code consumes the JSON and surfaces the text to the agent's next response. The text is capped at `inject_token_budget * 4` characters (rough byte-to-token estimate); excess is truncated with an ellipsis marker.

Why this matters: the recurring failure mode is "agent read the rule 5 hours ago and forgot." Re-injection at action time eliminates that gap. Even when the hook decides to allow (cache fresh, conditions satisfied), the agent gets a fresh reminder of why the rule exists.

## Phase 3 — violation telemetry / reinforcement loop (shipped)

Generated hooks already write JSONL audit entries (allow / block / skip-override) to `.claude/logs/<rule>.audit.jsonl`. Phase 3 adds the **aggregation + reporting layer** that turns those entries into a measurable feedback signal.

```bash
PYTHONPATH=lib python -m enforce.audit \
  [--logs-dir DIR]      # default: .claude/logs
  [--threshold N]       # flag rules with blocks >= N as escalation candidates
  [--json]              # machine-readable output
  [-v]                  # verbose
```

Default human-readable output:
```text
rule             blocks  allows  skips  total  first_seen            last_seen
---------------  ------  ------  -----  -----  --------------------  --------------------
cr-prepush       2       1       1      4      2026-04-29T18:30:00Z  2026-04-29T18:35:00Z
destructive-cmd  1       0       0      1      2026-04-29T19:00:00Z  2026-04-29T19:00:00Z
```

With `--threshold 2`:
```text
⚠️  1 rule(s) crossed threshold 2 (escalation candidates):
  - cr-prepush
Consider escalating to system prompt (--append-system-prompt) or CLAUDE.md,
or auto-generating an additional tool hook.
```

The escalation suggestion is informational — Phase 3 reports; the operator decides what to do (escalate to CLAUDE.md? add an `--append-system-prompt` invocation? auto-generate another hook?). Future phases may automate the recommended action.

## Phase 4 — pattern library start (shipped: block-on-match primitive)

Phase 4 starts the pattern library — a small collection of hook templates beyond the original `cr-prepush-guard.ts.template`. The first new shape is a generic block-on-match primitive plus an explicit-template-selection schema field so operators can opt into specific templates without relying on auto-dispatch.

### New schema field

```yaml
enforce:
  ... existing fields ...
  template: block-on-match-guard.ts.template   # optional; basename only, from templates/hooks/
```

When `template` is set, the generator uses that template directly. When omitted, the existing `TEMPLATE_PATTERNS` substring dispatch decides (today: `git push` → cr-prepush-guard).

Rejection cases:
- empty / non-string → `EnforceValidationError`
- absolute path / traversal / subdirectory → `EnforceValidationError`
- valid basename but file missing → `GenerationError` at generation time (loud failure)

### New template — `block-on-match-guard.ts.template`

A minimal block-on-match primitive: pattern matches → block. No cache, no diff check, no allow path. Suitable for "always block" rules (rm -rf, force push to main, destructive SQL, etc.). About half the size of the cr-prepush template — fits the simpler use case cleanly.

Like cr-prepush, supports `{{INJECT_BLOCK}}`/`{{INJECT_CALL}}` so Phase 2's `inject_on_match` works on this template too.

Subsequent Phase 4.x PRs add tool-specific templates (force-push branch parser, Edit/Write content scanning for credentials, etc.) — each is non-trivial enough to warrant its own focused PR.

## Phase 4.1 — force-push-guard (shipped)

The first tool-aware template in the pattern library. Where the
block-on-match primitive treats the command as an opaque string,
force-push-guard tokenises `git push` arguments and resolves the
target branch — either from an explicit refspec or by shelling out
to `git rev-parse --abbrev-ref HEAD` for the implicit case.

### New schema field

```yaml
enforce:
  ... existing fields ...
  protected_branches: [main, master, production]   # optional list of branch names
```

Validation rules: the list must be non-empty, every element must be a
non-empty string, and no element may contain whitespace (git refuses
those branch names anyway, and accepting them would silently no-op
the guard). When the field is omitted, the generator substitutes
`["main", "master"]` at substitution time — the schema stays
template-agnostic, so adding new templates with their own parameters
doesn't bloat the validator.

### New template — `force-push-guard.ts.template`

```yaml
enforce:
  tool: Bash
  pattern: "git push --force"          # auto-dispatches to force-push-guard
  hook: .claude/hooks/auto/force-push-guard.ts
  generated_from: memory/feedback_no_force_to_main.md
  protected_branches: [main, master]   # optional; this is the default
```

**Force flags recognised:** `--force`, `-f`, `--force-with-lease`
(including the `=` form for ref-pin), `--force-if-includes`.

**Target resolution:**
1. `git push <remote> <src>:<dst>` → `dst`
2. `git push <remote> <branch>` → `branch`
3. `git push` or `git push <remote>` → current HEAD via `execFile('git', ['rev-parse', '--abbrev-ref', 'HEAD'])`

**Allow paths** (no block, audit-logged with `event: allow`):
- target branch is not in `protected_branches`
- target cannot be resolved (detached HEAD, git lookup failed)
- delete-remote refspec (`:branch`) — separate concern, not a force-update of local

**Implementation notes:**
- Uses `execFileSync` with an args array, never a shell string. There
  is no user-controlled argument, but treating `git rev-parse` as a
  shell command would still be the wrong shape — Mnemosyne templates
  default to no-shell process spawning everywhere.
- Keeps the same `{{AUDIT_LOG_PATH}}` discipline as the block-on-match
  primitive after PR #15 R2: the audit path is whatever the schema
  computed (default `hook_stem + ".audit.jsonl"`), not a string
  rebuilt from `{{HOOK_PATH}}`.
- Phase 2 re-injection compatible — `{{INJECT_BLOCK}}` and
  `{{INJECT_CALL}}` placeholders are wired so `inject_on_match: true`
  works on this template.

### TEMPLATE_PATTERNS dispatch order

```python
TEMPLATE_PATTERNS = (
    ("Bash", "--force",  "force-push-guard.ts.template"),  # specific
    ("Bash", "git push", "cr-prepush-guard.ts.template"),  # general
)
```

First match wins, so the more specific `--force` substring shadows
the general `git push`. Operators who want force-push-guard for a
non-force pattern (rare) can still opt in via `enforce.template:`.

## What's still TODO (subsequent PRs)
- **Phase 4.2 — credential-leak-guard**: Edit/Write content scanning for AWS keys, API tokens, .env markers
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
