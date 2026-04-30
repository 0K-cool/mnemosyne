<p align="center">
  <img src="docs/assets/banner.jpg" alt="Mnemosyne Banner" width="100%" />
</p>

<p align="center">
  <strong>Structured AI memory plugin for Claude Code. 100% local. Zero cloud. Security-first.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Claude_Code-orange.svg" alt="Claude Code" />
  <a href="https://github.com/0K-cool/mnemosyne/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT" /></a>
  <img src="https://img.shields.io/badge/version-2.0.0--alpha-green.svg" alt="Version 2.0.0-alpha" />
  <img src="https://img.shields.io/badge/tests-366%20passing-brightgreen.svg" alt="366 tests passing" />
  <img src="https://img.shields.io/badge/cloud-none-critical.svg" alt="No cloud" />
  <img src="https://img.shields.io/badge/LongMemEval%20R%405-100%25-blueviolet.svg" alt="LongMemEval R@5: 100%" />
  <img src="https://img.shields.io/badge/v2-memory--driven_enforcement-9d4edd.svg" alt="v2 memory-driven enforcement" />
  <img src="https://img.shields.io/badge/ZeroK_Labs-ØK-black.svg" alt="ZeroK Labs" />
  <img src="https://img.shields.io/badge/Forged_in-Puerto_Rico_🇵🇷-c8960c.svg" alt="Forged in Puerto Rico" />
</p>

# Mnemosyne

By [ZerOK Labs](https://zeroklabs.ai) — part of the 0K product suite.

---

## Table of Contents

- [Install](#install)
- [What You Get](#what-you-get)
- [How It Works](#how-it-works)
- [Memory-Driven Enforcement (v2)](#memory-driven-enforcement-v2)
- [Architecture](#architecture)
- [Benchmark](#benchmark)
- [Security](#security)
- [Optional: Enhanced Retrieval](#optional-enhanced-retrieval)
- [Test Suite](#test-suite)
- [License](#license)

---

## Install

**Platform:** macOS (Apple Silicon optimized). Windows support planned.

```
claude plugins install mnemosyne
```

That's it. Zero dependencies. Works immediately.

## What You Get

- **Auto-save** — memories saved on session end, even if the AI forgets
- **Auto-retrieve** — relevant memories injected into every prompt
- **Memory-driven enforcement (v2 alpha)** — memory entries with an `enforce:` block generate Claude Code hooks that **hard-block at the tool boundary**. The agent cannot rationalise its way around the rule because the runtime intercepts before the tool runs. ([How](#memory-driven-enforcement-v2))
- **Self-improvement** — `/gotcha` captures mistakes at the source
- **Session mining** — `/mine-session` extracts learnings from past conversations
- **Memory validation** — L3 anti-poisoning blocks injection attempts (adversarial-tested, 100 test cases including homoglyph and encoding bypass)
- **Templates** — starter `MEMORY.md`, `identity.txt`, and `memory/` directory

## How It Works

Each component has one job. No overlap. Clear boundaries.

| Component | Role | Analogy |
|---|---|---|
| `identity.txt` | 100-token cold-start context | Your handshake |
| `MEMORY.md` | Index of what memories exist | Your table of contents |
| `memory/` files | Long-term storage — decisions, feedback, learnings | Your journal |
| `/gotcha` | Captures mistakes at the source | Your error log |
| `lessons-learned.md` | What went wrong and why | Your scar tissue |
| Auto-save hook | Mechanical enforcement — saves even if AI forgets | Your backup alarm |
| `/mine-session` | Extracts value from past conversations | Your archivist |
| L3 validation | Blocks poisoning, injection, data stuffing | Your immune system |

With optional [0K-RAG](https://github.com/0K-cool/0k-rag):

| Component | Role | Analogy |
|---|---|---|
| 0K-RAG | Hybrid semantic search across all indexed knowledge | Your library |

**Design principle:** The journal doesn't search. The library doesn't store decisions. The immune system doesn't retrieve. Each piece does one thing well.

## Memory-Driven Enforcement (v2)

> "CLAUDE.md content is delivered as a user message after the system prompt, not as part of the system prompt itself. Claude reads it and tries to follow it, but **there's no guarantee of strict compliance**."
> — [Anthropic, code.claude.com/docs/en/memory](https://code.claude.com/docs/en/memory)

Mnemosyne v1 makes memory *recallable*. v2 makes it *enforceable*. When a memory entry declares an `enforce:` block, Mnemosyne can generate a Claude Code hook that intercepts the matching tool call at the runtime boundary — a layer Anthropic's docs confirm IS enforced regardless of what the agent rationalises.

```yaml
---
name: no-force-push-to-main
type: feedback
description: |
  Force-pushing to main rewrites shared history. Catastrophic on a
  team; merely embarrassing on a solo project. Block before, not after.
enforce:
  tool: Bash
  pattern: "git push --force"
  hook: .claude/hooks/auto/force-push-guard.ts
  generated_from: memory/feedback_no_force_push_main.md
  protected_branches: [main, master]
---

Body text — the rule prose for human readers and recall.
```

```bash
PYTHONPATH=lib python -m enforce \
  --memory-dir memory \
  --output-dir .claude/hooks/auto

# → Writes .claude/hooks/auto/force-push-guard.ts
# → Claude Code loads it on next session start
# → `git push --force origin main` is now hard-blocked
```

### Templates that ship with v2 alpha

| Template | What it gates | Languages |
|---|---|:---:|
| `cr-prepush-guard` | `git push` to private 0K-cool repos behind a fresh CodeRabbit review | ts |
| `block-on-match-guard` | "Always block" pattern matches (`rm -rf /`, destructive SQL, etc.) | ts • py • sh |
| `force-push-guard` | `git push --force` to protected branches (default: `main`, `master`) | ts |
| `credential-leak-guard` | `Edit` / `Write` / `MultiEdit` writes containing AWS keys, GitHub PATs, Slack tokens, PEM private keys, Stripe live keys, npm / GitLab tokens | ts |

Tool-aware templates parse arguments rather than relying on regex alone — `force-push-guard` tokenises `git push` properly so `git -c k=v push --force ...` and `git push --force origin HEAD:refs/heads/main` are both caught (both are real bypass surfaces v1 regex would miss).

### Multi-language support

Default emit language is TypeScript (zero-dep on bun). Set `language: py` or `language: sh` in the `enforce:` block to emit a stdlib-only Python hook or a `jq`-based shell hook instead.

### What it doesn't do

- **Only the rules you wire** — entries without an `enforce:` block stay recall-only.
- **Tool boundary only** — hooks fire on tool calls, not on agent reasoning. An agent can still draft a bad plan; it just can't execute the gated action.
- **Architectural bypasses** are documented limits: Claude Code subagent calls bypass PreToolUse hooks ([#21460](https://github.com/anthropics/claude-code/issues/21460)), MCP tool calls have their own surface, `@file` mentions sidestep hook gates. Mnemosyne v2 is one defense-in-depth layer, not a silver bullet.
- **Pattern fragility is real** — a regex-only template can be evaded by command normalisation. The shipped templates layer arg parsing on top of regex to close the most common bypass classes, but new ones will surface.

Full design: [`docs/v2-enforcement.md`](docs/v2-enforcement.md).

## Architecture

```text
INSTALL (zero-dep)             v2 ENFORCE (opt-in)         + 0K-RAG (optional)
============================   ==========================  ============================
identity.txt ──► cold-start    enforce: ──► generator ──►
MEMORY.md ──► keyword index    .claude/hooks/auto/
memory/ ──► file storage         <rule>.<lang>          0K-RAG ──► vector + BM25
hooks/ ──► auto-save,                                              + RRF + BGE
           auto-retrieve,      Templates:                          reranking
           memory-validation     cr-prepush-guard
skills/ ──► /gotcha,             block-on-match-guard
            /mine-session        force-push-guard
                                 credential-leak-guard
                               Languages: ts | py | sh

Retrieval: BM25 + stemming ──► OR ──► vector + BM25 + RRF ──► OR ──► + BGE reranking
           (81% R@5, 0 deps)          (100% R@5, core)              (100% R@5, full)

Enforcement (opt-in per memory entry):
   memory entry { enforce: } ──► python -m enforce ──► PreToolUse hook ──► tool boundary block
```

## Benchmark

Tested on [LongMemEval](https://arxiv.org/abs/2410.10813) (470 questions, per-question indexing). [MemPalace](https://github.com/MemPalace/mempalace) is included as a reference — it's the most popular Claude Code memory plugin and publishes LongMemEval results using the same methodology.

| Configuration | Session R@5 | Turn R@5 | MRR | Dependencies |
|---|:---:|:---:|:---:|---|
| Mnemosyne alone | 81.1% | — | 59.7% | Zero |
| Mnemosyne + 0K-RAG core | **100.0%** | **93.0%** | 70.0% | Ollama + LanceDB |
| Mnemosyne + 0K-RAG full | **100.0%** | 91.5% | **74.3%** | Ollama + LanceDB + BGE reranker |
| MemPalace (raw ChromaDB) | 96.6% | — | — | chromadb |
| MemPalace (hybrid v4, no LLM) | 98.4% | — | — | chromadb + tuning |

**Methodology:** Per-question oracle indexing — identical to MemPalace's published methodology. Each question gets a fresh index containing only its haystack sessions. Same dataset, same metrics, same evaluation protocol.

**What the numbers mean:**
- **Session R@5:** Did the top-5 results include the correct conversation? (session-level)
- **Turn R@5:** Did the top-5 results include the exact correct turn? (turn-level, harder)
- **MRR:** How high did the first correct result rank? (1.0 = first position)

**A note on methodology:** Per-question benchmarks create a small, isolated corpus per question (~20-30 turns). All systems score high here because the search space is small. Real-world memory collections grow to hundreds of sessions. We publish both numbers so you can judge for yourself:

| Scenario | Mnemosyne + 0K-RAG | Corpus Size |
|---|:---:|---|
| Per-question (benchmark) | 100.0% R@5 | ~22 turns per question |
| Shared index (real-world) | 86.4% R@5 | 10,866 turns, single index |

The shared-index number reflects what actually happens when your memory has months of accumulated conversations. We believe this is the number that matters.

**The zero-dep tier** (81.1% R@5) uses BM25 scoring with suffix stemming against a markdown index — no models, no embeddings, no dependencies. It works offline, on any machine, instantly. For professionals who need memory but can't install ML models on hardened systems, this is a strong baseline.

**The core tier** (100% R@5, 93% turn-level) uses vector + BM25 + reciprocal rank fusion. Hits perfect session-level recall without a reranker. Best turn-level accuracy of any configuration.

**The full tier** (100% R@5, 74.3% MRR) adds BGE reranking on top. Same session-level recall as core, but better ranking of correct results (higher MRR). All local, zero API calls, zero cloud.

## Security

Mnemosyne includes an L3 anti-poisoning hook that blocks memory injection attempts at write time.

**What it catches:**
- Prompt injection patterns ("ignore previous instructions", "you are now", `<system>`)
- Privilege escalation ("act as admin", "override policies")
- Context manipulation ("forget previous", "do not follow rules")
- Oversized writes (>50KB data stuffing)
- Unicode normalization bypass (NFKC + zero-width character stripping)
- Cyrillic/Greek homoglyph substitution (confusables mapping for ~30 cross-script character pairs)
- Base64-encoded payloads (decoded and scanned if valid UTF-8 text)
- URL-encoded payloads (percent-decoded before pattern matching)

**What it doesn't catch** (known limitations, documented in tests):
- Legitimate content quoting injection patterns (security research notes that quote attack strings will trigger — this is by design: security > convenience, and the cost of a false negative outweighs the cost of a false positive)
- Novel patterns not yet in the rule set (the ruleset is updated as new techniques surface; see [SECURITY.md](SECURITY.md) for the threat-model boundary)

(HTML-entity encoding `&#105;gnore` was an earlier limitation — v1.1.0 added a numeric + small-named-entity decoder, MED-2 in the audit, so it IS now caught alongside the URL-encoded variants.)

**Test coverage:** 366 tests total (266 Python + 100 bun). The adversarial bun suite alone has 100 test cases covering contract validation, every regex pattern, homoglyph substitution, encoding bypass attempts, and false-positive prevention. `test_content_scanner.py` mirrors the same 56 cases at read time on retrieved chunks (defense in depth — same patterns, both write-time and read-time).

For comparison: MemPalace has zero memory validation. No injection detection, no size limits, no content scanning.

**Defense-in-depth:** Mnemosyne guards file system writes to memory. For broader coverage, consider [0K-Talon](https://github.com/0K-cool/0k-talon) — a security plugin that guards MCP Memory Server operations, code injection, egress, supply chain, and more. The two plugins have zero hook overlap and are tested to run together without conflicts.

## Optional: Enhanced Retrieval

For full retrieval accuracy, add 0K-RAG:

```
/mnemosyne-setup-rag
```

This guided setup installs [0K-RAG](https://github.com/0K-cool/0k-rag) — a hybrid semantic retrieval engine. Requires Ollama and ~3.7GB disk space.

| Tier | What You Get | Size |
|---|---|---|
| **Zero-dep** (default) | Keyword search against MEMORY.md index + file content | 0 MB |
| **Core** (0K-RAG, no reranker) | Vector (nomic-embed-text) + BM25 + RRF | ~2.5 GB |
| **Full** (0K-RAG) | Vector + BM25 + RRF + BGE reranker | ~3.7 GB |

The plugin auto-detects which tier is available and uses the best one.

## Test Suite

```bash
make test          # Run all 366 tests (266 Python + 100 bun)
make test-fast     # Unit + adversarial only (<1s)
make test-integration  # Hook I/O + plugin structure
```

| Suite | Framework | Tests | What It Covers |
|---|---|:---:|---|
| `test_markdown_retriever.py` | Python unittest | 23 | Two-pass keyword retrieval algorithm |
| `test_markdown_retriever_limits.py` | Python unittest | 8 | Retriever DoS guards (256KB cap, 5000-entry index ceiling) |
| `test_auto_retrieve.py` | Python unittest | 20 | RAG detection, memory dir walk, rate limiting |
| `test_auto_retrieve_security.py` | Python unittest | 30 | RAG path allowlist, importlib loader, untrusted-retrieved-memory delimiter |
| `test_content_scanner.py` | Python unittest | 56 | Read-time injection scanner (mirror of bun adversarial suite, applied to retrieved chunks) |
| `test_integration.py` | Python unittest | 10 | Dual-mode detection, plugin structure |
| `test_hook_io.py` | Python unittest | 9 | Subprocess JSON contracts for all 4 hooks |
| `test_enforce_schema.py` | Python unittest | 46 | v2 `enforce:` block validation: required fields, paths, regex compile, injection fields, template selection, protected_branches, credential_patterns, language |
| `test_enforce_generator.py` | Python unittest | 44 | v2 generator: parse, dispatch, render, bun-build / `compile()` / `bash -n` smoke tests across all template + language combinations |
| `test_enforce_cli.py` | Python unittest | 8 | v2 `mnemosyne enforce` CLI: walk memory dir, idempotent regen, dry-run, single-rule mode, orphan reporting |
| `test_enforce_audit.py` | Python unittest | 12 | v2 audit aggregator: per-rule counts, threshold escalation, JSON output |
| `test_memory_validation.test.ts` | Bun test | 100 | Adversarial L3 anti-poisoning (contract + bypass + homoglyph + encoding + read-time scanner) |

**Total: 366 tests** (266 Python + 100 bun adversarial). The bun suite shells out to a separate runtime; both are wired into `make test`.

## License

[MIT](LICENSE)

