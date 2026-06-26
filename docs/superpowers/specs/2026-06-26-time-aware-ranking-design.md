# Mnemosyne v2.2 — Time-Aware Retrieval Ranking

**Date:** 2026-06-26
**Status:** Design approved — pre-implementation
**Target:** `lib/markdown_retriever.py` + new `lib/reinforcement_ledger.py` (markdown tier)

---

## 1. Summary

Retrieval ranking that distinguishes living context from archive —
**without ever deleting, hiding, or rewriting anything.**

Today `MarkdownRetriever` ranks results purely by BM25 keyword relevance. A note
from months ago and one from yesterday rank identically given equal keyword
overlap, so stale memories clutter the top of results. This feature folds a
**recency/usage multiplier** into the final score: fresh and frequently-pulled
memories rank higher, dormant ones gently sink. Decay is a **ranking signal
only** — never storage. Nothing is deleted; the full archive is always one
flat (`apply_decay=False`) search away.

---

## 2. Non-Goals (YAGNI)

- **No entity/relationship graph layer.** Out of scope; ranking only.
- **No decay-as-deletion / decay-as-storage.** Memory files are never modified by
  this feature. Forensic and audit completeness is preserved.
- **No `/memory-staleness-check` skill here.** This spec ships the data-producing
  method only; the consuming skill is a separate future deliverable.
- **No env-var / config plumbing.** Constants are module-level and gentle by
  default. Tunable by editing constants.

---

## 3. Architecture

```
search(query, top_k, apply_decay=True, reinforce=False)
  │
  ├─ parse MEMORY.md index               (unchanged)
  ├─ BM25 pass 1 / pass 2 / fallback      (unchanged) → combined_score per result
  ├─ load ReinforcementLedger aggregate   (once per search)
  ├─ multiply each score × recency_factor(source)   [skipped if decay disabled]
  ├─ sort by adjusted score → top_k
  ├─ if reinforce: append one event per returned source   (best-effort)
  └─ return top_k
```

Two units, each independently testable:

### 3.1 `ReinforcementLedger` (new — `lib/reinforcement_ledger.py`)

Append-only JSONL sidecar at `<memory_dir>/.reinforcement.jsonl` (sibling to
the existing `.audit.jsonl`). Pure stdlib.

**Interface**
- `record(sources: list[str]) -> None` — append one `{"source": str, "ts": float}`
  line per source. Single batched write (one `open(..., "a")`), best-effort:
  any `OSError` is swallowed so reinforcement never breaks search.
- `aggregate() -> dict[str, dict]` — fold the ledger into
  `{source: {"access_count": int, "last_reinforced": float}}`.

**Defensive read (untrusted-input threat model — same as MEMORY.md):**
- Cap lines read at `MAX_LEDGER_LINES = 50_000`.
- Cap file size read at `MAX_LEDGER_BYTES = 5 MB`.
- Skip any line that is not valid JSON, lacks a string `source`, or whose `ts`
  is not a finite number.
- Missing file → empty aggregate (no crash).

### 3.2 Decay scoring (in `markdown_retriever.py`)

```
recency_factor(source) =
    DECAY_FLOOR + (1 - DECAY_FLOOR) * 0.5 ** (age_days / half_life)

  age_days  = (now - reference_ts) / 86400
  reference_ts =
      ledger.last_reinforced[source]      if source in ledger
      else file mtime                     if entry has a file
      else now  (factor → 1.0, never penalize undatable bold entries)

  half_life = min(BASE_HALF_LIFE_DAYS * (1 + log2(1 + access_count)),
                  MAX_HALF_LIFE_DAYS)
```

**Constants (module-level):**
- `DECAY_FLOOR = 0.5` — a fully-decayed, never-reinforced memory ranks at worst
  half its honest content score.
- `BASE_HALF_LIFE_DAYS = 90`
- `MAX_HALF_LIFE_DAYS = 365`

**Key invariant — `factor ∈ [DECAY_FLOOR, 1.0]`.** Decay can only ever *reduce* a
score, never inflate it above the honest BM25 content score. Consequence for the
poisoning case: a forged ledger entry can at most *un-decay* a memory (push its
factor toward 1.0); it can never push a memory above its content relevance, and
BM25 still gates whether the memory is a candidate at all. Blast radius is bounded
to "relatively promote an already-content-relevant memory." Accepted residual
risk, documented in SECURITY.md.

### 3.3 Query-aware opt-out

Decay is disabled (all factors = 1.0) when **any** of:
- `apply_decay=False` passed explicitly (audit/forensic callers, tests).
- The query matches a **temporal/forensic** marker:
  `when`, `first`, `earliest`, `original(ly)`, `history`, `timeline`, `ever`,
  `since`, an ISO date `\d{4}-\d{2}-\d{2}`, or a month name.

Rationale: "when did we first see X" and date-scoped audit queries must search
the full archive flat — recency bias would actively harm them and archival
recall.

### 3.4 Staleness feed

`staleness_candidates(threshold_factor: float = DECAY_FLOOR + 0.02, max_access_count: int = 1) -> list[dict]`
— returns memories whose current `recency_factor` sits at/under `threshold_factor`
**and** whose `access_count <= max_access_count` (default 1 — effectively never
reinforced), each as `{"source", "last_reinforced", "factor", "access_count"}`.
Detect-and-report only; never rewrites. Data feed for a future staleness-check
workflow. Runs with `reinforce=False` (a staleness scan must not itself reinforce).

---

## 4. Reinforcement Semantics

- **What reinforces:** every source that appears in the **final returned
  `top_k`** of a `search()` call with `reinforce=True`.
- Only the returned top_k count — not all intermediate BM25 candidates — so
  exploratory queries reinforce narrowly.
- **`reinforce` defaults to `False`** (no side effects for library/test/audit
  callers). The auto-retrieve hook (`hooks/auto-retrieve.py`) explicitly opts in
  with `reinforce=True`, so real session retrievals are the usage signal. This
  keeps the "reinforce on returned top_k" mechanic while making the *write*
  opt-in — existing tests pass untouched and no programmatic search silently
  mutates state.

---

## 5. Error Handling

| Failure | Behavior |
|---|---|
| Ledger file missing | Empty aggregate; all factors from mtime / neutral |
| Ledger line corrupt | Skip line; enforce line + byte caps |
| `ts` non-numeric / non-finite | Skip line |
| `os.path.getmtime` raises | factor = 1.0 for that source |
| Ledger append fails (read-only FS) | Swallow `OSError`; search returns normally |

No failure in this feature may break `search()`. Reinforcement and decay are
both best-effort enhancements over a retrieval path that must always succeed.

---

## 6. Testing (TDD — write first)

**`reinforcement_ledger` unit:**
- `record` appends one line per source; `aggregate` counts + tracks max ts.
- Corrupt lines skipped; non-numeric `ts` skipped; line cap enforced.
- Missing file → empty aggregate.
- Append failure swallowed.

**Decay math unit:**
- Never-reinforced + ancient → factor ≈ `DECAY_FLOOR`.
- Just-reinforced → factor ≈ 1.0.
- Factor always within `[DECAY_FLOOR, 1.0]`.
- `half_life` increases with `access_count`, capped at `MAX_HALF_LIFE_DAYS`.

**search() integration:**
- Two equal-content memories, different ages → fresher ranks first.
- Temporal query ("when did we first…") → stale memory NOT penalized.
- `apply_decay=False` → identical ordering to pre-feature behavior.
- `reinforce=True` writes events for returned sources; `reinforce=False` writes none.
- `staleness_candidates()` returns expected stale entries, writes nothing.

**Regression:**
- Existing `test_markdown_retriever*.py` pass unchanged. (Fixtures written fresh
  in a test share ~identical mtime → all factors ≈ 1.0 equally → relative order
  preserved. Verify, don't assume.)

---

## 7. Release Gate

Implementation may merge to `main`, but **v2.2 is not tagged/released until** the
retriever is benchmarked **both ways** — decay on vs off — against a long-memory
recall set (archival recall) and a daily-driver relevance set, with the trade-off
documented. Recency bias is expected to help daily relevance and may hurt pure
archival recall; the release must quantify both.

---

## 8. Security Notes (for SECURITY.md)

- Ledger lives in `memory_dir` — same trust boundary as MEMORY.md; treated as
  potentially untrusted. Reads are capped and validated.
- The `[DECAY_FLOOR, 1.0]` clamp is the core security property: reinforcement
  can never inflate a score above honest content relevance, only slow its decay.
- Reinforcement writes are best-effort and append-only; no read-modify-write,
  no file rewrite, so a write race cannot corrupt existing memory content.
