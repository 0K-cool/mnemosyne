# Changelog

All notable changes to Mnemosyne are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semver
for versioning.

[2.3.3]: https://github.com/0K-cool/mnemosyne/releases/tag/v2.3.3
[2.3.2]: https://github.com/0K-cool/mnemosyne/releases/tag/v2.3.2
[2.3.1]: https://github.com/0K-cool/mnemosyne/releases/tag/v2.3.1
[2.3.0]: https://github.com/0K-cool/mnemosyne/releases/tag/v2.3.0
[2.2.0]: https://github.com/0K-cool/mnemosyne/releases/tag/v2.2.0
[2.1.1]: https://github.com/0K-cool/mnemosyne/releases/tag/v2.1.1
[2.1.0]: https://github.com/0K-cool/mnemosyne/releases/tag/v2.1.0
[2.0.1]: https://github.com/0K-cool/mnemosyne/releases/tag/v2.0.1
[2.0.0]: https://github.com/0K-cool/mnemosyne/releases/tag/v2.0.0
[2.0.0-alpha]: https://github.com/0K-cool/mnemosyne/releases/tag/v2.0.0-alpha

## [2.3.3] — 2026-07-06

**Security hardening — origin-binding against semantic memory poisoning.**
Adds a provenance tier to memories so untrusted-origin content cannot acquire the
ranking authority of operator-asserted facts (Sleeper / MINJA attack classes).
Prior versions defended the *syntactic* threat (injection strings, encodings)
well but were blind to a semantically-clean fabricated fact planted from an
untrusted source.

- **Reinforcement-amplifier fix (self-inflicted bug):** a retrieved
  `derived-untrusted` memory is no longer written to the reinforcement ledger, so
  a triggered plant can no longer stretch its own half-life or refresh its recency
  clock to self-promote in ranking.
- **Origin frontmatter (`origin: operator-direct | derived-untrusted`):** parsed
  by the retriever (`markdown_retriever._parse_origin`, zero-dependency). Absent
  origin defaults to `operator-direct` (existing stores keep full behavior);
  unrecognized values fail closed to `derived-untrusted`.
- **Read-time trust tier:** `wrap_untrusted()` surfaces `origin=` and, for
  `derived-untrusted` memories, prepends an authority-denial notice — the content
  may inform but may not by itself authorize an action (delete/send/deploy/spend/
  config/command). Plumbed through `auto-retrieve.py` (RAG chunks unchanged).
- **Recency-boost denial:** unvetted memories earn no recency bonus, so they
  compete on content match only and cannot out-rank operator facts on freshness.
- **`mine-session` stamps `origin: derived-untrusted`:** auto-mined memories are
  agent-derived from transcripts (which may carry tool/web/subagent content), so
  they enter at lower trust until an operator confirms them.
- Deliberately **out of scope:** cryptographic provenance signing (forgeable on a
  local single-tenant store) and shadow-store contradiction checks (need
  structured extraction the markdown/BM25 store lacks; embedding-similarity
  contradiction detection is a proven dead end). The boundary here is origin +
  capability gating, not detection. Backing: CaMeL (arXiv:2503.18813), SMSR
  (arXiv:2606.12703), Anthropic "Zero Trust for AI Agents."

## [2.3.2] — 2026-07-06

**Security fix — Windows memory-poisoning bypass.** On native Windows the L3
anti-poisoning scan silently never ran: `isMemoryFile()` matched only
forward-slash paths, so a backslash memory path (`C:\...\memory\evil.md`) was
not recognized as a memory file and a poisoned write was **allowed**. Caught by
a downstream install/security test.

- **`isMemoryFile()`** normalizes `\`→`/`, matches the resolved
  `MNEMOSYNE_MEMORY_DIR` when set, and tightens the `MEMORY.md` match. Windows
  backslash regression tests added (bun unit + end-to-end hook I/O).
- **cwd-walk visibility (confidentiality):** `auto-retrieve.py`'s cwd-walk
  fallback now emits a one-line **stderr notice** when it discovers a memory dir
  by walking up from the working directory — it could otherwise silently land a
  store inside a (client) git tree. Behavior kept (project-scoped memory relies
  on it) but made visible; `MNEMOSYNE_MEMORY_DIR` pins + silences it.
- **Docs:** `MNEMOSYNE_MEMORY_DIR` documented up front (with a Windows example);
  `MIN_QUERY_LENGTH=30` / `MAX_SESSION_SEARCHES=3` tuning constants documented.

## [2.3.1] — 2026-07-06

**Packaging fix — the plugin now actually installs.** v2.3.0 shipped working
cross-platform code but not an installable package (caught by a thorough
downstream install test on Claude Code 2.1.201).

- Manifests moved to `.claude-plugin/` — CLI ≥2.1 requires `plugin.json` there,
  not at the repo root.
- The repo is now a single-plugin **marketplace** (`.claude-plugin/marketplace.json`),
  so `marketplace add` / `install` can resolve it.
- `plugin.json` schema fixes: `author` is now an object; skills are declared via
  the `skills` array (the `setup-rag` entry was a skill, not a command); dropped
  the non-standard `compatibleWith` / `features` / `optionalIntegrations` keys.
- Install flow: `claude plugins marketplace add 0K-cool/mnemosyne` then
  `claude plugins install mnemosyne@mnemosyne`.
- CI now runs `claude plugins validate .`, so manifest/schema drift fails the
  build instead of shipping.

## [2.3.0] — 2026-07-06

**Cross-platform: native Windows support (plus Linux), CI-proven on all
three OSes.** Mnemosyne now installs and runs on macOS, Linux, and
Windows 11 — no WSL required.

- **Save hooks ported to stdlib Python** — `auto-save-stop.sh` /
  `precompact-save.sh` are now `auto-save-stop.py` / `precompact-save.py`.
  Bash is no longer a dependency.
- **Cross-platform hook registration** — new `hooks/hooks.json` declares
  every hook in exec form (`command` + `args`, `${CLAUDE_PLUGIN_ROOT}`),
  bypassing the shell entirely.
- **Windows venv path fix** — `auto-retrieve.py` resolves the optional
  0K-RAG interpreter at `.venv/Scripts/python.exe` on Windows.
- **3-OS CI matrix** — the test suite runs on `ubuntu`, `macos`, and
  `windows`.

## [2.2.0] — 2026-06-27

**Time-aware retrieval ranking — fresh, frequently-used memories rank
higher, with zero cost to archival recall.** The markdown retriever now
weights results by recency and usage, and a benchmark-driven fix to BM25
scoring substantially improves baseline retrieval quality on its own.

### Added
- **Time-aware ranking (markdown tier).** Each result's score gets a small
  additive recency bonus — `final = content_norm + λ·recency` (λ=0.10),
  where recency is a `[0,1]` signal (fresh→1, old→0). It is a *bonus*, never
  a penalty, so a strongly-matching old memory is never demoted below a
  weaker but fresher one. Recency only reorders genuine near-ties. Disabled
  automatically for temporal/forensic queries ("when did I…", "how many days
  ago…", dates) and via `apply_decay=False` for flat archival search.
- **Reinforcement ledger** (`.reinforcement.jsonl`, append-only): memories
  surfaced by the auto-retrieve hook get their recency clock refreshed, so
  frequently-used notes stay "fresh" longer (half-life stretches with use).
  Ranking-only — memory files are never modified.
- **`staleness_candidates()`**: reports dormant, never-reinforced memories
  (detect-only; feeds a future staleness-check workflow).

### Changed
- **BM25 ranking no longer caps scores at 1.0.** BM25 is unbounded by design;
  the cap flattened strong multi-term matches into a tie (on a high-distractor
  store ~91% of top-k tied at exactly 1.0, collapsing ranking to insertion
  order). Ranking now uses raw scores; the `[0,1]` display score is
  max-normalized after ranking. Also lowered BM25 `b` 0.5→0.3 (memory notes
  are uniformly short). **Recall@5 on a 53-distractor benchmark: +24.9 points.**
- **Temporal-query detection broadened** — duration/ordering/recency phrasings
  ("how many days ago", "before X", "last month", "most recently", "order of")
  now correctly disable recency ranking (false-negative rate 54%→~1%).

### Notes
- Evidence (LongMemEval decay A/B): recency is archival-recall-neutral
  (Recall@5 Δ +0.00 oracle / −0.21 on the hard set) and adds a large
  changing-fact upside (it ranks the *current* value above a stale one in
  100% of controlled trials vs 10% without). Recency is on by default.

## [2.1.1] — 2026-06-07

**CLI robustness against real-world memory dirs — surfaced by PAI
dogfood of v2.1.0.** Installing the first production warn rule against
PAI's organically-grown memory directory exposed two `mnemosyne
enforce` rough edges that never appear against clean test fixtures.

### Fixed
- **Archived rules no longer resurrected (#36).** The recursive memory
  walk regenerated rules that had been retired by moving them into
  `archived-rules/` — reinstalling the very hook the operator removed.
  Files under `archived-rules/`, `archive/`, `archived/`, or `.archive/`
  are now skipped at generation; their previously-generated hooks
  surface as orphans under `--sync` (the intended retirement signal).
- **Frontmatter-less notes no longer fail the run (#37).** A memory
  dir accumulates plain notes and the occasional prose file with
  incidentally-broken YAML; these were counted as failures, so the CLI
  exited non-zero on any organic dir (`4 eligible, 10 failed` against
  PAI's real memory). Non-rule parse failures are now skips; only a
  file that declares an `enforce:` key and fails to parse counts as a
  failure and reaches the exit code.

## [2.1.0] — 2026-06-07

**Soft-to-hard escalation — rules can now start as nudges and earn
their teeth.** A `mode: warn` rule allows-but-audits with the rule text
re-injected as `additionalContext`; an `escalation:` policy promotes it
to a hard block when warn events cross a threshold inside a rolling
window, gated on operator approval.

### Added
- `enforce.mode: warn | block` (default `block`, fully backward
  compatible). Warn variant emitted by the block-on-match family in
  all three language ports (ts/py/sh).
- `enforce.escalation: {threshold, window_days}` schema (requires
  `mode: warn`; unknown keys rejected).
- `enforce.audit`: `warn` event counting (+ table column),
  `--memory-dir` policy join, time-windowed evaluation across all
  three timestamp dialects, READY TO ESCALATE reporting (table +
  JSON), `--apply`/`--yes` operator-gated promotion (rule rewrite +
  hook regeneration via the standard `--rule` path),
  `--webhook-url`/`MNEMOSYNE_WEBHOOK_URL` notifications
  (Discord-compatible payload, http/https only, fail-soft),
  `--fail-on-escalation` (exit 3) for cron/CI alerting.
- `enforce --sync` retirement pass (#29): gated deletion of generated
  orphan hooks whose source rule was archived/deleted. Provenance
  header check (foreign files never touched), per-file confirmation
  (`--yes` for non-interactive), audit sidecars preserved,
  settings.json deregistration reminder per deletion, `--dry-run`
  report-only mode. Closes the retirement half of the rule↔hook
  contract.

### Fixed
- cr-prepush template: documented `VEX_SKIP_CR_PREPUSH=1 <cmd>` skip
  was unreachable (hook read `process.env`, which a command-prefix
  assignment never reaches) — skip is now parsed from the command
  string, same-line prefix only, audited with the path taken (#30,
  PR #31).

### Security
- Log-poisoning forced-escalation analysed and documented in the risk
  register: escalation only ever tightens enforcement; apply is
  operator-gated per rule; webhook scheme allow-listed.

## [2.0.1] — 2026-05-08

**Template hardening — surfaced by PAI dogfood.** Three PAI dogfood
install cycles (cr-prepush, force-push, credential-leak) of the v2.0.0
templates surfaced 14 template-quality findings beyond what the v2.0.0
audit reached — 12 closed in this release, 2 deferred to a known
follow-up issue. Net dogfood payoff: real-repo template usage caught a
comparable findings volume to the audit (14 vs 8) at zero incremental
review cost.

This is a patch release — no breaking changes, no schema changes, no
new public CLI surface. All changes are template + generator-side
hardening picked up automatically by `mnemosyne enforce` regen.

### Template fixes — closed

- **PR [#24]: `cr-prepush-guard` Date.parse crash on malformed entry.**
  Validate `entry.ts` is a string before `Date.parse()`; corrupt cache
  entries no longer crash the pre-push hook (would previously throw and
  block the push with an unhelpful stack trace).
- **PR [#25]: `force-push-guard` 3 real security bypasses + box-width.**
  - **CRITICAL (delete-refspec)**: `git push origin :main` form was not
    recognised as a destructive op. `normalizeBranchName` now handles
    the empty-source-ref case.
  - **MAJOR (combined short flags)**: `-af` packed flag bundling slipped
    past the `--force` matcher. Argv tokenisation now expands short-flag
    bundles before matching.
  - **MAJOR (shell quoting)**: quoted branch names (`'main'`, `"main"`)
    evaded the protected-branches check. Branch arg now strip-quoted
    before comparison.
  - **MINOR**: box-width alignment in the BLOCKED banner.
- **PR [#26]: `credential-leak-guard` 6 template fixes (Phase 5 dogfood
  3/3 of the original Saturday plan).**
  - **CRITICAL (docstring runtime contract)**: rendered hook docstring
    claimed the hook scans Edit/Write/MultiEdit; runtime exits early on
    any tool other than `{{TOOL}}`. Docstring now describes the
    rendered-instance scope, not the template's full capability surface.
  - **MAJOR (`tool_name` fail-open)**: payload missing `tool_name`
    silently fell through `!== '{{TOOL}}'` and exited 0. Now blocks
    fail-closed (consistent with `JSON.parse` and missing-`file_path`
    branches). The asymmetry is deliberate — `credential-leak-guard`
    cannot afford "missed audit, allow by default."
  - **MINOR (npm token forward-compat)**: `npm_[A-Za-z0-9]{36}` →
    `{36,}` for granular-token format stability.
  - **MINOR (Stripe `pk_live_` exclusion)**: publishable keys are
    designed for client-side embed (frontend JS, README). Removing `pk`
    from the alternation eliminates a false-positive class.
  - **MINOR (`String(err)` redaction)**: modern V8/Node embeds an input
    excerpt in `SyntaxError` messages; logging `String(err)` would have
    contradicted the hook's own redaction guarantee. Now logs the error
    class name only (`err.name`).
  - **MINOR (path-scope dead-branch comment)**: when memory entry sets
    `pattern: ".*"`, the path-scope branch is intentionally unreachable.
    Clarifying comment so future readers don't mistake intent.
  - **MINOR (box-width W=60→62)**: matches the post-PR-#25 force-push
    convention; closes the trailing-rail visual misalignment.
  - **MINOR (unused import)**: dropped `existsSync` from the `fs`
    destructure — never referenced in the rendered hook.

### Deferred (tracked in [#27])

- **D1**: GitHub token patterns `{82}/{36}` → `{82,}/{36,}` for
  forward-compat (same shape as the npm relax, but speculative — no
  known length change announced by GitHub).
- **D2**: `pad()` uses JS `string.length` not terminal display width.
  The 🛑 emoji is double-width visually but counts as 1 JS char,
  causing a 1-column misalignment on the credential-leak-guard header
  row. Cosmetic.

### Process notes

- All three fix PRs landed via `coderabbit review` cycles ranging from
  1–7 rounds. PR [#26] specifically went 7 rounds — the longest dogfood
  cycle to date — driven by sequential CR finding pickup rather than
  any single deep issue.
- The release-prep commit is direct-to-`main` (rather than via a
  PR like v2.0.0's [#22]) because the bump is purely descriptive
  ceremony — no schema, code, or test changes vs. the merged HEAD.

### Tests

- 296 Python unittest + 100 Bun adversarial tests — all green pre and
  post each fix commit.
- PAI-side smoke tests on the rendered hooks: AWS / GitHub / Stripe
  (`sk_live_`, `rk_live_` block; `pk_live_` allows post-fix) / Slack /
  PEM / npm / GitLab pattern coverage; out-of-scope tools allow
  through; fail-closed on protocol drift; redaction guarantee verified
  against malformed-JSON-with-credential payload.

[#24]: https://github.com/0K-cool/mnemosyne/pull/24
[#25]: https://github.com/0K-cool/mnemosyne/pull/25
[#26]: https://github.com/0K-cool/mnemosyne/pull/26
[#27]: https://github.com/0K-cool/mnemosyne/issues/27

## [2.0.0] — 2026-05-05

**Memory-driven runtime enforcement, audit-hardened.** v2.0.0 graduates
the alpha to non-alpha after a parallel defender + offensive audit pass
(Phase 1) against the v2.0.0-alpha enforcement layer. The audit
surfaced 2 CRITICAL + 4 HIGH + 6 MEDIUM + 6 LOW findings; all CRITs
and HIGHs are closed in this release. Remaining MEDs and LOWs are
documented as known residuals in `SECURITY.md` scoped for v2.0.1.

Audit reports archived under
`output/research/mnemosyne-v2-audit-{defender,redteam}-2026-05-05.md`.

### Security — closed (CRIT)

- **CRIT-1: Template-injection RCE via `audit_log` field.**
  Schema-layer strict character allow-list `[A-Za-z0-9_./-]` on
  `audit_log` / `hook` / `generated_from` (256-byte cap) blocks
  the quote-injection payload at validation. Per-context generator
  sanitisers (`_safe_for_ts_string`, `_safe_for_py_string`,
  `_safe_for_shell_dollar_quote`) provide defense-in-depth at
  render time.
- **CRIT-2: Symlink-follow arbitrary file overwrite + chmod.**
  CLI now refuses to write when `out_path` is a symlink (check
  runs BEFORE the read_text idempotent-skip path) and the write
  itself uses `tempfile.mkstemp` + `fchmod` + `os.rename` for
  atomic, symlink-safe replace.

### Security — closed (HIGH)

- **HIGH-1: cr-prepush cache trust violated documented policy.**
  Template now AND-combines `statSync(CACHE_PATH).mtimeMs` with
  the JSON `entry.ts` freshness gate. Forged cache JSON no longer
  bypasses pre-push review.
- **HIGH-2: ReDoS via attacker-controlled patterns.** Schema
  rejects nested unbounded quantifiers (inner `+` / `*` / `?` /
  `{n,}` followed by outer quantifier) and caps pattern byte
  length at 512.
- **HIGH-3: `_safe_for_comment` insufficient outside comment
  contexts.** Renamed to `_safe_for_line_comment` with scope
  spelled out in docstring; three new context-specific sanitisers
  used in templates' string-literal placements.
- **HIGH-4: `block-on-match-guard.*` silently no-op for non-Bash
  tools.** Schema cross-field check rejects incompatible
  `(template, tool)` pairs.

### Security — closed (MED, opportunistic)

- **RT-EXP-2:** `force-push-guard` `normalizeBranchName` now
  strips `refs/tags/` and `refs/remotes/<remote>/` in addition
  to `refs/heads/`. The bypass refspec
  `git push --force origin HEAD:refs/tags/main` no longer evades.
- **RT-EXP-4:** `cr-prepush-guard.ts.template` audit path was
  hardcoded; now follows the operator's `audit_log:` setting via
  `{{AUDIT_LOG_PATH_TS}}`, consistent with the other three
  templates.

### Known residuals (scoped for v2.0.1)

See `SECURITY.md` § "Phase 1 audit findings" for the full list with
operator-facing notes. Summary: MED-1 idempotent-skip regex (TS
comments only), MED-2 `--output-dir` bypass, MED-3 TOCTOU empty-
file window (CRIT-2 narrows but doesn't eliminate), MED-4 sidecar
orphan-detection exemption, MED-5 audit aggregator silent-skip on
torn JSONL, MED-6 `chmod 0o755` ignores ACLs, RT-EXP-6 default
credential-pattern set lacks modern token formats (`sk-ant-`,
`sk-proj-`, `hf_`, `r8_`), LOW-1 through LOW-6.

### Tests

- 266 → **296 Python unit tests** (30 new — adversarial coverage
  for each closed finding, plus the symlink-equivalent-content
  edge case CR flagged on PR #21).
- 100 bun adversarial tests on main, all green.
- LongMemEval markdown tier R@5 = 81.06% — **identical to
  v2.0.0-alpha** (no retrieval regression from the audit fixes).

### What CodeRabbit's 18+ pre-merge rounds did NOT catch

Trust-transition gaps. CR is excellent at "is this code well-
written?" and weak at "is the contract this code claims to
enforce actually enforced?" CRIT-1, CRIT-2, HIGH-1, HIGH-3,
HIGH-4 all compiled cleanly, lint-cleanly, and reviewed cleanly
through ~18 CR rounds during v2.0.0-alpha development. The
parallel defender + offensive audit caught every one. Static
analysis is not a substitute for threat modelling; both are
required.

## [2.0.0-alpha] — 2026-04-29

**Memory-driven runtime enforcement.** Mnemosyne v2 closes the gap
between rule-recall and rule-compliance: memory entries with an
`enforce:` block generate Claude Code hooks that hard-block at the
tool boundary. Anthropic's own docs describe prompt-level memory as
having "no guarantee of strict compliance" while client-side hooks
ARE enforced — Mnemosyne v2 turns that asymmetry into infrastructure.

Opt-in: every existing memory entry without an `enforce:` block keeps
behaving exactly as v1.1.0 — recall-only, no enforcement. Operators
add the block deliberately, run `mnemosyne enforce` to generate the
hook source, and Claude Code intercepts the gated tool call from
that point on.

Five phases shipped over a single overnight session:

### Added — Phase 1: schema + generator

- **`lib/enforce/schema.py`** — `enforce` block validation. Required
  fields (`tool`, `pattern`, `hook`, `generated_from`); optional
  `freshness_secs`, `audit_log`, `repo_filter`. Path-traversal guard
  on `hook` / `audit_log`; hook must live under
  `.claude/hooks/auto/`; tool must be one of Claude Code's known
  tools.
- **`lib/enforce/generator.py`** — memory-entry markdown to hook
  source. Substitutes `{{PARAM}}` placeholders, neutralises
  template-residue attacks, derives audit-log defaults from the
  hook stem.
- **`templates/hooks/cr-prepush-guard.ts.template`** — first hook
  template; gates `git push` behind a fresh CodeRabbit review.

### Added — Phase 1.2: `mnemosyne enforce` CLI

- **`python -m enforce`** — walks a memory directory, generates a
  hook for every entry with an `enforce:` block. Idempotent
  (modulo timestamp); `--dry-run` previews; `--rule <path>`
  processes one entry; orphan-hook detection with no auto-delete.

### Added — Phase 2: action-time rule re-injection

- **`inject_on_match: true` schema field** — when set, the
  generated hook calls `console.log(JSON.stringify({ additionalContext }))`
  immediately after the pattern match. Claude Code surfaces the
  reminder text to the agent's next response. Closes the temporal
  gap between when a rule was first read (hours ago) and when the
  matching action is being decided.
- **`inject_text` + `inject_token_budget`** — operator-controlled
  reminder content + size cap (default 256, max 1024 tokens; rough
  4-char-per-token estimate).

### Added — Phase 3: violation telemetry / reinforcement loop

- **`python -m enforce.audit`** — aggregates `*.audit.jsonl` files
  written by every generated hook (allow / block / skip-override
  events). Reports per-rule counts, first/last seen, and
  `--threshold N` flags rules whose block count crosses the line as
  escalation candidates. Exit code wires the aggregator into CI
  loops without bespoke parsing.

### Added — Phase 4: pattern library start (block-on-match primitive)

- **`enforce.template:` schema field** — explicit template selection;
  basename only, lives in the bundled `templates/hooks/` directory.
  When set, the generator uses it directly instead of consulting
  `TEMPLATE_PATTERNS` for tool/pattern dispatch.
- **`templates/hooks/block-on-match-guard.ts.template`** — minimal
  "always block on pattern match" primitive. No cache, no diff
  check, no allow path — fits "always block" rules
  (rm -rf, force push to main, destructive SQL). About half the
  size of cr-prepush.

### Added — Phase 4.1: force-push-guard (first tool-aware template)

- **`enforce.protected_branches:` schema field** — list of non-empty
  whitespace-free branch names; default `["main", "master"]`
  applied at substitution time so schema stays template-agnostic.
- **`templates/hooks/force-push-guard.ts.template`** — tokenises
  `git push` arguments, resolves the target branch from an explicit
  refspec or via `execFileSync('git', ['rev-parse', '--abbrev-ref',
  'HEAD'])`, and blocks when the target is in
  `protected_branches`. Recognises `--force`, `-f`,
  `--force-with-lease`, `--force-if-includes`. `normalizeBranchName()`
  strips `refs/heads/` so `git push --force origin HEAD:refs/heads/main`
  doesn't bypass via the long-form ref. Parser tolerates global
  options before `push` (e.g. `git -c key=value push --force`),
  full-path program invocations (`/usr/bin/git push`), and
  paired-arg flags (`-o ci.skip`) without misresolving the target.

### Added — Phase 4.2: credential-leak-guard (write-surface)

- **`enforce.credential_patterns:` schema field** — list of regex
  strings, each must compile under both Python `re` AND a
  documented JS-portable subset; default 8 high-confidence patterns
  applied at substitution time. Setting the field replaces the
  defaults entirely (no merge — kept deliberately unambiguous).
- **`templates/hooks/credential-leak-guard.ts.template`** — first
  template hooking the **write surface** (Edit / Write / MultiEdit)
  instead of Bash. Same template handles all three input shapes via
  runtime `tool_name` dispatch; operator writes three memory
  entries (one per tool), each generates its own hook from the
  same template logic. The schema's `pattern` field becomes a
  `file_path` scope filter (`\.env$` to scope to .env files;
  `.*` to scan every write).
- **Default credential patterns**: AWS access keys
  (`AKIA[0-9A-Z]{16}`), GitHub PATs (classic + fine-grained),
  Slack tokens, PEM private key headers, Stripe live keys, npm
  publish tokens, GitLab PATs. AWS secret keys (40-char base64)
  intentionally excluded — too many FPs against legitimate hashes
  / build artifacts.
- **Fail-closed posture** — unique among the templates. Other
  Mnemosyne hooks fail open on stdin/parse errors and on payload
  shape drift (worst case: missed audit). credential-leak-guard
  cannot afford that asymmetry — a malformed payload silently
  permits a write that may carry credentials. Fails closed with an
  audited block on stdin read errors, JSON parse errors, missing
  `file_path`, and missing content keys. Empty content (length 0)
  remains a legitimate allow path.
- **Audit redaction** — the matched credential substring is NEVER
  written to stderr or the audit JSONL. Audit entries carry only
  the file path and the pattern source.

### Added — Phase 5: multi-language hook generators

- **`enforce.language:` schema field** — one of `ts | py | sh`,
  default `ts`. Backward-compat: every existing memory entry keeps
  emitting TypeScript hooks unchanged.
- **`pick_template` swaps the `.ts.template` suffix to
  `.<lang>.template`** when language is non-default. Missing port
  raises a loud `GenerationError` naming the missing file. No
  silent fallback to TS — that would emit a `bun`-shebanged script
  in a Python deployment, the wrong runtime altogether.
- **`templates/hooks/block-on-match-guard.py.template`** — stdlib
  only (`json`, `re`, `pathlib`, `sys`); same `emit_block` /
  `append_audit` shape as TS; isinstance guards on `data` /
  `tool_input` / `cmd` so malformed JSON shapes don't violate the
  fail-open contract via AttributeError.
- **`templates/hooks/block-on-match-guard.sh.template`** — REQUIRES
  `jq` for JSON parsing; pure-POSIX JSON is impractical and the
  silent-failure modes are too risky for an enforcement hook.
  Distinguishes `grep` exit codes (rc=1 no-match → allow,
  rc≥2 regex error → block with "pattern evaluation failed") so a
  pattern using JS-only regex syntax doesn't silently disable the
  guard.
- **New `PATTERN_SH` substitution** — bash ANSI-C quoting
  (`$'...'`) so regex metacharacters like `$`, backticks, and
  `[]` round-trip into shell without mangling. Generator escapes
  only `\` and `'`.
- **Cross-field constraint** — `inject_on_match: true` requires
  `language: ts`. Phase 2 re-injection emits only TS glue today;
  combining with py/sh would produce a broken hook. Schema rejects
  the combo with a clear error pointing operators at the Phase 5.x
  port follow-ups.

### Templates shipped (v2 alpha)

| Template | ts | py | sh |
|---|---|---|---|
| `cr-prepush-guard` | ✅ | — | — |
| `block-on-match-guard` | ✅ | ✅ | ✅ |
| `force-push-guard` | ✅ | — | — |
| `credential-leak-guard` | ✅ | — | — |

Tool-aware templates (cr-prepush, force-push, credential-leak)
stay TS-only in this release; their py/sh ports are tracked as
Phase 5.x follow-ups (each non-trivial: git diff + cache logic,
`git rev-parse` shelling, multi-tool input shapes).

### Hardening discipline applied across all v2 templates

- **Audit path correctness** — `PAI_DIR` resolution uses three
  `..` to reach repo root from `.claude/hooks/auto/<file>.<lang>`.
  An earlier off-by-one (two `..`) silently shipped in two PRs
  before being caught and bundled-fixed across all three templates.
- **Block reason redaction** — block reasons never carry the
  matched command / credential substring. Audit entries carry the
  pattern source instead. Logging the matched secret would defeat
  the guard.
- **No-shell process spawning** — branch resolution in
  force-push-guard uses `execFileSync` with an args array, never
  `execSync` with a string command. Even hardcoded args follow the
  no-shell discipline.
- **Portable regex constraint** — `credential_patterns` rejects
  Python-only forms (`(?P<name>…)`, `(?P=name)`,
  `(?[aiLmsux]+…)`) at validation time so they don't crash the
  hook at startup.

### Hardening — generator-side

- **Template-residue check** — `_render` errors if any `{{X}}`
  pattern remains after substitution, catching unsupplied
  parameters at build time.
- **Comment safety** — values that land inside `//` line comments
  in templates are stripped of newlines, CR, and Unicode
  line-separator chars so a malicious memory entry cannot break
  out of the comment to inject code.
- **chmod 0o755** on every generated hook so Claude Code can spawn
  it; documented `# nosec B103 # nosemgrep` in the CLI.

### Tests

- **110 unit tests** for the v2 enforcement layer (schema +
  generator + CLI + audit aggregator + multi-language dispatch),
  on top of the existing 156 v1.1.0 retrieval / scanner / hook IO
  tests. Total: **266 Python + 100 bun adversarial = 366 tests**.
- **Per-template syntax checks**: bun-build smoke for TS,
  `compile()` for Python, `bash -n` for shell.
- **18 review rounds across 5 PRs** (PR #14 / #15 / #16 / #17 /
  #18) with CodeRabbit catching three classes of bypasses we
  shipped naively (refs/heads ref normalisation, `git -c k=v
  push` parser bypass, payload-shape-drift fail-open in
  credential-leak). Anti-loop cap (3 fixup rounds per PR) was
  never tripped.

### Documentation

- **`docs/v2-enforcement.md`** — full v2 enforcement design doc
  (schema reference, dispatch behaviour, language port table,
  hardening rationale).

### Compatibility

- v1.1.0 memory entries continue to work unchanged. The `enforce:`
  block is additive; entries without it stay recall-only.
- Adds optional `language: py | sh` runtime support; the default
  remains `ts` to preserve every existing deployment's runtime
  expectations.

## [1.1.0] — 2026-04-22

Security-hardening release. Driven by a parallel defender + offensive
audit run on the v1.0.0 codebase (April 21, 2026) that surfaced 16
findings — 2 CRITICAL, 4 HIGH, 5 MEDIUM, 3 LOW, 2 INFO. This release
closes all CRITICAL and HIGH findings plus the majority of MEDIUMs.

### Added

- **`lib/content_scanner.py`** — read-time injection scanner. Applied
  to every retrieved chunk before it reaches `additionalContext`.
  Mirrors the `INJECTION_PATTERNS` set, NFKC, confusables, zero-width
  + bidi + format strip, and HTML-entity decode from the TS validator.
- **`<untrusted-retrieved-memory>` delimiter** around every injected
  chunk, replacing the weak `[Mnemosyne Auto-Retrieved]` header. The
  delimiter tag name is collision-neutralised inside content so stored
  `</untrusted-retrieved-memory>` cannot escape the wrapper.
- **`MNEMOSYNE_LANCE_PATH` environment variable** — user-configurable
  LanceDB path, replaces the previously hardcoded auditor-specific path
  (`lance_vex_kb`). Defaults to `~/.mnemosyne/lance_kb`.
- **`_is_rag_path_allowed()` + `_resolve_allowed_rag_path()`** — allowlist
  on `MNEMOSYNE_RAG_PATH`. Only paths resolving under `~/tools/` or
  `~/.mnemosyne/` are accepted; `/tmp`, `/var/tmp`, `~/Downloads` are
  denied. Resolved path (not raw env) binds every downstream filesystem
  call — closes TOCTOU symlink-swap.
- **`_load_rag_embedder()`** — replaces `sys.path.insert(0, rag_path)`
  with `importlib.util.spec_from_file_location` + `exec_module` so no
  caller-supplied path ever enters global `sys.path`.
- **`MAX_RETRIEVE_BYTES = 256 KB` + `MAX_INDEX_ENTRIES = 5000`** on the
  markdown retriever. MEMORY.md line cap counts input lines (not parsed
  entries) so junk-line-filled indexes cannot bypass the guard.
- **Per-file exception handling** in the retriever's Pass 2 so one
  unreadable file (delete/chmod race, invalid UTF-8) no longer aborts
  the entire search.
- **`SECURITY.md`** — documented threat model + validated channels +
  residual risk disclosure.
- **`.github/dependabot.yml`** — weekly tracking of SHA-pinned Actions.
- **HTML entity decoder** — numeric (decimal + hex, case-insensitive
  `[xX]`) and small named entity set. Bounded multi-pass decode for
  double-encoded payloads (`&amp;#105;` → `&#105;` → `i`). NFKC runs
  before entity decode so fullwidth `＆` disguises collapse to ASCII
  first.

### Changed

- **`normalise_text` order** (TS and Python): NFKC → entity decode →
  NFKC → zero-width strip → NBSP → confusables. Previously entities
  decoded first, leaving disguised fullwidth ampersands unfolded.
- **Zero-width strip → empty**, no longer space-replaced. The prior
  behaviour split tokens (`ig<ZWS>nore` → `ig nore`) and defeated the
  `/ignore\s+previous/` regex. Expanded to cover U+200B–U+200F,
  U+202A–U+202E, U+2060, U+2066–U+2069, U+FEFF.
- **Session ID handling**: whitelisted to `^[A-Za-z0-9_-]{1,64}$`. Any
  non-matching input (including `CLAUDE_CODE_SESSION_ID=../../evil`
  which was live-confirmed to escape the state directory) maps to
  `"unknown"` and routes to a single shared counter.
- **CI workflow `claude.yml`**: SHA-pinned `actions/checkout` and
  `anthropics/claude-code-action`; added `author_association` allowlist
  on all four `@claude` triggers so random issue commenters cannot
  invoke Claude Code runs on the repo; top-level `contents: read`
  default permission; `timeout-minutes: 15`; `persist-credentials: false`.

### Removed

- `.github/workflows/claude-code-review.yml` and
  `claude-code-security-review.yml` — Mnemosyne is a public repo; per
  the zero-drift Step 5c.0 policy, public repos use CodeRabbit App for
  review and the Claude CI chain was redundant.
- Kelvin-specific `~/Personal_AI_Infrastructure/lance_vex_kb` hardcoded
  default from `search_rag`.

### Fixed

- **CRIT-1 / F-01** — no read-time scan on retrieved memory. Closed.
- **CRIT-2 / F-01+F-10** — unsanitised RAG chunks + hardcoded Kelvin
  path. Closed.
- **CRIT-3 / F-02** — session ID path traversal. Closed.
- **HIGH-1/2 / F-03+F-11** — unbounded file read + unbounded MEMORY.md
  line scan. Closed.
- **HIGH-3 / F-05** — `sys.path.insert` import hijack. Closed via
  allowlist + importlib isolation.
- **HIGH-4 / F-06** — CI supply-chain + untrusted `@claude` commenter.
  Closed.
- **MED-1 / F-08** — ZWS strip bypass. Closed.
- **MED-2 / F-09** — HTML entity encoding bypass. Closed.
- **MED-3 / F-10** — RAG label injection. Closed via `sanitize_label`.

### Reconfirmed (no regression since v1.0.1)

- **H-3** — path traversal in MEMORY.md link resolution
  (`lib/markdown_retriever.py:_safe_resolve_memory_path`). Fixed in
  v1.0.1 (PR #2); the v1.1.0 audit bypass-tested every layer of the
  four-part defence and found no regression.

### Deferred to v1.1.1

- **MED-4 / M-2** — semantic / paraphrase injection requires an
  LLM-based read-path classifier; out of scope for this release.
- **M-1** — fail-open event logging.
- **M-3** — nested base64 decode depth.
- **M-5** — URL-encoded traversal pre-check.
- **L-1** — state file expiry / rotation.
- **L-2** — `find_memory_dir` 10-parent walk documentation.
- **I-1** — static-string Stop / PreCompact hook cleanup.

## [1.0.1] — 2026-04-20

### Fixed

- **H-3** path traversal in MEMORY.md link resolution via
  `_safe_resolve_memory_path` four-layer defence (absolute reject,
  `~` reject, `.md` requirement, post-resolve `relative_to` check).
  See PR #2.

## [1.0.0] — 2026-04-15

Initial release.

### Added

- Dual-mode retrieval: RAG (lancedb + nomic-embed-text via
  vex-rag / 0k-rag) with a zero-dependency Markdown fallback
  (`lib/markdown_retriever.py`).
- `memory-validation.ts` PreToolUse hook — pattern + base64 + URL
  decode scan on `Write` / `Edit` / `MultiEdit` tool calls targeting
  `memory/` files or `MEMORY.md`.
- `auto-retrieve.py` UserPromptSubmit hook — per-prompt semantic search,
  result-count caps, session search rate limit.
- `auto-save-stop.sh` and `precompact-save.sh` hooks to nudge the model
  toward persisting learnings.
- `mnemosyne-setup-rag` slash command.

[1.1.0]: https://github.com/0K-cool/mnemosyne/releases/tag/v1.1.0
[1.0.1]: https://github.com/0K-cool/mnemosyne/releases/tag/v1.0.1
[1.0.0]: https://github.com/0K-cool/mnemosyne/releases/tag/v1.0.0
