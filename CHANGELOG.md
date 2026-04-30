# Changelog

All notable changes to Mnemosyne are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semver
for versioning.

[2.0.0-alpha]: https://github.com/0K-cool/mnemosyne/releases/tag/v2.0.0-alpha

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
