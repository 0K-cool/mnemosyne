# Changelog

All notable changes to Mnemosyne are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); semver
for versioning.

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
