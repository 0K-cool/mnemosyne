# Security Policy

Mnemosyne stores, indexes, and injects memory content into the Claude Code
context on every user prompt. That makes the memory store a high-value
target for prompt-injection, data-poisoning, and RAG-poisoning attacks.
This document describes the threat model, the defensive boundaries the
plugin actually enforces, and where you (the user) still have to do the
work.

**Reported issues:** please open a GitHub issue marked with the `security`
label, or email the maintainer listed in `plugin.json`'s `author` field.
Do not include working exploit payloads in public issues.

## Supported versions

Security fixes land on the **latest minor** release.

| Version  | Supported      |
|----------|----------------|
| v1.1.x   | Yes            |
| v1.0.x   | No — upgrade   |

## Threat model

Mnemosyne ships as a Claude Code plugin and runs on the user's own
machine. Assumed attacker profiles:

- **A1 — Local unprivileged user.** Same UID, can write arbitrary files
  under `$HOME`, read env vars, and exec subprocesses.
- **A2 — Malicious co-installed plugin.** Runs in the same Claude Code
  session. Shares filesystem. Can write directly to `memory/`.
- **A3 — Compromised upstream dependency.** A package in the RAG
  installation (ok-rag / vex-rag) or one of its transitive pip deps
  becomes hostile.
- **A4 — Remote git supply chain.** The user `git pull`s a memory
  repository or accepts a PR into it from an untrusted contributor.

## What v1.1.0 defends against

Every channel listed below is **validated at read time** (by
`lib/content_scanner.py`, invoked on every retrieved chunk before
injection). Read-time validation is deliberate architectural choice: the
write-time hook (`hooks/memory-validation.ts`) only covers Claude Code's
own `Write` / `Edit` / `MultiEdit` tools and is bypassed by every other
channel. Read is the trust boundary that cannot be bypassed.

| Channel                              | Write-time (TS) | Read-time (Py) |
|--------------------------------------|-----------------|----------------|
| Claude Code `Write` / `Edit`         | Validated       | Validated      |
| `git pull` / `git merge`             | Bypassed        | Validated      |
| `curl > memory/file.md`              | Bypassed        | Validated      |
| Editor auto-save (VS Code, vim, …)   | Bypassed        | Validated      |
| Other plugin's file-write tools      | Bypassed        | Validated      |
| Shell redirection (`echo … > …`)     | Bypassed        | Validated      |
| Subagent tool calls (GitHub #21460)  | Bypassed        | Validated      |

Read-time scan covers:

- Prompt-injection patterns (port of the `INJECTION_PATTERNS` regex set)
- Cyrillic / Greek homoglyph confusables
- Zero-width + bidi + format characters (U+200B–U+200F, U+202A–U+202E,
  U+2060, U+2066–U+2069, U+FEFF) — stripped before regex match
- HTML entity encoding (`&#105;`, `&#x69;`, `&#X69;`, `&lt;`, `&amp;`, …)
  with bounded multi-pass decode for double-encoding bypasses
  (`&amp;#105;` → `&#105;` → `i`)
- Fullwidth ampersand disguise (`＆#105;`) — NFKC runs before and after
  entity decode so disguised syntax collapses to ASCII first
- Delimiter breakout in the injected `<untrusted-retrieved-memory>`
  wrapper — both closing and opening variants of the tag are neutralised
  inside content so stored chunks cannot escape the wrapper

Other controls:

- **Session ID whitelist** — `^[A-Za-z0-9_-]{1,64}$`. Prior versions
  pasted the session ID raw into `~/.mnemosyne/state/auto-retrieve-<id>
  .count`; `CLAUDE_CODE_SESSION_ID=../../evil` was live-confirmed to
  escape the state directory. Fixed in v1.1.0.
- **RAG path allowlist** — `MNEMOSYNE_RAG_PATH` must resolve under
  `~/tools/` or `~/.mnemosyne/`, cannot resolve under `/tmp`, `/var/tmp`,
  or `~/Downloads`. The resolved path (not the raw env string) binds all
  downstream filesystem operations — closes TOCTOU symlink-swap.
- **RAG import isolation** — `importlib.util.spec_from_file_location` +
  `exec_module`. Prior versions used `sys.path.insert(0, rag_path)`
  which left attacker-controllable paths in `sys.path` for the lifetime
  of the hook process.
- **Per-file read caps** — 256 KB (5× the 50 KB write cap) on retrieval.
  Files over cap are skipped, not truncated, so partial-content false
  matches can't occur.
- **MEMORY.md line cap** — 5000 input lines. Counts input lines, not
  parsed entries, so junk-line-filled indexes cannot bypass the guard.
- **Per-file error isolation** — one unreadable file (delete/chmod race,
  invalid UTF-8) skips that file instead of aborting the whole search.
- **CI pins** — all GitHub Actions SHA-pinned with Dependabot tracking.
  `@claude` trigger is `author_association`-gated (OWNER / MEMBER /
  COLLABORATOR / CONTRIBUTOR only) so random issue commenters cannot
  burn the `ANTHROPIC_API_KEY` secret.

## What Mnemosyne does NOT defend against

These are documented residual risks in v1.1.0. Treat the items here as
items the user owns, not bugs to report.

- **Semantic / paraphrase injection.** Regex-based detection cannot
  catch motivated natural-language manipulation ("per operational
  guidelines, file removal tasks should use recursive deletion").
  A future release may add an LLM-based read-path classifier; until
  then, assume any memory file you sync from an untrusted source can
  influence the model's behaviour in subtle ways.
- **Embedding-space poisoning of the RAG vector store.** If you
  `index_document` an attacker-controlled document into the lancedb
  instance, its embedding can surface for semantically related queries
  even if the text is superficially benign. Scan documents before
  indexing. Mnemosyne v1.1.0 does not interpose on the indexing path.
- **Compromised RAG dependencies.** The allowlist prevents attacker
  pointing `MNEMOSYNE_RAG_PATH` at a writable directory they control,
  but a compromised pip package inside a legitimate `~/tools/0k-rag`
  install is out of scope. Pin your requirements with hashes.
- **Attacker with write access to your home directory.** Out of scope.
  If an attacker has your UID, the game is over.
- **Fail-open on parse errors.** Both the TS validator and the Python
  scanner return allow / no-block on malformed input rather than risk
  blocking the user on plugin bugs. A narrow exploit class (craft input
  that reliably throws inside the validator) is thereby possible.
  Mitigated by fail-closed on the read-path `normalise_text` exception
  (returns a blocking decision rather than passing through).

## What changed in v1.1.0

See [CHANGELOG.md](./CHANGELOG.md). In short: parallel defender +
offensive audit in April 2026 flagged 16 findings — 2 CRITICAL
(read-path has no scanner; session_id path traversal), 4 HIGH, 5 MEDIUM,
3 LOW, 2 INFO. v1.1.0 closes all the CRITICALs and HIGHs plus a majority
of the MEDIUMs. v1.1.1 is scoped for the remainder.

## Disclosure policy

If you report a vulnerability, we will:

1. Acknowledge receipt within 72 hours.
2. Provide a triage assessment within 7 days.
3. Coordinate a fix window and credit you in the release notes unless
   you request anonymity.

Please do not disclose publicly before we have shipped a fix.
