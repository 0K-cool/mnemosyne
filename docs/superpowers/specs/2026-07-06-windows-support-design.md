# Mnemosyne Cross-Platform (Windows) Support — Design Spec

**Date:** 2026-07-06
**Status:** Approved design → ready for implementation planning
**Repo:** `0K-cool/mnemosyne` (working clone `~/VERSANT/Projects/Mnemosyne`, v2.2.0)
**Forcing function:** NESTOR (RSM work identity) needs Mnemosyne on a Windows 11 laptop.
**Target release:** v2.3.0

---

## 1. Goal

Make Mnemosyne install and run on **native Windows 11 (no WSL)**, product-grade — full support, not beta. In doing so, formalize the plugin as a **three-platform** product: **macOS + Linux + Windows**, each CI-proven.

**Why Linux is in scope for free:** CI already runs on `ubuntu-24.04` (Linux is the current de-facto test platform), and every design move is natively portable to it. The README currently claims "macOS (Apple Silicon optimized)" while CI only tests Linux — this spec closes that gap by advertising and CI-proving all three.

---

## 2. Root cause of Windows incompatibility

1. **Two bash hooks** — `hooks/auto-save-stop.sh`, `hooks/precompact-save.sh` — won't fire on native Windows. They are trivial: each reads stdin (discards it) and emits a fixed `{"continue": true, "additionalContext": "<save-reminder>"}` JSON.
2. **No `hooks/hooks.json`** — the plugin has no cross-platform hook registration; `plugin.json` only sets `"hooks": true`. Hook commands aren't declared in a portable, shell-free form.
3. **`auto-retrieve.py:188`** hardcodes `.venv/bin/python3` (Unix venv layout) for the optional 0K-RAG probe — on Windows that path is `.venv\Scripts\python.exe`.
4. **Interpreter name** — `python3` is standard on macOS/Linux but not reliably on Windows PATH (`python` / `py` launcher there).

Non-issues (already portable): `lib/` is stdlib + PyYAML; `pathlib`/`os.path.expanduser` usage; `memory-validation.ts` runs on bun (cross-platform).

---

## 3. Design decisions

### 3.1 All-Python save hooks (drop bash)
Replace the two `.sh` hooks with stdlib `.py` equivalents emitting the identical JSON. Bash is removed from the plugin entirely (simplifies macOS/Linux too). Python is already a required dependency (retriever + auto-retrieve).

### 3.2 Cross-platform hook registration via `hooks/hooks.json` + exec form
Create `hooks/hooks.json` declaring every hook in **exec form** (`command` + `args`), which Claude Code documents as the cross-platform-safe pattern — it bypasses the shell (no `sh`/PowerShell/git-bash variance). Anchor script paths with **`${CLAUDE_PLUGIN_ROOT}`**.

Hooks to declare: `auto-retrieve.py` (UserPromptSubmit), `auto-save-stop.py` (Stop), `precompact-save.py` (PreCompact), `memory-validation.ts` (PreToolUse).

Example entry (interpreter pending §3.3):
```json
{
  "type": "command",
  "command": "python3",
  "args": ["${CLAUDE_PLUGIN_ROOT}/hooks/auto-save-stop.py"]
}
```

### 3.3 Interpreter resolution (design spike — resolve FIRST)
Decide how the exec-form `command` names the Python interpreter so it resolves on all three OSes. Candidates:
- `python3` — works macOS/Linux; **verify Windows** (python.org installer / `py` launcher / Store alias).
- `python` — works Windows; not guaranteed on macOS.
- Per-OS entries if Claude Code hooks.json supports OS conditioning.

Resolve empirically on the Vaio + Windows CI before finalizing `hooks.json`. This gates the command syntax. `memory-validation.ts` stays `bun`.

### 3.4 Path / state audit
- Fix `auto-retrieve.py:188` — select `.venv\Scripts\python.exe` on Windows, `.venv/bin/python3` on Unix (use `sys.platform`/`os.name`). (Optional-RAG path; NESTOR won't use it, but product-grade support requires correctness.)
- Prefer `${CLAUDE_PLUGIN_DATA}` for the state dir where a hook receives it; keep `~/.mnemosyne/state` via `expanduser` as the fallback (already cross-platform).
- Confirm no remaining Unix-only path/shell assumptions in `hooks/` and `lib/`.

### 3.5 Three-OS CI
Extend `.github/workflows/ci.yml` to a matrix over `ubuntu-latest`, `macos-latest`, `windows-latest`:
- `actions/setup-python@<pinned>` (3.12), `pip install pyyaml`.
- Run tests directly: `python -m unittest discover -s tests -p "test_*.py"` (Windows has neither `make` nor `python3`; invoking the module avoids both).
- Keep the existing adversarial/integration coverage.
Add hook-I/O tests for the two new Python hooks (`tests/test_hook_io.py`): stdin in → exact JSON out, exit 0.

### 3.6 Docs + release
- `README.md`: "Platform: macOS (Apple Silicon optimized). Windows support planned." → macOS / Linux / Windows supported; add Windows prereqs (Python on PATH, bun) + install notes.
- `plugin.json`: version bump to 2.3.0; reflect platform support if a field exists.
- `CHANGELOG.md`: v2.3.0 entry.

---

## 4. Files touched

- **Delete:** `hooks/auto-save-stop.sh`, `hooks/precompact-save.sh`
- **Create:** `hooks/auto-save-stop.py`, `hooks/precompact-save.py`, `hooks/hooks.json`
- **Modify:** `hooks/auto-retrieve.py` (venv path fix), `.github/workflows/ci.yml` (3-OS matrix), `tests/test_hook_io.py` (new hook tests), `README.md`, `CHANGELOG.md`, `plugin.json`

---

## 5. Verification

- **CI green on all three OSes** (ubuntu + macos + windows) — the product-grade bar.
- **No macOS/Linux regression** — existing 18 test files still pass.
- **Vaio manual confirmation** — install the plugin, confirm auto-retrieve injects context, auto-save/precompact fire on session end/compaction, memory persists to `memory/`.

---

## 6. Out of scope (YAGNI)

- Full 0K-RAG-on-Windows beyond the `.venv` path fix (RAG is optional; Windows vector stack is a separate effort).
- Rewriting `memory-validation.ts` (bun is already cross-platform).
- WSL-specific paths (native Windows is the target).

---

## 7. Open items

- **Interpreter-name spike (§3.3)** — resolve on the Vaio/CI before finalizing `hooks.json`. Load-bearing; do first.
- Confirm whether Claude Code auto-registers plugin hooks from `hooks/hooks.json` on install, or whether users must wire them — determines whether §3.2 fully closes registration or also needs an install note.
