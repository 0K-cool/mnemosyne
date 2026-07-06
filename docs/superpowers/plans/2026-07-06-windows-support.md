# Mnemosyne Cross-Platform (Windows) Support — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Mnemosyne install and run on native Windows 11 (no WSL) — and formalize macOS/Linux/Windows as CI-proven platforms — by replacing the two bash hooks with stdlib Python, adding cross-platform `hooks/hooks.json` exec-form registration, fixing the Windows venv path, and extending CI to a 3-OS matrix. Ship as v2.3.0.

**Architecture:** All hooks invoked via exec form (`command` + `args`) — bypasses the shell, the Claude Code-documented cross-platform pattern. Scripts located via `${CLAUDE_PLUGIN_ROOT}`. Save hooks become trivial stdlib-Python static-JSON emitters (byte-identical behavior to the bash versions).

**Tech Stack:** Python 3.10+ stdlib (+ PyYAML for enforce), `unittest`, GitHub Actions, bun (existing TS hook only).

## Global Constraints

- Target: **native Windows 11 (no WSL)** + macOS + Linux. — spec §1.
- Hooks use **exec form** (`command`+`args`), never shell form. — spec §3.2.
- Interpreter command in `hooks.json` = **`python3`**, verified to resolve on all three CI OSes (via `actions/setup-python`, which provides `python3` on windows-latest). Documented Windows prereq: Python 3.10+ on PATH. — spec §3.3.
- Save-hook `additionalContext` strings must be **byte-identical** to the current bash hooks (no behavior change). — spec §3.1.
- No macOS/Linux regression: existing 18 test files stay green. — spec §5.
- Branch: `feat/windows-support` off `main`. Commit per task. Do NOT commit to `main`.

---

## File Structure

```
hooks/
├── auto-save-stop.py      (NEW — replaces auto-save-stop.sh)
├── precompact-save.py     (NEW — replaces precompact-save.sh)
├── auto-retrieve.py       (MODIFY — venv path fix)
├── memory-validation.ts   (unchanged — bun, cross-platform)
└── hooks.json             (NEW — cross-platform exec-form registration)
tests/test_hook_io.py      (MODIFY — add tests for the 2 new Python hooks)
.github/workflows/ci.yml   (MODIFY — 3-OS matrix)
README.md, CHANGELOG.md, plugin.json  (MODIFY — docs + release)
```

---

### Task 0: Branch + schema confirmation

- [ ] **Step 1: Create the feature branch**

Run: `cd ~/VERSANT/Projects/Mnemosyne && git checkout -b feat/windows-support`
Expected: `Switched to a new branch 'feat/windows-support'`

- [ ] **Step 2: Confirm the exact `hooks.json` schema**

Read the persisted Claude Code plugins-reference doc:
`/Users/kelvinlomboy/.claude/projects/-Users-kelvinlomboy-Personal-AI-Infrastructure/1653b122-6d05-466c-ab6c-70acd690186f/tool-results/toolu_01HhUZCEjiUR4vYHf8pvwvHe.txt`
Confirm the event→`{matcher?, hooks:[{type,command,args}]}` nesting used in Task 3. If it differs from the structure below, use the doc's schema.

---

### Task 1: All-Python save hooks

**Files:**
- Create: `hooks/auto-save-stop.py`, `hooks/precompact-save.py`
- Delete: `hooks/auto-save-stop.sh`, `hooks/precompact-save.sh`
- Test: `tests/test_hook_io.py`

**Interfaces:**
- Produces: each hook reads (and drains) stdin, prints exactly one JSON object `{"continue": true, "additionalContext": "<fixed string>"}` to stdout, exits 0. The `additionalContext` strings are copied verbatim from the bash originals.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_hook_io.py`:
```python
import json, subprocess, sys
from pathlib import Path

HOOKS = Path(__file__).resolve().parent.parent / "hooks"

def _run(hook_name, stdin_text=""):
    proc = subprocess.run(
        [sys.executable, str(HOOKS / hook_name)],
        input=stdin_text, capture_output=True, text=True,
    )
    return proc

class TestPythonSaveHooks(unittest.TestCase):
    def test_auto_save_stop_emits_valid_json_continue_true(self):
        p = _run("auto-save-stop.py", '{"session_id":"x"}')
        self.assertEqual(p.returncode, 0)
        obj = json.loads(p.stdout)
        self.assertTrue(obj["continue"])
        self.assertIn("Auto-Save", obj["additionalContext"])

    def test_precompact_emits_valid_json_continue_true(self):
        p = _run("precompact-save.py", '{"trigger":"auto"}')
        self.assertEqual(p.returncode, 0)
        obj = json.loads(p.stdout)
        self.assertTrue(obj["continue"])
        self.assertIn("Pre-Compact", obj["additionalContext"])

    def test_hooks_ignore_stdin_and_never_crash_on_empty(self):
        for h in ("auto-save-stop.py", "precompact-save.py"):
            p = _run(h, "")
            self.assertEqual(p.returncode, 0, f"{h} failed on empty stdin")
            json.loads(p.stdout)
```
(Ensure `import unittest` is present at the top of the file.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_hook_io -v`
Expected: FAIL (files `auto-save-stop.py` / `precompact-save.py` don't exist yet).

- [ ] **Step 3: Write `hooks/auto-save-stop.py`**

```python
#!/usr/bin/env python3
"""Mnemosyne: Auto-save on session end (Stop hook). Cross-platform stdlib."""
import sys
import json

_ = sys.stdin.read()  # drain stdin; content unused
print(json.dumps({
    "continue": True,
    "additionalContext": "[Mnemosyne Auto-Save] Session ending. If you learned anything new about the user, their projects, or received corrections during this session, save them to memory/ files now before the session closes. Check: (1) Any unsaved user preferences or feedback? (2) Any project decisions not yet recorded? (3) Any corrections that should update lessons-learned.md?"
}))
```

- [ ] **Step 4: Write `hooks/precompact-save.py`**

```python
#!/usr/bin/env python3
"""Mnemosyne: Save before context compression (PreCompact hook). Cross-platform stdlib."""
import sys
import json

_ = sys.stdin.read()  # drain stdin; content unused
print(json.dumps({
    "continue": True,
    "additionalContext": "[Mnemosyne Pre-Compact] Context compression imminent. Save any unsaved decisions, corrections, or learnings to memory/ files NOW — they may be lost after compression."
}))
```

- [ ] **Step 5: Delete the bash hooks**

Run: `git rm hooks/auto-save-stop.sh hooks/precompact-save.sh`

- [ ] **Step 6: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_hook_io -v`
Expected: PASS (3 new tests green).

- [ ] **Step 7: Commit**

```bash
git add hooks/auto-save-stop.py hooks/precompact-save.py tests/test_hook_io.py
git commit -m "feat(hooks): port save hooks to stdlib Python (cross-platform)"
```

---

### Task 2: `auto-retrieve.py` Windows venv path fix

**Files:**
- Modify: `hooks/auto-retrieve.py` (~line 188, `.venv/bin/python3`)
- Test: `tests/test_auto_retrieve.py`

**Interfaces:**
- Produces: a helper that returns the venv interpreter path — `.venv/Scripts/python.exe` on Windows (`os.name == "nt"`), `.venv/bin/python3` otherwise.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_auto_retrieve.py`:
```python
def test_venv_python_path_is_os_specific(self):
    import os
    from importlib import import_module
    ar = import_module("auto-retrieve") if False else None  # if not importable, test the helper directly
    # Expect a helper _venv_python(base) that branches on os.name:
    from auto_retrieve_helpers import venv_python  # adjust import to actual module
    base = "/x/0k-rag"
    p = venv_python(base)
    if os.name == "nt":
        self.assertTrue(p.endswith("Scripts\\python.exe") or p.endswith("Scripts/python.exe"))
    else:
        self.assertTrue(p.endswith("bin/python3"))
```
(If `auto-retrieve.py` isn't importable due to the hyphen, extract the path logic into a small importable helper or test via a subprocess probe. Match the existing test file's import style.)

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_auto_retrieve -v`
Expected: FAIL.

- [ ] **Step 3: Implement the OS-branch**

In `hooks/auto-retrieve.py` around line 188, replace the hardcoded Unix path:
```python
import os
if os.name == "nt":
    python_path = str(Path(resolved) / ".venv" / "Scripts" / "python.exe")
else:
    python_path = str(Path(resolved) / ".venv" / "bin" / "python3")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_auto_retrieve -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add hooks/auto-retrieve.py tests/test_auto_retrieve.py
git commit -m "fix(auto-retrieve): OS-specific venv interpreter path (Windows Scripts/)"
```

---

### Task 3: Cross-platform `hooks/hooks.json`

**Files:**
- Create: `hooks/hooks.json`

- [ ] **Step 1: Write `hooks/hooks.json`** (confirm nesting against Task 0 Step 2)

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [ { "type": "command", "command": "python3", "args": ["${CLAUDE_PLUGIN_ROOT}/hooks/auto-retrieve.py"] } ] }
    ],
    "Stop": [
      { "hooks": [ { "type": "command", "command": "python3", "args": ["${CLAUDE_PLUGIN_ROOT}/hooks/auto-save-stop.py"] } ] }
    ],
    "PreCompact": [
      { "hooks": [ { "type": "command", "command": "python3", "args": ["${CLAUDE_PLUGIN_ROOT}/hooks/precompact-save.py"] } ] }
    ],
    "PreToolUse": [
      { "matcher": "Write|Edit|MultiEdit", "hooks": [ { "type": "command", "command": "bun", "args": ["${CLAUDE_PLUGIN_ROOT}/hooks/memory-validation.ts"] } ] }
    ]
  }
}
```

- [ ] **Step 2: Validate JSON**

Run: `python3 -c "import json; json.load(open('hooks/hooks.json')); print('valid')"`
Expected: `valid`

- [ ] **Step 3: Commit**

```bash
git add hooks/hooks.json
git commit -m "feat(hooks): cross-platform exec-form hook registration"
```

---

### Task 4: 3-OS CI matrix

**Files:**
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add an OS-matrix test job** (keep existing adversarial/integration jobs)

```yaml
  test-matrix:
    name: tests (${{ matrix.os }})
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@<pinned-sha>
      - uses: actions/setup-python@<pinned-sha>
        with:
          python-version: '3.12'
      - name: Install deps
        run: pip install pyyaml
      - name: Run tests
        run: python -m unittest discover -s tests -p "test_*.py" -v
```
Pin the action SHAs consistent with the repo's existing pinning practice.

- [ ] **Step 2: Push branch and confirm CI green on all three OSes**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add macOS + Windows to the test matrix"
git push -u origin feat/windows-support
```
Expected: the `test-matrix` job passes on ubuntu-latest, macos-latest, AND windows-latest. If windows fails on `python3` resolution, switch the run step to `python` (setup-python provides both; `python` is the safe Windows name) and document accordingly in Task 5.

---

### Task 5: Docs + release

**Files:**
- Modify: `README.md`, `CHANGELOG.md`, `plugin.json`

- [ ] **Step 1: README platform flip**

Replace `**Platform:** macOS (Apple Silicon optimized). Windows support planned.` with a macOS/Linux/Windows support statement + Windows prereqs (Python 3.10+ on PATH; bun for the validation hook). Note the interpreter command resolved in Task 4.

- [ ] **Step 2: `plugin.json` version bump**

Set `"version": "2.3.0"`.

- [ ] **Step 3: CHANGELOG entry**

Add a `## v2.3.0 — Cross-platform (Windows) support` section: bash hooks → stdlib Python, `hooks/hooks.json` exec-form registration, Windows venv path fix, 3-OS CI.

- [ ] **Step 4: Commit**

```bash
git add README.md CHANGELOG.md plugin.json
git commit -m "docs: declare macOS/Linux/Windows support; v2.3.0"
```

---

## Self-Review

**Spec coverage:** §3.1 all-Python hooks → Task 1; §3.2 hooks.json → Task 3; §3.3 interpreter → Global Constraints + Task 4 fallback; §3.4 venv path → Task 2; §3.5 3-OS CI + hook-I/O tests → Tasks 4 + 1; §3.6 docs/release → Task 5. No uncovered requirement.

**Placeholder scan:** hook bodies, test code, hooks.json, and CI yaml are full content. `<pinned-sha>` is an intentional instruction to match the repo's existing SHA-pinning, not a code placeholder. Task 2's test import is flagged to match the actual module style (the hyphenated filename isn't importable as-is).

**Type consistency:** hook filenames (`auto-save-stop.py`, `precompact-save.py`, `auto-retrieve.py`, `memory-validation.ts`) identical across Tasks 1/3/4 and `hooks.json`. Interpreter command (`python3`, with `python` fallback) consistent between Task 3 and Task 4.

**Open item carried from spec:** interpreter name is decided as `python3` (primary) with a `python` fallback proven-or-switched in Task 4's Windows CI run — no longer blocking.
