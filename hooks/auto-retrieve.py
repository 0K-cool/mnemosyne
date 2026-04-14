#!/usr/bin/env python3
"""
auto-retrieve.py — Dual-mode UserPromptSubmit hook for Mnemosyne.

On every substantive user prompt, this hook:
  1. Searches memory for relevant context (RAG or Markdown fallback)
  2. Injects results as additionalContext before the AI sees the prompt

Modes:
  RAG mode   — uses lancedb + nomic-embed-text via vex-rag/ok-rag (semantic)
  Fallback   — uses MarkdownRetriever (keyword, zero dependencies)

Graceful degradation: any failure falls back or silently passes the prompt through.
"""

import sys
import os
import json
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

MIN_QUERY_LENGTH = 30           # Skip trivially short prompts ("yes", "ok", "do it")
MAX_SESSION_SEARCHES = 3        # Limit auto-searches per session to avoid noise
MAX_RESULTS = 3                 # Results injected per search
MAX_CONTEXT_CHARS = 2000        # Cap total injected context length

STATE_DIR = Path(os.path.expanduser("~/.mnemosyne/state"))

# ---------------------------------------------------------------------------
# Session search counter (persists in STATE_DIR for the session lifetime)
# ---------------------------------------------------------------------------

def _state_file(session_id: str) -> Path:
    return STATE_DIR / f"auto-retrieve-{session_id}.count"


def get_session_search_count(session_id: str) -> int:
    try:
        return int(_state_file(session_id).read_text().strip())
    except Exception:
        return 0


def increment_session_search_count(session_id: str) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        current = get_session_search_count(session_id)
        _state_file(session_id).write_text(str(current + 1))
    except Exception:
        pass  # Non-fatal


# ---------------------------------------------------------------------------
# Memory directory detection
# ---------------------------------------------------------------------------

def find_memory_dir() -> str | None:
    """
    Locate the memory directory in priority order:
      1. MNEMOSYNE_MEMORY_DIR env var
      2. Walk from cwd upward looking for MEMORY.md
    """
    from_env = os.environ.get("MNEMOSYNE_MEMORY_DIR", "")
    if from_env and Path(from_env).is_dir():
        return from_env

    # Walk cwd and parents looking for MEMORY.md
    candidate = Path.cwd()
    for _ in range(10):  # cap traversal depth
        if (candidate / "MEMORY.md").exists():
            return str(candidate)
        if (candidate / "memory" / "MEMORY.md").exists():
            return str(candidate / "memory")
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent

    return None


# ---------------------------------------------------------------------------
# RAG availability probe
# ---------------------------------------------------------------------------

def detect_rag() -> tuple[bool, str, str]:
    """
    Return (available, rag_path, python_path).

    Priority:
      1. MNEMOSYNE_RAG_ENABLED=true + MNEMOSYNE_RAG_PATH or ~/tools/ok-rag
      2. VEX_RAG_PATH or ~/tools/vex-rag (venv python probe)
    """
    rag_enabled_env = os.environ.get("MNEMOSYNE_RAG_ENABLED", "").lower() == "true"

    # Explicit enable via env
    if rag_enabled_env:
        rag_path = os.environ.get(
            "MNEMOSYNE_RAG_PATH",
            os.path.expanduser("~/tools/ok-rag")
        )
        python_path = str(Path(rag_path) / ".venv" / "bin" / "python3")
        if Path(python_path).exists():
            return True, rag_path, python_path
        # Env var said enabled but venv missing — try vex-rag fallback below

    # Probe ok-rag
    ok_rag_path = os.environ.get(
        "MNEMOSYNE_RAG_PATH",
        os.path.expanduser("~/tools/ok-rag")
    )
    ok_python = str(Path(ok_rag_path) / ".venv" / "bin" / "python3")
    if Path(ok_python).exists():
        return True, ok_rag_path, ok_python

    # Probe vex-rag
    vex_rag_path = os.environ.get(
        "VEX_RAG_PATH",
        os.path.expanduser("~/tools/vex-rag")
    )
    vex_python = str(Path(vex_rag_path) / ".venv" / "bin" / "python3")
    if Path(vex_python).exists():
        return True, vex_rag_path, vex_python

    return False, "", ""


# ---------------------------------------------------------------------------
# RAG search — vector search via lancedb + Embedder
# ---------------------------------------------------------------------------

def search_rag(query: str, rag_path: str, top_k: int = MAX_RESULTS) -> list:
    """
    Import lancedb and vex-rag/ok-rag modules directly, run vector search.

    Returns list of formatted strings or empty list on any failure.
    """
    try:
        if rag_path not in sys.path:
            sys.path.insert(0, rag_path)

        import lancedb
        from rag.indexing.embedder import Embedder

        db_path = os.path.expanduser("~/Personal_AI_Infrastructure/lance_vex_kb")
        db = lancedb.connect(db_path)

        try:
            table = db.open_table("knowledge_base")
        except Exception:
            return []

        embedder = Embedder(model="nomic-embed-text")
        query_vec = embedder.embed(query)
        if query_vec is None:
            return []

        results = (
            table.search(query_vec, vector_column_name="vector")
            .limit(top_k)
            .to_list()
        )

        formatted = []
        for r in results:
            source = r.get("source_file", "unknown")
            project = r.get("source_project", "unknown")
            content = r.get("original_chunk", "")
            if len(content) > 600:
                content = content[:600] + "..."
            formatted.append(f"[{source} ({project})]: {content}")

        return formatted

    except Exception:
        return []


# ---------------------------------------------------------------------------
# Markdown fallback search
# ---------------------------------------------------------------------------

def search_markdown(query: str, memory_dir: str, top_k: int = MAX_RESULTS) -> list:
    """
    Zero-dependency keyword search via MarkdownRetriever.
    Locates the lib/ directory relative to this hook's location.
    """
    try:
        hook_dir = Path(__file__).parent
        lib_dir = str(hook_dir.parent / "lib")
        if lib_dir not in sys.path:
            sys.path.insert(0, lib_dir)

        from markdown_retriever import MarkdownRetriever

        retriever = MarkdownRetriever(memory_dir)
        results = retriever.search(query, top_k=top_k)

        formatted = []
        for r in results:
            source = r.get("source", "memory")
            content = r.get("content", "")
            formatted.append(f"[{source}]: {content}")

        return formatted

    except Exception:
        return []


# ---------------------------------------------------------------------------
# Prompt extraction
# ---------------------------------------------------------------------------

def extract_prompt(event: dict) -> str:
    """Extract the user prompt text from various UserPromptSubmit event shapes."""
    prompt = event.get("prompt", "")
    if prompt:
        return prompt

    message = event.get("message", {})
    if isinstance(message, dict):
        content = message.get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    return block.get("text", "")

    return ""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    start = time.time()

    # Read stdin
    try:
        raw = sys.stdin.read()
    except Exception:
        print(json.dumps({"continue": True}))
        return

    if not raw.strip():
        print(json.dumps({"continue": True}))
        return

    # Parse event
    try:
        event = json.loads(raw)
    except Exception:
        print(json.dumps({"continue": True}))
        return

    if not isinstance(event, dict):
        print(json.dumps({"continue": True}))
        return

    # Extract prompt
    prompt = extract_prompt(event)
    if not prompt or len(prompt) < MIN_QUERY_LENGTH:
        print(json.dumps({"continue": True}))
        return

    # Session search limit
    session_id = event.get(
        "session_id",
        os.environ.get("CLAUDE_CODE_SESSION_ID", "unknown")
    )
    if get_session_search_count(session_id) >= MAX_SESSION_SEARCHES:
        print(json.dumps({"continue": True}))
        return

    # Locate memory dir (needed for markdown fallback label)
    memory_dir = find_memory_dir()

    # Try RAG first, fall back to Markdown
    results = []
    method = "none"

    rag_available, rag_path, _ = detect_rag()

    if rag_available:
        try:
            results = search_rag(prompt, rag_path)
            if results:
                method = "rag"
        except Exception:
            results = []

    if not results and memory_dir:
        try:
            results = search_markdown(prompt, memory_dir)
            if results:
                method = "markdown"
        except Exception:
            results = []

    elapsed = time.time() - start

    if not results:
        print(json.dumps({"continue": True}))
        return

    # Build additionalContext (cap at MAX_CONTEXT_CHARS)
    context_parts = ["[Mnemosyne Auto-Retrieved]"]
    total_chars = 0
    included = 0
    for r in results:
        if total_chars + len(r) > MAX_CONTEXT_CHARS:
            break
        context_parts.append(r)
        total_chars += len(r)
        included += 1

    context = "\n\n".join(context_parts)

    # Track search
    increment_session_search_count(session_id)
    search_num = get_session_search_count(session_id)

    # Progress line on stderr
    print(
        f"[mnemosyne] {included} results via {method} in {elapsed:.1f}s"
        f" (search #{search_num}/{MAX_SESSION_SEARCHES})",
        file=sys.stderr
    )

    print(json.dumps({
        "continue": True,
        "additionalContext": context,
    }))


if __name__ == "__main__":
    main()
