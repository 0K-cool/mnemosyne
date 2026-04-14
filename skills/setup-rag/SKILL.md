---
name: mnemosyne-setup-rag
description: |
  Bootstrap ok-rag for enhanced semantic retrieval. Guided 9-step setup:
  check Ollama, pull models, clone repo, install deps, generate config,
  wire MCP, health check, and index starter docs. Each step is idempotent.
  USE WHEN user says "/mnemosyne-setup-rag", "setup rag", "enable semantic search",
  "install ok-rag", or wants to upgrade from keyword to semantic retrieval.
---

# Setup RAG — Enhanced Retrieval Bootstrap

Upgrades Mnemosyne from keyword-based retrieval (~60% accuracy) to
semantic hybrid retrieval (100% accuracy on LongMemEval benchmark).

**Announce at start:** "Setting up ok-rag for enhanced semantic retrieval. This is a 9-step guided process — each step is idempotent, so you can re-run safely if anything fails."

## Prerequisites

- macOS or Linux
- Python 3.11+
- ~2.5GB free disk space (full install) or ~150MB (core install)
- Internet connection (for model downloads)

## Steps

Run each step in order. Check the health condition before proceeding. If the condition is already met, skip to the next step.

### Step 1: Check Ollama

**Health check:** Run `ollama --version` — should return version string.

If NOT installed:
- macOS: `brew install ollama`
- Linux: `curl -fsSL https://ollama.com/install.sh | sh`

After install, start the service:
- macOS: `ollama serve` (or it auto-starts via Homebrew)
- Linux: `systemctl start ollama` or `ollama serve`

Verify: `ollama --version` returns a version number.

### Step 2: Pull Embedding Model

**Health check:** `ollama list` includes `nomic-embed-text`.

```bash
ollama pull nomic-embed-text
```

This downloads ~274MB. Used for generating query and document embeddings.

### Step 3: Pull Context Generation Model

**Health check:** `ollama list` includes `llama3.2:1b`.

```bash
ollama pull llama3.2:1b
```

This downloads ~1.3GB. Used for generating contextual summaries during indexing.

### Step 4: Clone ok-rag

**Health check:** `~/tools/ok-rag/plugin.json` exists (or `~/tools/vex-rag/plugin.json` for legacy installs).

```bash
git clone https://github.com/0K-cool/ok-rag.git ~/tools/ok-rag
```

If user already has vex-rag at `~/tools/vex-rag`, that works too — set `MNEMOSYNE_RAG_PATH=~/tools/vex-rag`.

### Step 5: Create venv and Install Dependencies

**Health check:** `~/tools/ok-rag/.venv/bin/python -c "import lancedb; print('ok')"` prints "ok".

Ask the user which tier they want:

> **Core** (~150MB): Vector search + BM25 + fusion. ~88% retrieval accuracy.
> **Full** (~2.5GB, recommended): Adds BGE reranker + PII sanitization. 100% accuracy.

For **core**:
```bash
cd ~/tools/ok-rag
python3 -m venv .venv
.venv/bin/pip install -r requirements-core.txt
```

For **full** (recommended):
```bash
cd ~/tools/ok-rag
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

If pip fails with externally-managed-environment error, suggest:
```bash
python3 -m venv --system-site-packages .venv
```

### Step 6: Generate Configuration

**Health check:** `.vex-rag.yml` exists in the user's project root.

Create `.vex-rag.yml` in the project root with this template (fill in project-specific values):

```yaml
project:
  name: "{PROJECT_NAME}"

database:
  path: "{PROJECT_ROOT}/lance_vex_kb"

retrieval:
  enable_reranking: true
  reranker_model: "BAAI/bge-reranker-large"
  default_top_k: 5

indexing:
  enable_sanitization: false
  auto_index_paths:
    - "memory/"
  auto_index_extensions:
    - ".md"

security:
  allowed_base_paths:
    - "{PROJECT_ROOT}"

logging:
  level: "INFO"
  file: ".claude/logs/rag.log"
```

Replace `{PROJECT_NAME}` and `{PROJECT_ROOT}` with actual values.

### Step 7: Wire MCP Server

**Health check:** `.mcp.json` in project root contains `vex-knowledge-base` entry.

Add to `.mcp.json` (create if it doesn't exist):

```json
{
  "mcpServers": {
    "vex-knowledge-base": {
      "type": "stdio",
      "command": "{OK_RAG_PATH}/.venv/bin/python3",
      "args": ["-m", "mcp_server.vex_kb_server"],
      "env": {
        "RAG_CONFIG": "{PROJECT_ROOT}/.vex-rag.yml",
        "PYTHONPATH": "{OK_RAG_PATH}"
      }
    }
  }
}
```

Replace `{OK_RAG_PATH}` and `{PROJECT_ROOT}` with actual paths.

### Step 8: Health Check

**Verify end-to-end:**

1. Restart Claude Code (to pick up new MCP config)
2. Run: `search_kb("test query")` — should return results or empty list (not an error)
3. Run: `get_kb_stats()` — should return stats dict with `search_healthy: true`

If the MCP server fails to start:
- Check Ollama is running: `ollama list`
- Check Python path: `~/tools/ok-rag/.venv/bin/python3 -c "import lancedb"`
- Check config: `cat .vex-rag.yml`
- Check logs: `cat .claude/logs/rag.log`

### Step 9: Index Starter Documents

Index the user's memory files to populate the knowledge base:

```
index_document("memory/MEMORY.md")
```

Then index individual memory files that exist:
```
index_document("memory/lessons-learned.md")
```

After indexing, verify with a test search:
```
search_kb("what do I know about this project")
```

## Completion Message

After all steps pass:

> ok-rag is now active. Your retrieval accuracy has been upgraded from ~60% (keyword) to 100% (semantic hybrid).
>
> The auto-retrieve hook will automatically use ok-rag for future sessions. You can verify by checking the stderr output for `[mnemosyne] N results via vex-rag`.
>
> To re-run this setup: `/mnemosyne-setup-rag`
