"""ReinforcementLedger — append-only usage sidecar for v2.2 time-aware ranking.

Records which memories proved useful (appeared in a search's returned top_k) so
the retriever can weight ranking by recency *and* usage, without ever modifying
the memory files themselves.

Design properties:
  - Append-only JSONL at <memory_dir>/.reinforcement.jsonl (sibling to .audit.jsonl).
  - Pure stdlib (json, os, time, pathlib).
  - Best-effort writes: any OSError is swallowed so reinforcement never breaks search.
  - Defensive reads: the sidecar shares MEMORY.md's trust boundary and is treated
    as potentially poisoned — line/byte caps, per-line validation, skip-and-continue.

Dependencies: Python stdlib only.
"""

import json
import math
import os
import time
from pathlib import Path
from typing import Dict, List


LEDGER_FILENAME = ".reinforcement.jsonl"

# Read caps — a poisoned/huge ledger must not exhaust RAM. Mirrors the markdown
# retriever's MAX_INDEX_ENTRIES / MAX_RETRIEVE_BYTES posture.
MAX_LEDGER_LINES = 50_000
MAX_LEDGER_BYTES = 5 * 1024 * 1024  # 5 MB


class ReinforcementLedger:
    """Append-only reinforcement sidecar for one memory directory."""

    def __init__(self, memory_dir: str):
        self.memory_dir = Path(memory_dir)
        self.ledger_path = self.memory_dir / LEDGER_FILENAME

    def record(self, sources: List[str]) -> None:
        """Append one reinforcement event per source. Best-effort — never raises.

        A single batched write keeps interleaving with concurrent sessions
        minimal (each line < PIPE_BUF, so POSIX O_APPEND writes stay atomic).
        """
        if not sources:
            return
        now = time.time()
        try:
            lines = [
                json.dumps({"source": s, "ts": now}) + "\n"
                for s in sources
                if isinstance(s, str) and s
            ]
            if not lines:
                return
            with open(self.ledger_path, "a", encoding="utf-8") as f:
                f.write("".join(lines))
        except OSError:
            # Read-only FS, missing parent dir, etc. Reinforcement is an
            # enhancement, not a requirement — degrade silently.
            pass

    def aggregate(self) -> Dict[str, Dict]:
        """Fold the ledger into {source: {access_count, last_reinforced}}.

        Defensive against a poisoned sidecar: caps lines/bytes read, skips any
        malformed or schema-invalid line.
        """
        result: Dict[str, Dict] = {}
        if not self.ledger_path.exists():
            return result

        try:
            if os.path.getsize(self.ledger_path) > MAX_LEDGER_BYTES:
                # Read only up to the byte cap; a truncated final line is just
                # skipped by the per-line validation below.
                with open(self.ledger_path, "r", encoding="utf-8", errors="replace") as f:
                    blob = f.read(MAX_LEDGER_BYTES)
                lines = blob.splitlines()
            else:
                with open(self.ledger_path, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.read().splitlines()
        except OSError:
            return result

        for i, line in enumerate(lines):
            if i >= MAX_LEDGER_LINES:
                break
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(obj, dict):
                continue
            source = obj.get("source")
            ts = obj.get("ts")
            if not isinstance(source, str) or not source:
                continue
            # bool is a subclass of int — exclude it explicitly; require finite.
            if isinstance(ts, bool) or not isinstance(ts, (int, float)):
                continue
            if not math.isfinite(ts):
                continue

            entry = result.get(source)
            if entry is None:
                result[source] = {"access_count": 1, "last_reinforced": float(ts)}
            else:
                entry["access_count"] += 1
                if ts > entry["last_reinforced"]:
                    entry["last_reinforced"] = float(ts)

        return result
