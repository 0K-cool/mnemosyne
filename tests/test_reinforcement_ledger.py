"""Tests for ReinforcementLedger — append-only usage sidecar (v2.2 time-aware ranking).

The ledger records which memories proved useful (appeared in a search's returned
top_k). It is append-only, stdlib-only, and defensive against a poisoned sidecar
(same trust boundary as MEMORY.md).
"""

import json
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from reinforcement_ledger import (  # noqa: E402
    ReinforcementLedger,
    MAX_LEDGER_LINES,
    LEDGER_FILENAME,
)


class TestReinforcementLedger(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.ledger = ReinforcementLedger(self.tmp)
        self.path = Path(self.tmp) / LEDGER_FILENAME

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- record / aggregate ---

    def test_record_appends_one_entry_per_source(self):
        self.ledger.record(["a.md", "b.md"])
        agg = self.ledger.aggregate()
        self.assertIn("a.md", agg)
        self.assertIn("b.md", agg)
        self.assertEqual(agg["a.md"]["access_count"], 1)

    def test_aggregate_counts_repeated_reinforcement(self):
        self.ledger.record(["a.md"])
        self.ledger.record(["a.md"])
        self.ledger.record(["a.md"])
        self.assertEqual(self.ledger.aggregate()["a.md"]["access_count"], 3)

    def test_aggregate_tracks_latest_ts(self):
        self.ledger.record(["a.md"])
        agg = self.ledger.aggregate()
        self.assertAlmostEqual(agg["a.md"]["last_reinforced"], time.time(), delta=5)

    def test_record_empty_list_is_noop(self):
        self.ledger.record([])
        self.assertEqual(self.ledger.aggregate(), {})

    # --- defensive reads ---

    def test_missing_file_empty_aggregate(self):
        self.assertEqual(self.ledger.aggregate(), {})

    def test_corrupt_lines_skipped(self):
        self.path.write_text(
            'not json\n'
            '{"source":"a.md","ts":123.0}\n'
            '{"source":"b.md"}\n'          # missing ts → skip
            '{"ts":5.0}\n'                 # missing source → skip
            '{"source":"c.md","ts":456.0}\n'
        )
        agg = self.ledger.aggregate()
        self.assertEqual(set(agg.keys()), {"a.md", "c.md"})

    def test_non_numeric_ts_skipped(self):
        self.path.write_text(
            '{"source":"a.md","ts":"abc"}\n'
            '{"source":"b.md","ts":100.0}\n'
        )
        agg = self.ledger.aggregate()
        self.assertNotIn("a.md", agg)
        self.assertIn("b.md", agg)

    def test_non_string_source_skipped(self):
        self.path.write_text('{"source":123,"ts":1.0}\n{"source":"ok.md","ts":1.0}\n')
        agg = self.ledger.aggregate()
        self.assertEqual(set(agg.keys()), {"ok.md"})

    def test_line_cap_enforced(self):
        with open(self.path, "w") as f:
            for _ in range(MAX_LEDGER_LINES + 500):
                f.write(json.dumps({"source": "x.md", "ts": 1.0}) + "\n")
        agg = self.ledger.aggregate()
        self.assertLessEqual(agg["x.md"]["access_count"], MAX_LEDGER_LINES)

    # --- best-effort writes ---

    def test_append_failure_swallowed(self):
        bad = ReinforcementLedger("/nonexistent/should/not/exist/xyz123")
        try:
            bad.record(["a.md"])
        except Exception as e:  # noqa: BLE001
            self.fail(f"record() must swallow write errors, raised: {e}")


if __name__ == "__main__":
    unittest.main()
