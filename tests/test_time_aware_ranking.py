"""Tests for v2.2 time-aware retrieval ranking — decay math + search integration.

Decay is a RANKING signal only (never storage). The recency factor is bounded
[DECAY_FLOOR, 1.0] so it can only ever reduce a score, never inflate it above the
honest BM25 content score.
"""

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from markdown_retriever import (  # noqa: E402
    MarkdownRetriever,
    DECAY_FLOOR,
    BASE_HALF_LIFE_DAYS,
    MAX_HALF_LIFE_DAYS,
    _decay_factor,
    _half_life_days,
    _is_temporal_query,
)
from reinforcement_ledger import ReinforcementLedger  # noqa: E402


# ---------------------------------------------------------------------------
# Pure decay math
# ---------------------------------------------------------------------------

class TestDecayMath(unittest.TestCase):
    def test_fresh_factor_is_one(self):
        self.assertAlmostEqual(_decay_factor(0, 0), 1.0, places=4)

    def test_ancient_unreinforced_near_floor(self):
        f = _decay_factor(3650, 0)  # 10 years, never reinforced
        self.assertGreaterEqual(f, DECAY_FLOOR)
        self.assertLess(f, DECAY_FLOOR + 0.01)

    def test_factor_always_within_bounds(self):
        for age in [0, 1, 30, 90, 365, 3650, 100000]:
            for ac in [0, 1, 10, 1000, 10**6]:
                f = _decay_factor(age, ac)
                self.assertGreaterEqual(f, DECAY_FLOOR)
                self.assertLessEqual(f, 1.0)

    def test_reinforcement_slows_decay(self):
        # Same age, more reinforcement → higher (less-decayed) factor.
        self.assertGreater(_decay_factor(180, 50), _decay_factor(180, 0))

    def test_half_life_increases_with_access(self):
        self.assertGreater(_half_life_days(10), _half_life_days(0))

    def test_half_life_capped(self):
        self.assertLessEqual(_half_life_days(10**9), MAX_HALF_LIFE_DAYS)

    def test_base_half_life(self):
        self.assertEqual(_half_life_days(0), BASE_HALF_LIFE_DAYS)


# ---------------------------------------------------------------------------
# Temporal query detection
# ---------------------------------------------------------------------------

class TestTemporalDetection(unittest.TestCase):
    def test_when_first_history_are_temporal(self):
        for q in ["when did we start", "first contact", "project history",
                  "earliest record", "timeline of events", "since 2024",
                  "originally planned", "2026-06-07 incident"]:
            self.assertTrue(_is_temporal_query(q), f"should be temporal: {q}")

    def test_plain_query_not_temporal(self):
        for q in ["alpha widget", "surf spots puerto rico", "athena bugs"]:
            self.assertFalse(_is_temporal_query(q), f"should NOT be temporal: {q}")


# ---------------------------------------------------------------------------
# search() integration
# ---------------------------------------------------------------------------

class TestTimeAwareSearch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        mem = Path(self.tmp)
        (mem / "memory").mkdir()
        body = "alpha widget alpha widget project notes content"
        (mem / "memory" / "fresh.md").write_text("# Fresh\n" + body)
        (mem / "memory" / "stale.md").write_text("# Stale\n" + body)
        (mem / "MEMORY.md").write_text(
            "# Mem\n"
            "- [Fresh](memory/fresh.md) — alpha widget\n"
            "- [Stale](memory/stale.md) — alpha widget\n"
        )
        now = time.time()
        # fresh: age ~0; stale: 800 days old (decays well below the staleness floor)
        os.utime(mem / "memory" / "fresh.md", (now, now))
        old = now - 800 * 86400
        os.utime(mem / "memory" / "stale.md", (old, old))
        self.retriever = MarkdownRetriever(memory_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _scores(self, **kw):
        return {r["source"]: r["score"]
                for r in self.retriever.search("alpha widget", top_k=5, **kw)}

    def test_fresh_outranks_stale_equal_content(self):
        results = self.retriever.search("alpha widget", top_k=5, reinforce=False)
        sources = [r["source"] for r in results]
        self.assertIn("fresh.md", sources)
        self.assertIn("stale.md", sources)
        self.assertLess(sources.index("fresh.md"), sources.index("stale.md"))

    def test_no_decay_equal_content_equal_score(self):
        s = self._scores(apply_decay=False, reinforce=False)
        self.assertAlmostEqual(s["fresh.md"], s["stale.md"], places=4)

    def test_decay_penalizes_stale_not_fresh(self):
        decayed = self._scores(apply_decay=True, reinforce=False)
        flat = self._scores(apply_decay=False, reinforce=False)
        self.assertLess(decayed["stale.md"], flat["stale.md"])
        self.assertAlmostEqual(decayed["fresh.md"], flat["fresh.md"], places=3)

    def test_temporal_marker_auto_disables_decay(self):
        # "history" marks the query temporal → decay must be auto-disabled,
        # so stale's score matches the explicit apply_decay=False score.
        auto = {r["source"]: r["score"]
                for r in self.retriever.search("alpha widget history", top_k=5, reinforce=False)}
        flat = {r["source"]: r["score"]
                for r in self.retriever.search("alpha widget history", top_k=5,
                                               apply_decay=False, reinforce=False)}
        self.assertAlmostEqual(auto["stale.md"], flat["stale.md"], places=4)

    # --- reinforcement side effects ---

    def test_reinforce_true_writes_events(self):
        self.retriever.search("alpha widget", top_k=5, reinforce=True)
        agg = ReinforcementLedger(self.tmp).aggregate()
        self.assertIn("fresh.md", agg)

    def test_reinforce_default_is_false(self):
        # Library default must not mutate state.
        self.retriever.search("alpha widget", top_k=5)
        self.assertEqual(ReinforcementLedger(self.tmp).aggregate(), {})

    def test_reinforce_false_writes_nothing(self):
        self.retriever.search("alpha widget", top_k=5, reinforce=False)
        self.assertEqual(ReinforcementLedger(self.tmp).aggregate(), {})

    # --- staleness feed ---

    def test_staleness_candidates_flags_stale_only(self):
        cands = self.retriever.staleness_candidates()
        sources = [c["source"] for c in cands]
        self.assertIn("stale.md", sources)
        self.assertNotIn("fresh.md", sources)

    def test_staleness_scan_does_not_reinforce(self):
        self.retriever.staleness_candidates()
        self.assertEqual(ReinforcementLedger(self.tmp).aggregate(), {})

    def test_reinforcement_lifts_a_stale_memory(self):
        # Reinforce stale.md many times → its half-life stretches → it should
        # rank closer to fresh than before.
        before = self._scores(apply_decay=True, reinforce=False)["stale.md"]
        ledger = ReinforcementLedger(self.tmp)
        for _ in range(20):
            ledger.record(["stale.md"])
        # Note: last_reinforced is now ~now, so stale.md is effectively fresh.
        after = self._scores(apply_decay=True, reinforce=False)["stale.md"]
        self.assertGreater(after, before)


if __name__ == "__main__":
    unittest.main()
