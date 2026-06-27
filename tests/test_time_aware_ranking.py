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
    BASE_HALF_LIFE_DAYS,
    MAX_HALF_LIFE_DAYS,
    _half_life_days,
    _is_temporal_query,
)
from reinforcement_ledger import ReinforcementLedger  # noqa: E402

# Recency-signal math (additive model) lives in test_additive_recency.py.
# This file keeps the half-life, temporal-detection, search-integration,
# reinforcement, and staleness coverage.


class TestHalfLife(unittest.TestCase):
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

    def test_duration_ordering_recency_phrasings(self):
        # Real LongMemEval temporal-reasoning phrasings the original detector
        # missed (54% false-negative rate). These must disable decay.
        for q in [
            "How many days had passed between the two events?",
            "How many weeks ago did I attend the sale?",
            "How many months ago did I book the Airbnb?",
            "How long did it take to find a house I loved?",
            "How long have I been working before my current job?",
            "Which streaming service did I start using most recently?",
            "Which pair of shoes did I clean last month?",
            "What time do I wake up on Tuesdays and Thursdays?",
            "What is the order of the three events I described?",
            "How many days before the festival did I participate?",
            "How many days did it take after starting?",
        ]:
            self.assertTrue(_is_temporal_query(q), f"should be temporal: {q}")

    def test_plain_query_not_temporal(self):
        # Genuinely non-temporal queries must NOT be flagged (else decay no-ops).
        for q in ["alpha widget", "surf spots puerto rico", "athena bugs",
                  "what is my favorite restaurant", "which laptop did I buy",
                  "my preferred coffee order"]:
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

    def test_recency_boosts_fresh_above_stale(self):
        # Additive model: fresh earns a recency bonus, so after display
        # normalization its score is 1.0 and the (unboosted) stale entry sits
        # relatively lower — without stale's raw content score being penalized.
        decayed = self._scores(apply_decay=True, reinforce=False)
        flat = self._scores(apply_decay=False, reinforce=False)
        self.assertGreater(decayed["fresh.md"], decayed["stale.md"])
        self.assertLess(decayed["stale.md"], flat["stale.md"])

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
