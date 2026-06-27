"""Additive-λ recency — v2.2.1 redesign.

Replaces the multiplicative decay (`score × factor` in [0.5,1.0]) with an
additive tie-breaker: `final = content_norm + λ·recency`, where recency is a
[0,1] BONUS (fresh→1, old→0) — never a penalty. Boost relevant, never demote
old. The defining property: a strongly-matching OLD memory must outrank a
weakly-matching RECENT one (multiplicative violated this by halving the old
item's score below a weaker recent one).
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
    RECENCY_WEIGHT,
    _recency_signal,
    _half_life_days,
)


# ---------------------------------------------------------------------------
# Pure recency-signal math (additive model)
# ---------------------------------------------------------------------------

class TestRecencySignal(unittest.TestCase):
    def test_fresh_signal_is_one(self):
        self.assertAlmostEqual(_recency_signal(0, 0), 1.0, places=4)

    def test_ancient_signal_near_zero(self):
        # No floor in the additive model: old items get ~0 BONUS, not a penalty.
        self.assertLess(_recency_signal(3650, 0), 0.01)
        self.assertGreaterEqual(_recency_signal(3650, 0), 0.0)

    def test_signal_within_unit_range(self):
        for age in [0, 1, 30, 90, 365, 3650, 100000]:
            for ac in [0, 1, 10, 1000]:
                s = _recency_signal(age, ac)
                self.assertGreaterEqual(s, 0.0)
                self.assertLessEqual(s, 1.0)

    def test_reinforcement_raises_signal_at_same_age(self):
        self.assertGreater(_recency_signal(180, 50), _recency_signal(180, 0))

    def test_weight_is_small_tiebreaker(self):
        # λ must be small so recency only reorders near-ties, never overrides a
        # clearly-stronger content match.
        self.assertGreater(RECENCY_WEIGHT, 0.0)
        self.assertLessEqual(RECENCY_WEIGHT, 0.25)


# ---------------------------------------------------------------------------
# search() integration — the archival-recall-preserving property
# ---------------------------------------------------------------------------

class TestAdditiveSearch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        mem = Path(self.tmp)
        (mem / "memory").mkdir()
        index = ["# Mem"]
        # Filler raises IDF so content scores discriminate.
        for i in range(15):
            (mem / "memory" / f"f{i}.md").write_text(
                f"# F{i}\nunrelated padding words {i} content text here document")
            index.append(f"- [F{i}](memory/f{i}.md) — padding")
        # strong_old: all 3 query terms, repeated → high content. OLD.
        (mem / "memory" / "strong_old.md").write_text(
            "# Strong Old\nalpha beta gamma alpha beta gamma alpha beta gamma")
        # medium_recent: 2 terms → medium content. RECENT.
        (mem / "memory" / "medium_recent.md").write_text(
            "# Medium Recent\nalpha beta alpha beta padding text here")
        index += [
            "- [Strong Old](memory/strong_old.md) — alpha beta gamma",
            "- [Medium Recent](memory/medium_recent.md) — alpha beta",
        ]
        (mem / "MEMORY.md").write_text("\n".join(index) + "\n")
        now = time.time()
        old = now - 800 * 86400
        os.utime(mem / "memory" / "strong_old.md", (old, old))
        os.utime(mem / "memory" / "medium_recent.md", (now, now))
        self.retriever = MarkdownRetriever(memory_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _order(self, **kw):
        return [r["source"] for r in
                self.retriever.search("alpha beta gamma", top_k=10, reinforce=False, **kw)]

    def test_strong_old_beats_medium_recent(self):
        """THE defining property: content dominates; recency can't promote a
        weaker-but-recent memory over a clearly-stronger old one."""
        order = self._order()
        self.assertIn("strong_old.md", order)
        self.assertIn("medium_recent.md", order)
        self.assertLess(order.index("strong_old.md"), order.index("medium_recent.md"))

    def test_recency_breaks_ties_equal_content(self):
        """With equal content, the fresher memory wins (the legitimate use)."""
        mem = Path(self.tmp) / "memory"
        body = "delta epsilon delta epsilon padding"
        (mem / "tie_fresh.md").write_text("# TF\n" + body)
        (mem / "tie_old.md").write_text("# TO\n" + body)
        idx = (Path(self.tmp) / "MEMORY.md").read_text()
        idx += ("- [TF](memory/tie_fresh.md) — delta epsilon\n"
                "- [TO](memory/tie_old.md) — delta epsilon\n")
        (Path(self.tmp) / "MEMORY.md").write_text(idx)
        now = time.time()
        os.utime(mem / "tie_fresh.md", (now, now))
        os.utime(mem / "tie_old.md", (now - 800 * 86400, now - 800 * 86400))
        order = [r["source"] for r in
                 self.retriever.search("delta epsilon", top_k=10, reinforce=False)]
        self.assertLess(order.index("tie_fresh.md"), order.index("tie_old.md"))

    def test_apply_decay_false_is_pure_content(self):
        """No recency term when decay disabled → strong_old still wins on content."""
        order = self._order(apply_decay=False)
        self.assertLess(order.index("strong_old.md"), order.index("medium_recent.md"))

    def test_scores_in_unit_range(self):
        for r in self.retriever.search("alpha beta gamma", top_k=10, reinforce=False):
            self.assertGreaterEqual(r["score"], 0.0)
            self.assertLessEqual(r["score"], 1.0)


if __name__ == "__main__":
    unittest.main()
