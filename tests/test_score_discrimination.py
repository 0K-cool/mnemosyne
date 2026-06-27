"""Score discrimination — v2.2.1 fix for BM25 cap saturation.

The previous retriever capped the combined score at min(score, 1.0). BM25 is
unbounded, so every multi-term match flattened to exactly 1.0 — on a
high-distractor corpus ~91% of top-k tied at 1.0 and ranking collapsed to
insertion order. The fix ranks on raw scores and max-normalizes only for the
[0,1] display contract.
"""

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from markdown_retriever import MarkdownRetriever  # noqa: E402


class TestScoreDiscrimination(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        mem = Path(self.tmp)
        (mem / "memory").mkdir()
        index = ["# Mem"]
        # Filler docs make the query terms RARE → high IDF → matching docs score
        # well above 1.0. Under the old min(.,1.0) cap they all flatten to 1.0
        # (the saturation tie); the fix must discriminate them.
        for i in range(18):
            (mem / "memory" / f"filler{i}.md").write_text(
                f"# Filler {i}\nunrelated padding words {i} text document content here")
            index.append(f"- [Filler {i}](memory/filler{i}.md) — padding words")
        (mem / "memory" / "strong.md").write_text(
            "# Strong\nalpha beta gamma alpha beta gamma alpha beta gamma")
        (mem / "memory" / "medium.md").write_text(
            "# Medium\nalpha beta alpha beta padding text here")
        (mem / "memory" / "weak.md").write_text(
            "# Weak\nalpha padding filler words content here more text")
        index += [
            "- [Strong](memory/strong.md) — alpha beta gamma",
            "- [Medium](memory/medium.md) — alpha beta",
            "- [Weak](memory/weak.md) — alpha",
        ]
        (mem / "MEMORY.md").write_text("\n".join(index) + "\n")
        self.retriever = MarkdownRetriever(memory_dir=self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _scored(self):
        return {r["source"]: r["score"]
                for r in self.retriever.search("alpha beta gamma", top_k=5,
                                               apply_decay=False, reinforce=False)}

    def test_scores_are_not_all_tied_at_one(self):
        """The core fix: results must NOT all collapse to 1.0."""
        s = self._scored()
        distinct = set(s.values())
        self.assertGreater(len(distinct), 1, f"scores collapsed to a tie: {s}")

    def test_stronger_match_scores_higher(self):
        s = self._scored()
        self.assertGreater(s["strong.md"], s["weak.md"])

    def test_strong_and_medium_not_tied_at_cap(self):
        # Both score >1.0 raw; the old cap flattened both to 1.0. The fix must
        # keep strong strictly above medium.
        s = self._scored()
        self.assertGreater(s["strong.md"], s["medium.md"])

    def test_all_scores_in_unit_range(self):
        for v in self._scored().values():
            self.assertGreaterEqual(v, 0.0)
            self.assertLessEqual(v, 1.0)

    def test_top_result_normalized_to_one(self):
        s = self._scored()
        self.assertAlmostEqual(max(s.values()), 1.0, places=4)

    def test_ranking_order_by_relevance(self):
        results = self.retriever.search("alpha beta gamma", top_k=5,
                                        apply_decay=False, reinforce=False)
        order = [r["source"] for r in results]
        self.assertEqual(order[0], "strong.md")
        self.assertLess(order.index("strong.md"), order.index("weak.md"))


if __name__ == "__main__":
    unittest.main()
