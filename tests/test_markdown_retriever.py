"""Tests for MarkdownRetriever — zero-dep MEMORY.md-aware search."""

import os
import sys
import unittest
from pathlib import Path

# Add lib/ to path so we can import the retriever
sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from markdown_retriever import MarkdownRetriever


FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestMarkdownRetriever(unittest.TestCase):
    """Test the two-pass MEMORY.md-aware retrieval algorithm."""

    def setUp(self):
        self.retriever = MarkdownRetriever(memory_dir=str(FIXTURES_DIR))

    # --- Pass 1: MEMORY.md parsing ---

    def test_parse_memory_index_link_format(self):
        """Parse '- [Title](file.md) — description' lines."""
        entries = self.retriever.parse_memory_index()
        titles = [e["title"] for e in entries]
        self.assertIn("RSM Job Details", titles)
        self.assertIn("Surf Spots", titles)
        self.assertIn("ATHENA Bugs", titles)

    def test_parse_memory_index_bold_format(self):
        """Parse '- **Bold** — description' lines (no file link)."""
        entries = self.retriever.parse_memory_index()
        titles = [e["title"] for e in entries]
        self.assertIn("napoleontek", titles)

    def test_parse_memory_index_extracts_descriptions(self):
        """Descriptions are extracted after the em-dash."""
        entries = self.retriever.parse_memory_index()
        rsm = next(e for e in entries if e["title"] == "RSM Job Details")
        self.assertIn("cybersecurity compliance", rsm["description"])
        self.assertIn("May 2026", rsm["description"])

    def test_parse_memory_index_extracts_file_paths(self):
        """File paths are resolved relative to memory_dir."""
        entries = self.retriever.parse_memory_index()
        rsm = next(e for e in entries if e["title"] == "RSM Job Details")
        self.assertEqual(rsm["file_path"], str(FIXTURES_DIR / "memory" / "rsm-job.md"))

    def test_parse_bold_entry_has_no_file_path(self):
        """Bold-format entries without links have file_path=None."""
        entries = self.retriever.parse_memory_index()
        nap = next(e for e in entries if e["title"] == "napoleontek")
        self.assertIsNone(nap["file_path"])

    # --- Pass 1: Scoring ---

    def test_score_exact_keyword_match(self):
        """Query with exact keywords from description scores high."""
        results = self.retriever.search("RSM Puerto Rico cybersecurity", top_k=1)
        self.assertEqual(len(results), 1)
        self.assertIn("rsm-job", results[0]["source"])

    def test_score_partial_keyword_match(self):
        """Query with partial overlap still returns results."""
        results = self.retriever.search("surf spots Pine Grove", top_k=1)
        self.assertEqual(len(results), 1)
        self.assertIn("surf-spots", results[0]["source"])

    def test_score_no_match_returns_empty(self):
        """Query with zero keyword overlap returns empty list."""
        results = self.retriever.search("quantum computing blockchain", top_k=5)
        self.assertEqual(len(results), 0)

    def test_minimum_score_threshold(self):
        """Results below 0.2 score threshold are filtered out."""
        # "pizza" appears nowhere in fixtures
        results = self.retriever.search("pizza delivery schedule", top_k=5)
        for r in results:
            self.assertGreaterEqual(r["score"], 0.2)

    # --- Pass 2: Content search ---

    def test_content_search_improves_ranking(self):
        """Pass 2 content scan should find details not in MEMORY.md description."""
        # "HIPAA" is in rsm-job.md content but NOT in MEMORY.md description
        results = self.retriever.search("HIPAA compliance role", top_k=3)
        sources = [r["source"] for r in results]
        self.assertIn("rsm-job.md", sources[0])

    def test_content_extracts_relevant_paragraph(self):
        """Retrieved content should contain the most relevant text."""
        results = self.retriever.search("Pine Grove morning surf", top_k=1)
        self.assertIn("Pine Grove", results[0]["content"])

    # --- Interface contract ---

    def test_result_format(self):
        """Results match the MemoryResult interface."""
        results = self.retriever.search("ATHENA bugs beta test", top_k=1)
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertIn("source", r)
        self.assertIn("content", r)
        self.assertIn("score", r)
        self.assertIn("method", r)
        self.assertEqual(r["method"], "markdown")
        self.assertIsInstance(r["score"], float)
        self.assertGreater(r["score"], 0)
        self.assertLessEqual(r["score"], 1.0)

    def test_top_k_limits_results(self):
        """top_k parameter caps the number of results."""
        results = self.retriever.search("Puerto Rico", top_k=2)
        self.assertLessEqual(len(results), 2)

    def test_results_sorted_by_score_descending(self):
        """Results are returned highest score first."""
        results = self.retriever.search("Puerto Rico", top_k=5)
        if len(results) > 1:
            for i in range(len(results) - 1):
                self.assertGreaterEqual(results[i]["score"], results[i + 1]["score"])


if __name__ == "__main__":
    unittest.main()
