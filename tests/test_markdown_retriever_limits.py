"""Size/line-count limit tests for MarkdownRetriever — v1.1.0 HIGH-1/2.

HIGH-1 / F-03: unbounded f.read() on retrieval — 100MB file OOMs the hook.
HIGH-2 / F-11: unbounded parse_memory_index() — 10M-line MEMORY.md exhausts RAM.

Both are realistic via any non-Claude-Code write path (git, curl, editor) that
bypasses memory-validation.ts's 50KB write cap.

Security mapping:
  OWASP LLM10 (Unbounded Consumption), ATLAS AML.T0029 (DoS)
"""

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

LIB_DIR = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(LIB_DIR))

markdown_retriever = importlib.import_module("markdown_retriever")


class TestMaxRetrieveBytes(unittest.TestCase):
    """HIGH-1 / F-03 — read-side size cap on per-file content."""

    def test_max_retrieve_bytes_constant_exists(self):
        self.assertTrue(
            hasattr(markdown_retriever, "MAX_RETRIEVE_BYTES"),
            "MarkdownRetriever must expose MAX_RETRIEVE_BYTES constant",
        )
        # 256 KB chosen per spec — 5× the 50KB write cap, generous margin
        # for legitimate long-form memory files that bypassed write validation.
        self.assertEqual(markdown_retriever.MAX_RETRIEVE_BYTES, 256 * 1024)

    def test_oversized_file_skipped(self):
        """A file larger than MAX_RETRIEVE_BYTES must be skipped during search,
        not read, tokenised, or returned."""
        with tempfile.TemporaryDirectory() as tmpdir:
            memory_dir = Path(tmpdir)
            # Create MEMORY.md pointing to a huge file
            huge_file = memory_dir / "huge.md"
            # 512 KB — 2× cap
            huge_file.write_text("surf ATHENA bug\n" * (512 * 1024 // 16))
            (memory_dir / "MEMORY.md").write_text(
                "- [Huge File](huge.md) — contains surf and ATHENA keywords\n"
            )

            retriever = markdown_retriever.MarkdownRetriever(str(memory_dir))
            # Query that would match the huge file content
            results = retriever.search("surf ATHENA", top_k=5)

            # The file was over cap — must not appear in results.
            for r in results:
                self.assertNotEqual(
                    r.get("source"),
                    "huge.md",
                    "Oversized file leaked into retrieval results",
                )

    def test_under_cap_file_included(self):
        """Sanity: a file under the cap must still be read and returned."""
        with tempfile.TemporaryDirectory() as tmpdir:
            memory_dir = Path(tmpdir)
            normal_file = memory_dir / "normal.md"
            # ~1 KB — well under cap
            normal_file.write_text(
                "RSM Puerto Rico cybersecurity consulting role details.\n"
                "Starts May 2026. Transition from napoleontek in progress.\n"
            )
            (memory_dir / "MEMORY.md").write_text(
                "- [RSM Details](normal.md) — Puerto Rico cybersecurity role\n"
            )
            retriever = markdown_retriever.MarkdownRetriever(str(memory_dir))
            results = retriever.search("RSM Puerto Rico", top_k=5)
            self.assertGreater(len(results), 0)


class TestMemoryIndexLineCap(unittest.TestCase):
    """HIGH-2 / F-11 — MEMORY.md line-count cap."""

    def test_max_index_entries_constant_exists(self):
        self.assertTrue(
            hasattr(markdown_retriever, "MAX_INDEX_ENTRIES"),
            "MarkdownRetriever must expose MAX_INDEX_ENTRIES constant",
        )
        # 5000 chosen per spec — realistic upper bound on legitimate memory
        # index size, well below the point where BM25 scoring exhausts RAM.
        self.assertEqual(markdown_retriever.MAX_INDEX_ENTRIES, 5000)

    def test_index_truncated_at_cap(self):
        """parse_memory_index() must stop after MAX_INDEX_ENTRIES entries
        even if MEMORY.md contains more."""
        with tempfile.TemporaryDirectory() as tmpdir:
            memory_dir = Path(tmpdir)
            # Write MEMORY.md with 2× the cap number of link entries
            lines = [
                f"- [Entry {i}](entry{i}.md) — description for entry {i}\n"
                for i in range(markdown_retriever.MAX_INDEX_ENTRIES * 2)
            ]
            (memory_dir / "MEMORY.md").write_text("".join(lines))

            retriever = markdown_retriever.MarkdownRetriever(str(memory_dir))
            entries = retriever.parse_memory_index()
            self.assertEqual(
                len(entries),
                markdown_retriever.MAX_INDEX_ENTRIES,
                "parse_memory_index must cap at MAX_INDEX_ENTRIES",
            )

    def test_short_index_unaffected(self):
        """Sanity: an index with < MAX_INDEX_ENTRIES returns all its entries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            memory_dir = Path(tmpdir)
            # 10 entries — well under cap
            lines = [
                f"- [Entry {i}](entry{i}.md) — desc {i}\n"
                for i in range(10)
            ]
            (memory_dir / "MEMORY.md").write_text("".join(lines))
            retriever = markdown_retriever.MarkdownRetriever(str(memory_dir))
            entries = retriever.parse_memory_index()
            self.assertEqual(len(entries), 10)


if __name__ == "__main__":
    unittest.main()
