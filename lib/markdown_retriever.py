"""
MarkdownRetriever — Zero-dependency MEMORY.md-aware search.

Two-pass algorithm:
  Pass 1: Parse MEMORY.md index, score entries by keyword overlap with query.
  Pass 2: Read top candidate files, re-score by content keyword density.

Returns results in the standard MemoryResult format:
  {"source": str, "content": str, "score": float, "method": "markdown"}

Dependencies: Python stdlib only (re, pathlib, os). No pip packages.
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Optional


# Matches: - [Title](path.md) — description
_LINK_PATTERN = re.compile(
    r"^-\s+\[([^\]]+)\]\(([^)]+)\)\s*[—–-]\s*(.+)$"
)

# Matches: - **Title** — description
_BOLD_PATTERN = re.compile(
    r"^-\s+\*\*([^*]+)\*\*\s*[—–-]\s*(.+)$"
)

# Word tokenizer: split on non-alphanumeric, lowercase
_WORD_SPLIT = re.compile(r"[^a-z0-9]+")

# Stop words to ignore in scoring
_STOP_WORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "shall",
    "should", "may", "might", "must", "can", "could", "of", "in", "to",
    "for", "with", "on", "at", "by", "from", "as", "into", "through",
    "during", "before", "after", "and", "but", "or", "nor", "not", "so",
    "yet", "both", "either", "neither", "each", "every", "all", "any",
    "few", "more", "most", "other", "some", "such", "no", "only", "own",
    "same", "than", "too", "very", "just", "about", "above", "below",
    "between", "up", "down", "out", "off", "over", "under", "again",
    "further", "then", "once", "here", "there", "when", "where", "why",
    "how", "what", "which", "who", "whom", "this", "that", "these",
    "those", "i", "me", "my", "we", "our", "you", "your", "he", "him",
    "his", "she", "her", "it", "its", "they", "them", "their",
})


def _tokenize(text: str) -> set:
    """Split text into a set of lowercased non-stop words."""
    words = set(_WORD_SPLIT.split(text.lower()))
    words.discard("")
    return words - _STOP_WORDS


class MarkdownRetriever:
    """Zero-dependency MEMORY.md-aware retrieval for Mnemosyne."""

    def __init__(self, memory_dir: str):
        self.memory_dir = Path(memory_dir)
        self.memory_index_path = self.memory_dir / "MEMORY.md"

    def parse_memory_index(self) -> List[Dict]:
        """Parse MEMORY.md into structured entries.
        Returns list of: {"title": str, "description": str, "file_path": str|None}
        """
        if not self.memory_index_path.exists():
            return []

        entries = []
        with open(self.memory_index_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip()

                m = _LINK_PATTERN.match(line)
                if m:
                    title, rel_path, description = m.group(1), m.group(2), m.group(3)
                    abs_path = (self.memory_dir / rel_path).resolve()
                    entries.append({
                        "title": title,
                        "description": description.strip(),
                        "file_path": str(abs_path) if abs_path.exists() else None,
                    })
                    continue

                m = _BOLD_PATTERN.match(line)
                if m:
                    title, description = m.group(1), m.group(2)
                    entries.append({
                        "title": title,
                        "description": description.strip(),
                        "file_path": None,
                    })
                    continue

        return entries

    def _score_entry(self, query_words: set, entry: Dict) -> float:
        if not query_words:
            return 0.0
        desc_words = _tokenize(entry["description"])
        title_words = _tokenize(entry["title"])
        desc_overlap = len(query_words & desc_words)
        title_overlap = len(query_words & title_words)
        weighted_overlap = desc_overlap + (title_overlap * 1.5)
        return weighted_overlap / len(query_words)

    def _score_content(self, query_words: set, content: str) -> float:
        if not query_words or not content:
            return 0.0
        content_words = _tokenize(content)
        overlap = len(query_words & content_words)
        return overlap / len(query_words)

    def _extract_best_paragraph(self, query_words: set, content: str, max_chars: int = 600) -> str:
        paragraphs = re.split(r"\n\s*\n", content)
        if not paragraphs:
            return content[:max_chars]

        best_para = ""
        best_density = -1.0

        for para in paragraphs:
            para = para.strip()
            if not para or len(para) < 20:
                continue
            para_words = _tokenize(para)
            if not para_words:
                continue
            overlap = len(query_words & para_words)
            density = overlap / len(para_words)
            if density > best_density:
                best_density = density
                best_para = para

        if not best_para:
            best_para = paragraphs[0].strip()
        if len(best_para) > max_chars:
            best_para = best_para[:max_chars] + "..."
        return best_para

    def search(self, query: str, top_k: int = 5) -> List[Dict]:
        """Two-pass MEMORY.md-aware search.
        Returns: [{"source": str, "content": str, "score": float, "method": "markdown"}]
        """
        query_words = _tokenize(query)
        if not query_words:
            return []

        entries = self.parse_memory_index()
        if not entries:
            return []

        # Pass 1: Score index entries
        scored = []
        for entry in entries:
            score = self._score_entry(query_words, entry)
            if score >= 0.2:
                scored.append((entry, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        candidates = scored[: top_k * 2]

        # Pass 2: Read files and re-score
        results = []
        for entry, index_score in candidates:
            file_path = entry["file_path"]

            if file_path and os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                content_score = self._score_content(query_words, content)
                combined_score = 0.4 * index_score + 0.6 * content_score
                best_paragraph = self._extract_best_paragraph(query_words, content)
                source = os.path.basename(file_path)
            else:
                combined_score = index_score * 0.4
                best_paragraph = entry["description"]
                source = entry["title"]

            if combined_score >= 0.2:
                results.append({
                    "source": source,
                    "content": best_paragraph,
                    "score": round(min(combined_score, 1.0), 4),
                    "method": "markdown",
                })

        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]
