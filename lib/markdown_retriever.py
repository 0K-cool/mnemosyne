"""
MarkdownRetriever — Zero-dependency MEMORY.md-aware search.

Three-pass algorithm:
  Pass 1: Parse MEMORY.md index, score entries by BM25 with stemming.
  Pass 2: Read top candidate files, re-score by content BM25.
  Pass 3 (fallback): If Pass 1 finds too few candidates, scan all files directly.

Returns results in the standard MemoryResult format:
  {"source": str, "content": str, "score": float, "method": "markdown"}

Dependencies: Python stdlib only (re, pathlib, os, math, collections). No pip packages.
"""

import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import List, Dict, Optional


# ---------------------------------------------------------------------------
# Resource caps — v1.1.0 HIGH-1 / HIGH-2 (DoS / context stuffing)
# ---------------------------------------------------------------------------

# Per-file read cap on retrieval side. 5x the 50 KB write cap
# (memory-validation.ts MAX_FILE_SIZE_BYTES) — generous margin for legit
# long-form notes that may have slipped past write validation via git sync,
# editor saves, curl, or any non-Claude-Code write channel. Files over this
# cap are skipped during search (not truncated — silent truncation risks
# partial-content false matches).
MAX_RETRIEVE_BYTES = 256 * 1024

# Line cap on MEMORY.md parsing. A poisoned MEMORY.md with millions of
# entries would build a huge BM25 corpus and exhaust RAM before any top_k
# truncation. 5000 is well above realistic memory index sizes and below
# the point where the scoring loop becomes an attack surface.
MAX_INDEX_ENTRIES = 5000


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

# Suffix stemming rules — longest suffix first, min stem length 3
_STEM_RULES = [
    ("ational", "ate"), ("ization", "ize"), ("isation", "ize"),
    ("ations", "ate"), ("ation", "ate"), ("ating", "ate"),
    ("iveness", ""), ("fulness", ""), ("ousness", ""),
    ("ments", ""), ("ment", ""), ("ness", ""),
    ("ings", ""), ("ing", ""), ("tion", ""),
    ("ible", ""), ("able", ""),
    ("ious", ""), ("ous", ""), ("ive", ""),
    ("ers", ""), ("est", ""), ("ely", ""),
    ("er", ""), ("ly", ""), ("ed", ""),
    ("es", ""), ("s", ""),
]


def _stem(word: str) -> str:
    """Simple suffix stemmer. No dependencies."""
    for suffix, replacement in _STEM_RULES:
        if word.endswith(suffix) and len(word) - len(suffix) + len(replacement) >= 3:
            return word[:-len(suffix)] + replacement
    return word


def _tokenize(text: str) -> set:
    """Split text into a set of lowercased, stemmed, non-stop words."""
    words = set(_WORD_SPLIT.split(text.lower()))
    words.discard("")
    filtered = words - _STOP_WORDS
    return {_stem(w) for w in filtered}


def _tokenize_list(text: str) -> list:
    """Split text into a list of lowercased, stemmed, non-stop words (preserves count)."""
    words = _WORD_SPLIT.split(text.lower())
    return [_stem(w) for w in words if w and w not in _STOP_WORDS]


class _BM25:
    """Minimal BM25 scorer. Zero dependencies."""

    k1 = 1.5
    b = 0.5  # lower b for short docs (markdown files are typically short)

    def __init__(self, corpus: List[List[str]]):
        self.N = len(corpus) if corpus else 1
        self.avgdl = sum(len(d) for d in corpus) / self.N if corpus else 1
        self.df: Dict[str, int] = {}
        for doc in corpus:
            for term in set(doc):
                self.df[term] = self.df.get(term, 0) + 1

    def idf(self, term: str) -> float:
        df = self.df.get(term, 0)
        return math.log((self.N - df + 0.5) / (df + 0.5) + 1)

    def score(self, query_terms: set, doc_terms: list) -> float:
        tf = Counter(doc_terms)
        dl = len(doc_terms)
        total = 0.0
        for term in query_terms:
            if term not in tf:
                continue
            freq = tf[term]
            num = freq * (self.k1 + 1)
            den = freq + self.k1 * (1 - self.b + self.b * dl / self.avgdl)
            total += self.idf(term) * num / den
        return total


class MarkdownRetriever:
    """Zero-dependency MEMORY.md-aware retrieval for Mnemosyne."""

    def __init__(self, memory_dir: str):
        self.memory_dir = Path(memory_dir)
        self.memory_index_path = self.memory_dir / "MEMORY.md"

    def _safe_resolve_memory_path(self, rel_path: str):
        """Resolve MEMORY.md link target, rejecting anything that would
        escape self.memory_dir.

        Attack class: an attacker-written MEMORY.md with a link like
        `[surf](../../../.ssh/id_ed25519)` or `[x](/etc/hosts)` would
        previously cause parse_memory_index() to return an absolute
        path outside memory_dir, which downstream retrieval would then
        open() and inject into LLM context.

        Defense-in-depth layers:
          1. Reject absolute paths (`/...`) and home-relative (`~/...`)
          2. Require `.md` suffix (memory entries are markdown only)
          3. Reject explicit `..` traversal components before resolution
          4. After resolution, require the result to stay under memory_dir
             (handles symlinks pointing outside the dir)

        Returns Path on success, None on any rejection.
        """
        from pathlib import Path

        if not rel_path:
            return None
        # Reject absolute and home-relative
        if rel_path.startswith(("/", "~")):
            return None
        # Must be .md (memory entries only)
        if not rel_path.endswith(".md"):
            return None
        # Reject explicit traversal before resolving (cheap pre-check)
        # Split on both / and \ to catch Windows-style too
        parts = rel_path.replace("\\", "/").split("/")
        if ".." in parts:
            return None

        try:
            abs_path = (self.memory_dir / rel_path).resolve()
            memory_root = self.memory_dir.resolve()
        except (OSError, RuntimeError):
            return None

        # After resolution, verify the path is actually under memory_dir.
        # Covers symlink attacks where a file inside memory_dir links out.
        try:
            abs_path.relative_to(memory_root)
        except ValueError:
            return None

        return abs_path

    def parse_memory_index(self) -> List[Dict]:
        """Parse MEMORY.md into structured entries.
        Returns list of: {"title": str, "description": str, "file_path": str|None}
        """
        if not self.memory_index_path.exists():
            return []

        entries = []
        # Line-count cap — count INPUT LINES, not parsed entries
        # (CodeRabbit PR #4 finding). A poisoned MEMORY.md with millions
        # of non-matching junk lines would otherwise still scan end-to-end
        # since neither _LINK_PATTERN nor _BOLD_PATTERN would advance the
        # entry count past the budget.
        lines_read = 0
        with open(self.memory_index_path, "r", encoding="utf-8") as f:
            for line in f:
                lines_read += 1
                if lines_read > MAX_INDEX_ENTRIES:
                    break
                line = line.rstrip()

                m = _LINK_PATTERN.match(line)
                if m:
                    title, rel_path, description = m.group(1), m.group(2), m.group(3)
                    abs_path = self._safe_resolve_memory_path(rel_path)
                    entries.append({
                        "title": title,
                        "description": description.strip(),
                        "file_path": str(abs_path) if abs_path and abs_path.exists() else None,
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

    def _collect_file_entries(self, entries: List[Dict]) -> List[Dict]:
        """Return only entries that have readable file paths."""
        return [e for e in entries if e["file_path"] and os.path.exists(e["file_path"])]

    def search(self, query: str, top_k: int = 5) -> List[Dict]:
        """Three-pass MEMORY.md-aware search with BM25, stemming, and content fallback.
        Returns: [{"source": str, "content": str, "score": float, "method": "markdown"}]
        """
        query_words = _tokenize(query)
        if not query_words:
            return []

        entries = self.parse_memory_index()
        if not entries:
            return []

        # Build BM25 index from all entry descriptions + titles
        file_entries = self._collect_file_entries(entries)
        corpus = []
        for entry in entries:
            doc = _tokenize_list(entry["title"] + " " + entry["description"])
            corpus.append(doc)
        bm25 = _BM25(corpus)

        # Pass 1: Score index entries with BM25 (threshold lowered to 0.1)
        scored = []
        for i, entry in enumerate(entries):
            score = bm25.score(query_words, corpus[i])
            if score > 0.0:
                scored.append((entry, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        candidates = scored[: top_k * 4]

        # Pass 3 fallback: if too few candidates, add all file entries not already included
        if len(candidates) < top_k and file_entries:
            candidate_paths = {e["file_path"] for e, _ in candidates if e["file_path"]}
            for entry in file_entries:
                if entry["file_path"] not in candidate_paths:
                    candidates.append((entry, 0.0))

        # Pass 2: Read files and re-score with content BM25
        content_corpus = []
        content_entries = []
        for entry, index_score in candidates:
            file_path = entry["file_path"]
            if not (file_path and os.path.exists(file_path)):
                continue
            # Size-cap retrieval reads — see MAX_RETRIEVE_BYTES comment at top.
            # Files over the cap are skipped silently; a partial read would
            # risk false BM25 matches on truncated content.
            #
            # Per-file try/except (CodeRabbit PR #4 finding): getsize(), open(),
            # read(), and UTF-8 decode can all race after the exists() check
            # (delete/chmod race, malformed UTF-8, etc.). Skip the single bad
            # file rather than abort the whole search().
            try:
                if os.path.getsize(file_path) > MAX_RETRIEVE_BYTES:
                    continue
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read(MAX_RETRIEVE_BYTES)
            except (OSError, UnicodeDecodeError):
                continue
            content_corpus.append(_tokenize_list(content))
            content_entries.append((entry, index_score, content, file_path))

        if content_corpus:
            content_bm25 = _BM25(content_corpus)

        results = []
        for i, (entry, index_score, content, file_path) in enumerate(content_entries):
            content_score = content_bm25.score(query_words, content_corpus[i])
            # Combine: content matters more than index description
            combined_score = 0.3 * index_score + 0.7 * content_score
            best_paragraph = self._extract_best_paragraph(query_words, content)
            source = os.path.basename(file_path)

            if combined_score > 0.0:
                results.append({
                    "source": source,
                    "content": best_paragraph,
                    "score": round(min(combined_score, 1.0), 4),
                    "method": "markdown",
                })

        # Also include entries without files (bold-format, no file_path)
        for entry, index_score in candidates:
            if not entry["file_path"] and index_score > 0.0:
                results.append({
                    "source": entry["title"],
                    "content": entry["description"],
                    "score": round(min(index_score * 0.3, 1.0), 4),
                    "method": "markdown",
                })

        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:top_k]
