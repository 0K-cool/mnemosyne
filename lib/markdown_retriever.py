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
import time
from collections import Counter
from pathlib import Path
from typing import List, Dict, Optional

from reinforcement_ledger import ReinforcementLedger


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


# ---------------------------------------------------------------------------
# Time-aware ranking — v2.2
# ---------------------------------------------------------------------------
# Decay is a RANKING signal only, never storage. The recency factor is bounded
# [DECAY_FLOOR, 1.0] so it can only ever reduce a score, never inflate it above
# the honest BM25 content score. Constants are intentionally gentle: a security
# memory store values archival completeness, so old facts sink but never vanish.

DECAY_FLOOR = 0.5            # worst-case multiplier for a fully-decayed memory
BASE_HALF_LIFE_DAYS = 90     # half-life with zero reinforcement
MAX_HALF_LIFE_DAYS = 365     # cap: heavily-used memories fade no slower than this

# Query markers that force a flat, full-archive search (decay disabled). Any
# temporal / forensic / duration / ordering / recency question must not bias
# toward recent memories — its answer may live in an old memory.
#
# Bias note: a false POSITIVE here only forgoes decay's (small) upside on one
# query; a false NEGATIVE lets decay sink an old-but-correct answer and costs
# archival recall. So this set is deliberately generous.
_TEMPORAL_MARKERS = frozenset({
    "when", "first", "earliest", "latest", "recently", "recent", "lately",
    "ago", "before", "after", "between", "during", "since", "until",
    "prior", "previously", "initially", "originally", "history", "timeline",
    "ever", "earlier", "later", "duration", "elapsed", "passed",
    "oldest", "newest", "longest", "chronological",
})
_MONTH_NAMES = frozenset({
    "january", "february", "march", "april", "may", "june", "july",
    "august", "september", "october", "november", "december",
})
_DAYS_OF_WEEK = frozenset({
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "mondays", "tuesdays", "wednesdays", "thursdays", "fridays", "saturdays", "sundays",
    "weekday", "weekdays", "weekend", "weekends",
})
_ISO_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
# Phrase-level markers for cases where the trigger words are too common to put
# in the bare-word set (e.g. "order", "time", "last", "this").
_TEMPORAL_PHRASES = re.compile(
    r"how long|how many (day|week|month|year|hour|minute|time)|"
    r"\b(last|this|past|next) (week|month|year|night|time|day|spring|summer|fall|winter)\b|"
    r"most recent|what time|order of|in what order|sequence of"
)


def _half_life_days(access_count: int) -> float:
    """Half-life in days. Stretches with reinforcement (used often → fades
    slower), capped at MAX_HALF_LIFE_DAYS."""
    hl = BASE_HALF_LIFE_DAYS * (1 + math.log2(1 + max(0, access_count)))
    return min(hl, MAX_HALF_LIFE_DAYS)


def _decay_factor(age_days: float, access_count: int) -> float:
    """Exponential recency factor in [DECAY_FLOOR, 1.0]."""
    hl = _half_life_days(access_count)
    factor = DECAY_FLOOR + (1.0 - DECAY_FLOOR) * (0.5 ** (max(0.0, age_days) / hl))
    return max(DECAY_FLOOR, min(1.0, factor))


def _is_temporal_query(query: str) -> bool:
    """True when the query is temporal/forensic and decay should be disabled."""
    if not query:
        return False
    low = query.lower()
    if _ISO_DATE.search(low) or _TEMPORAL_PHRASES.search(low):
        return True
    words = set(_WORD_SPLIT.split(low))
    words.discard("")
    return (bool(words & _TEMPORAL_MARKERS)
            or bool(words & _MONTH_NAMES)
            or bool(words & _DAYS_OF_WEEK))


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
    # Low b for short docs: memory notes are uniformly short by nature, so
    # length-normalization (which penalizes longer-than-average docs) mostly
    # adds noise here. Elastic's short-doc guidance is b≈0.2–0.4.
    b = 0.3

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
        self._ledger = ReinforcementLedger(memory_dir)

    def _recency_factor(self, source: str, file_path: Optional[str],
                        ledger_agg: Dict[str, Dict], now: float) -> float:
        """Recency/usage multiplier in [DECAY_FLOOR, 1.0] for one result.

        Reference timestamp precedence:
          1. ledger last_reinforced (the memory has been used)
          2. file mtime (datable but never reinforced)
          3. neutral 1.0 (undatable bold entry — never penalized)
        """
        agg = ledger_agg.get(source)
        if agg:
            reference_ts = agg["last_reinforced"]
            access_count = agg["access_count"]
        else:
            access_count = 0
            if not file_path:
                return 1.0
            try:
                reference_ts = os.path.getmtime(file_path)
            except OSError:
                return 1.0
        age_days = (now - reference_ts) / 86400.0
        return _decay_factor(age_days, access_count)

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

    def search(self, query: str, top_k: int = 5,
               apply_decay: bool = True, reinforce: bool = False) -> List[Dict]:
        """Three-pass MEMORY.md-aware search with BM25, stemming, and content fallback.

        Time-aware ranking (v2.2): unless disabled, each result's score is
        multiplied by a recency/usage factor so fresh, frequently-pulled
        memories rank above dormant ones. Ranking only — nothing is hidden or
        deleted; the full archive is always one ``apply_decay=False`` search away.

        Args:
            query: search string.
            top_k: max results to return.
            apply_decay: when True (default), apply recency ranking — but
                auto-disabled for temporal/forensic queries. Pass False for
                audit/forensic retrieval that must search the archive flat.
            reinforce: when True, append a reinforcement event for each returned
                source. Defaults to False (no side effects); the auto-retrieve
                hook opts in so real session retrievals are the usage signal.

        Returns: [{"source": str, "content": str, "score": float, "method": "markdown"}]
        """
        query_words = _tokenize(query)
        if not query_words:
            return []

        now = time.time()
        decay_on = apply_decay and not _is_temporal_query(query)
        ledger_agg = self._ledger.aggregate() if decay_on else {}

        def _adjust(base_score: float, source: str, file_path: Optional[str]) -> float:
            if not decay_on:
                return base_score
            return base_score * self._recency_factor(source, file_path, ledger_agg, now)

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

        # Rank on RAW (uncapped) scores. BM25 is unbounded by design; the old
        # min(score, 1.0) cap flattened every strong multi-term match to exactly
        # 1.0, destroying discrimination (on a high-distractor store ~91% of
        # top-k tied at 1.0). The [0,1] display contract is restored by
        # max-normalizing AFTER ranking — never used for ordering.
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
                    "method": "markdown",
                    "_raw": _adjust(combined_score, source, file_path),
                })

        # Also include entries without files (bold-format, no file_path)
        for entry, index_score in candidates:
            if not entry["file_path"] and index_score > 0.0:
                results.append({
                    "source": entry["title"],
                    "content": entry["description"],
                    "method": "markdown",
                    "_raw": _adjust(index_score * 0.3, entry["title"], None),
                })

        results.sort(key=lambda x: x["_raw"], reverse=True)
        top = results[:top_k]

        # Max-normalize the returned set into [0,1] for the display score
        # contract (top result = 1.0). Sorted desc, so top[0] is the global max.
        if top:
            max_raw = top[0]["_raw"]
            for r in top:
                r["score"] = round(r["_raw"] / max_raw, 4) if max_raw > 0 else 0.0
                del r["_raw"]

        # Reinforce the returned set (opt-in; the auto-retrieve hook passes True).
        if reinforce and top:
            self._ledger.record([r["source"] for r in top])

        return top

    def staleness_candidates(self, threshold_factor: float = DECAY_FLOOR + 0.02,
                             max_access_count: int = 1) -> List[Dict]:
        """Memories whose recency factor sits at/under ``threshold_factor`` and
        whose ``access_count <= max_access_count``. Detect-and-report only —
        never reinforces, never rewrites. Feeds a future staleness-check workflow.
        """
        now = time.time()
        ledger_agg = self._ledger.aggregate()
        out: List[Dict] = []
        for entry in self.parse_memory_index():
            file_path = entry["file_path"]
            source = os.path.basename(file_path) if file_path else entry["title"]
            agg = ledger_agg.get(source)
            access_count = agg["access_count"] if agg else 0
            if access_count > max_access_count:
                continue
            factor = self._recency_factor(source, file_path, ledger_agg, now)
            if factor <= threshold_factor:
                out.append({
                    "source": source,
                    "last_reinforced": agg["last_reinforced"] if agg else None,
                    "factor": round(factor, 4),
                    "access_count": access_count,
                })
        return out
