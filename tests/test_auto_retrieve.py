"""Unit tests for auto-retrieve.py hook internals."""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Add hooks/ to path so we can import auto-retrieve as a module
HOOKS_DIR = Path(__file__).parent.parent / "hooks"
sys.path.insert(0, str(HOOKS_DIR))

# Import with underscore name since the file has a hyphen
import importlib
auto_retrieve = importlib.import_module("auto-retrieve")

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestDetectRag(unittest.TestCase):
    """Test RAG availability detection logic.

    v1.1.0 HIGH-3 tightening: detect_rag now applies _is_rag_path_allowed()
    which only accepts paths under ~/tools or ~/.mnemosyne. Tests that use
    tempfile.TemporaryDirectory() (which lands in /var/folders on macOS)
    patch the allowlist to also include the tempdir prefix, so legitimate
    detection logic still gets exercised in CI environments.
    """

    def _patch_allowlist(self, extra_prefix: Path):
        """Add extra_prefix to _RAG_ALLOWED_PREFIXES for the duration of
        a single test. Returns the patcher so the test can call .start()/
        .stop() — preferred pattern for compatibility with unittest.
        """
        return patch.object(
            auto_retrieve,
            "_RAG_ALLOWED_PREFIXES",
            auto_retrieve._RAG_ALLOWED_PREFIXES + (extra_prefix,),
        )

    def test_returns_true_when_env_enabled_and_venv_exists(self):
        """RAG detected when MNEMOSYNE_RAG_ENABLED=true and .venv exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            venv_python = Path(tmpdir) / ".venv" / "bin" / "python3"
            venv_python.parent.mkdir(parents=True)
            venv_python.touch()
            with self._patch_allowlist(Path(tmpdir).parent), \
                    patch.dict(os.environ, {
                        "MNEMOSYNE_RAG_ENABLED": "true",
                        "MNEMOSYNE_RAG_PATH": tmpdir,
                    }):
                available, rag_path, python_path = auto_retrieve.detect_rag()
                self.assertTrue(available)
                self.assertEqual(rag_path, tmpdir)
                self.assertEqual(python_path, str(venv_python))

    def test_returns_false_when_env_not_set(self):
        """RAG not detected when no env vars set and no default paths exist."""
        with patch.dict(os.environ, {
            "MNEMOSYNE_RAG_ENABLED": "",
            "MNEMOSYNE_RAG_PATH": "/nonexistent/rag/path",
            "VEX_RAG_PATH": "/nonexistent/vex/path",
        }, clear=False):
            available, _, _ = auto_retrieve.detect_rag()
            self.assertFalse(available)

    def test_returns_false_when_venv_missing(self):
        """RAG not detected when env says enabled but .venv doesn't exist."""
        with patch.dict(os.environ, {
            "MNEMOSYNE_RAG_ENABLED": "true",
            "MNEMOSYNE_RAG_PATH": "/nonexistent/no/venv/here",
            "VEX_RAG_PATH": "/nonexistent/either",
        }):
            available, _, _ = auto_retrieve.detect_rag()
            self.assertFalse(available)

    def test_probes_ok_rag_path_without_explicit_enable(self):
        """Probes ~/tools/0k-rag even without MNEMOSYNE_RAG_ENABLED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            venv_python = Path(tmpdir) / ".venv" / "bin" / "python3"
            venv_python.parent.mkdir(parents=True)
            venv_python.touch()
            with self._patch_allowlist(Path(tmpdir).parent), \
                    patch.dict(os.environ, {
                        "MNEMOSYNE_RAG_ENABLED": "",
                        "MNEMOSYNE_RAG_PATH": tmpdir,
                        "VEX_RAG_PATH": "/nonexistent",
                    }):
                available, rag_path, _ = auto_retrieve.detect_rag()
                self.assertTrue(available)
                self.assertEqual(rag_path, tmpdir)

    def test_falls_back_to_vex_rag_path(self):
        """Falls back to VEX_RAG_PATH when ok-rag not found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            venv_python = Path(tmpdir) / ".venv" / "bin" / "python3"
            venv_python.parent.mkdir(parents=True)
            venv_python.touch()
            with self._patch_allowlist(Path(tmpdir).parent), \
                    patch.dict(os.environ, {
                        "MNEMOSYNE_RAG_ENABLED": "",
                        "MNEMOSYNE_RAG_PATH": "/nonexistent/ok-rag",
                        "VEX_RAG_PATH": tmpdir,
                    }):
                available, rag_path, _ = auto_retrieve.detect_rag()
                self.assertTrue(available)
                self.assertEqual(rag_path, tmpdir)


class TestFindMemoryDir(unittest.TestCase):
    """Test memory directory location logic."""

    def test_respects_env_var(self):
        """MNEMOSYNE_MEMORY_DIR env var takes priority."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"MNEMOSYNE_MEMORY_DIR": tmpdir}):
                result = auto_retrieve.find_memory_dir()
                self.assertEqual(result, tmpdir)

    def test_walks_up_to_find_memory_md(self):
        """Walks cwd upward to find MEMORY.md."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "MEMORY.md").touch()
            subdir = Path(tmpdir) / "a" / "b"
            subdir.mkdir(parents=True)
            with patch.dict(os.environ, {"MNEMOSYNE_MEMORY_DIR": ""}, clear=False):
                orig_cwd = os.getcwd()
                try:
                    os.chdir(subdir)
                    result = auto_retrieve.find_memory_dir()
                    # Resolve both sides: macOS /var is a symlink to /private/var
                    self.assertEqual(
                        Path(result).resolve(),
                        Path(tmpdir).resolve(),
                    )
                finally:
                    os.chdir(orig_cwd)

    def test_returns_none_when_not_found(self):
        """Returns None when no MEMORY.md in tree."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(os.environ, {"MNEMOSYNE_MEMORY_DIR": ""}, clear=False):
                orig_cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    result = auto_retrieve.find_memory_dir()
                    self.assertIsNone(result)
                finally:
                    os.chdir(orig_cwd)

    def test_finds_memory_subdir_pattern(self):
        """Finds memory/MEMORY.md subdirectory pattern."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mem_subdir = Path(tmpdir) / "memory"
            mem_subdir.mkdir()
            (mem_subdir / "MEMORY.md").touch()
            with patch.dict(os.environ, {"MNEMOSYNE_MEMORY_DIR": ""}, clear=False):
                orig_cwd = os.getcwd()
                try:
                    os.chdir(tmpdir)
                    result = auto_retrieve.find_memory_dir()
                    # Resolve both sides: macOS /var is a symlink to /private/var
                    self.assertEqual(
                        Path(result).resolve(),
                        mem_subdir.resolve(),
                    )
                finally:
                    os.chdir(orig_cwd)


class TestExtractPrompt(unittest.TestCase):
    """Test prompt extraction from various event shapes."""

    def test_top_level_prompt(self):
        event = {"prompt": "What is RSM Puerto Rico?"}
        self.assertEqual(auto_retrieve.extract_prompt(event), "What is RSM Puerto Rico?")

    def test_nested_message_content_string(self):
        event = {"message": {"content": "Tell me about surf spots"}}
        self.assertEqual(auto_retrieve.extract_prompt(event), "Tell me about surf spots")

    def test_nested_message_content_list(self):
        event = {"message": {"content": [{"type": "text", "text": "ATHENA bugs status"}]}}
        self.assertEqual(auto_retrieve.extract_prompt(event), "ATHENA bugs status")

    def test_empty_event_returns_empty(self):
        self.assertEqual(auto_retrieve.extract_prompt({}), "")

    def test_malformed_message_returns_empty(self):
        self.assertEqual(auto_retrieve.extract_prompt({"message": "just a string"}), "")


class TestSearchMarkdown(unittest.TestCase):
    """Test markdown fallback search via MarkdownRetriever."""

    def test_returns_results_for_matching_query(self):
        results = auto_retrieve.search_markdown(
            "RSM Puerto Rico cybersecurity compliance",
            str(FIXTURES_DIR),
            top_k=3,
        )
        self.assertGreater(len(results), 0)
        self.assertIsInstance(results[0], str)
        # v1.1.0: results are wrapped in untrusted-retrieved-memory delimiters
        # (replaces the prior "[source]: content" label format).
        self.assertIn("<untrusted-retrieved-memory", results[0])
        self.assertIn("</untrusted-retrieved-memory>", results[0])

    def test_returns_empty_for_missing_directory(self):
        results = auto_retrieve.search_markdown("test query", "/nonexistent/path", top_k=3)
        self.assertEqual(results, [])

    def test_returns_empty_for_no_match(self):
        results = auto_retrieve.search_markdown(
            "quantum blockchain metaverse cryptocurrency",
            str(FIXTURES_DIR),
            top_k=3,
        )
        self.assertEqual(results, [])


class TestSessionCounter(unittest.TestCase):
    """Test session search rate limiting."""

    def setUp(self):
        self.test_session = f"test-unit-{id(self)}"
        self.state_dir = Path.home() / ".mnemosyne" / "state"

    def tearDown(self):
        state_file = self.state_dir / f"auto-retrieve-{self.test_session}.count"
        state_file.unlink(missing_ok=True)

    def test_initial_count_is_zero(self):
        count = auto_retrieve.get_session_search_count(self.test_session)
        self.assertEqual(count, 0)

    def test_increment_increases_count(self):
        auto_retrieve.increment_session_search_count(self.test_session)
        count = auto_retrieve.get_session_search_count(self.test_session)
        self.assertEqual(count, 1)
        auto_retrieve.increment_session_search_count(self.test_session)
        count = auto_retrieve.get_session_search_count(self.test_session)
        self.assertEqual(count, 2)

    def test_max_session_searches_constant(self):
        self.assertEqual(auto_retrieve.MAX_SESSION_SEARCHES, 3)


if __name__ == "__main__":
    unittest.main()
