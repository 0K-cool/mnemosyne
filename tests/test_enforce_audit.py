"""Unit tests for lib/enforce/audit.py — aggregate hook firings into rule-level stats.

The hook templates write JSONL audit entries (one per fire) to
`.claude/logs/<rule>.audit.jsonl`. Phase 3's audit module reads those
files and reports per-rule stats: allow / block / skip-override counts,
first-seen / last-seen timestamps, and (with --threshold) flags rules
that have crossed a violation threshold as escalation candidates.

Behavior contract:
  - Empty / missing logs dir → exit 0 with no rules reported
  - Each `*.audit.jsonl` file becomes one rule (rule_name = file stem
    minus `.audit`)
  - Per rule: count events by type, capture first/last ts
  - --threshold N flags rules with `blocks >= N`
  - --json emits machine-readable output to stdout
  - Malformed JSONL lines are skipped silently, not fatal
"""

import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

LIB_DIR = Path(__file__).parent.parent / "lib"
sys.path.insert(0, str(LIB_DIR))

from enforce.audit import aggregate_audit_logs, main as audit_main  # noqa: E402


def _run(*args: str) -> tuple[int, str, str]:
    """Drive the CLI with captured stdout/stderr. Returns (exit_code, stdout, stderr)."""
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            rc = audit_main(list(args))
        except SystemExit as exc:
            rc = exc.code if isinstance(exc.code, int) else 1
    return rc, out.getvalue(), err.getvalue()


class TestAggregate(unittest.TestCase):
    """Pure aggregation logic — no CLI."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write_log(self, name: str, lines: list[dict]) -> Path:
        path = self.tmp / name
        with path.open("w") as fh:
            for d in lines:
                fh.write(json.dumps(d) + "\n")
        return path

    def test_aggregate_empty_dir(self):
        result = aggregate_audit_logs(self.tmp)
        self.assertEqual(result, [])

    def test_aggregate_missing_dir_returns_empty(self):
        result = aggregate_audit_logs(self.tmp / "nope")
        self.assertEqual(result, [])

    def test_aggregate_single_log_counts_events(self):
        self._write_log("cr-prepush.audit.jsonl", [
            {"ts": "2026-04-01T10:00:00Z", "event": "block", "reason": "no cache"},
            {"ts": "2026-04-01T11:00:00Z", "event": "block", "reason": "stale"},
            {"ts": "2026-04-01T12:00:00Z", "event": "allow", "reason": "fresh"},
            {"ts": "2026-04-01T13:00:00Z", "event": "skip-override"},
        ])
        result = aggregate_audit_logs(self.tmp)
        self.assertEqual(len(result), 1)
        rule = result[0]
        self.assertEqual(rule["rule"], "cr-prepush")
        self.assertEqual(rule["blocks"], 2)
        self.assertEqual(rule["allows"], 1)
        self.assertEqual(rule["skip_overrides"], 1)
        self.assertEqual(rule["total"], 4)
        self.assertEqual(rule["first_seen"], "2026-04-01T10:00:00Z")
        self.assertEqual(rule["last_seen"], "2026-04-01T13:00:00Z")

    def test_aggregate_multiple_logs(self):
        self._write_log("rule-a.audit.jsonl", [
            {"ts": "2026-04-01T10:00:00Z", "event": "block"},
        ])
        self._write_log("rule-b.audit.jsonl", [
            {"ts": "2026-04-02T10:00:00Z", "event": "allow"},
            {"ts": "2026-04-02T11:00:00Z", "event": "allow"},
        ])
        result = aggregate_audit_logs(self.tmp)
        # Sorted alphabetically by rule name for stable output
        self.assertEqual([r["rule"] for r in result], ["rule-a", "rule-b"])
        self.assertEqual(result[0]["blocks"], 1)
        self.assertEqual(result[1]["allows"], 2)

    def test_aggregate_skips_malformed_lines(self):
        path = self.tmp / "broken.audit.jsonl"
        with path.open("w") as fh:
            fh.write('{"ts":"2026-04-01T10:00:00Z","event":"block"}\n')
            fh.write("not json at all\n")
            fh.write('{"ts":"2026-04-01T11:00:00Z","event":"allow"}\n')
        result = aggregate_audit_logs(self.tmp)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["blocks"], 1)
        self.assertEqual(result[0]["allows"], 1)

    def test_aggregate_ignores_non_audit_files(self):
        # *.jsonl that aren't audit files (different suffix) are skipped
        (self.tmp / "random.log").write_text("nothing\n")
        (self.tmp / "other.jsonl").write_text("{}\n")
        result = aggregate_audit_logs(self.tmp)
        self.assertEqual(result, [])


class TestCli(unittest.TestCase):
    """End-to-end CLI: stdout/stderr/exit codes."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write_log(self, name: str, lines: list[dict]) -> None:
        path = self.tmp / name
        with path.open("w") as fh:
            for d in lines:
                fh.write(json.dumps(d) + "\n")

    def test_empty_logs_dir_exits_0(self):
        rc, _out, err = _run("--logs-dir", str(self.tmp))
        self.assertEqual(rc, 0, f"stderr: {err}")

    def test_table_output_lists_rules(self):
        self._write_log("cr-prepush.audit.jsonl", [
            {"ts": "2026-04-01T10:00:00Z", "event": "block"},
            {"ts": "2026-04-01T11:00:00Z", "event": "allow"},
        ])
        rc, out, err = _run("--logs-dir", str(self.tmp))
        self.assertEqual(rc, 0)
        # Default human-readable output names the rule + counts
        combined = out + err
        self.assertIn("cr-prepush", combined)
        self.assertIn("1", combined)  # 1 block, 1 allow

    def test_json_output_is_parseable(self):
        self._write_log("rule-a.audit.jsonl", [
            {"ts": "2026-04-01T10:00:00Z", "event": "block"},
        ])
        rc, out, _ = _run("--logs-dir", str(self.tmp), "--json")
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["rule"], "rule-a")
        self.assertEqual(data[0]["blocks"], 1)

    def test_threshold_flags_escalation_candidates(self):
        self._write_log("frequent.audit.jsonl", [
            {"ts": "2026-04-01T10:00:00Z", "event": "block"} for _ in range(5)
        ])
        self._write_log("rare.audit.jsonl", [
            {"ts": "2026-04-01T10:00:00Z", "event": "block"},
        ])
        rc, out, err = _run("--logs-dir", str(self.tmp), "--threshold", "3")
        # threshold reached → flagged but exit still 0 (informational)
        self.assertEqual(rc, 0)
        combined = out + err
        # The frequent rule must be marked as crossing threshold
        self.assertIn("frequent", combined)
        # Some kind of escalation marker — title-case "ESCALATE" or similar
        self.assertTrue(
            any(kw in combined.lower() for kw in ("escalate", "threshold", "candidate")),
            f"no escalation marker in output:\n{combined}",
        )

    def test_threshold_negative_rejected(self):
        """argparse parse-time validation: --threshold must be >= 0."""
        # Can't use _run because argparse calls sys.exit(2) on parse failure;
        # capture stderr to verify the error message.
        rc, _out, err = _run("--logs-dir", str(self.tmp), "--threshold", "-1")
        self.assertEqual(rc, 2, "expected argparse exit code 2 for invalid arg")
        self.assertIn("threshold", err.lower())

    def test_threshold_in_json_output(self):
        self._write_log("frequent.audit.jsonl", [
            {"ts": "2026-04-01T10:00:00Z", "event": "block"} for _ in range(5)
        ])
        rc, out, _ = _run("--logs-dir", str(self.tmp), "--threshold", "3", "--json")
        self.assertEqual(rc, 0)
        data = json.loads(out)
        self.assertTrue(data[0].get("escalation_candidate", False))


if __name__ == "__main__":
    unittest.main(verbosity=2)
