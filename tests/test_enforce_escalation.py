"""Tests for v2.1.0 soft-to-hard escalation — lib/enforce/audit.py.

Covers: ISO-8601 parsing across template dialects, windowed warn
counting, escalation-config loading from memory entries, READY
evaluation, the operator-gated apply flow (rule rewrite + hook
regeneration), webhook notification, and CLI exit codes.
"""

import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

LIB_DIR = Path(__file__).parent.parent / "lib"
TEMPLATE_DIR = Path(__file__).parent.parent / "templates" / "hooks"
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "enforce"
sys.path.insert(0, str(LIB_DIR))

from enforce.audit import (  # noqa: E402
    _count_warns_in_window,
    _parse_ts,
    _post_webhook,
    apply_escalation,
    evaluate_escalations,
    load_escalation_configs,
    main,
)
from enforce.schema import validate_enforce_block  # noqa: E402
from enforce.generator import parse_memory_entry  # noqa: E402

NOW = datetime(2026, 6, 7, 12, 0, 0, tzinfo=timezone.utc)


def _iso_z(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_main(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestParseTs(unittest.TestCase):
    """_parse_ts accepts every dialect the three template ports emit."""

    def test_z_suffix(self):
        dt = _parse_ts("2026-06-07T12:00:00Z")
        self.assertEqual(dt, NOW)

    def test_offset_suffix(self):
        dt = _parse_ts("2026-06-07T12:00:00+00:00")
        self.assertEqual(dt, NOW)

    def test_naive_assumed_utc(self):
        dt = _parse_ts("2026-06-07T12:00:00")
        self.assertEqual(dt, NOW)

    def test_garbage_returns_none(self):
        for bad in ["not-a-date", "", "2026-13-45T99:99:99Z"]:
            self.assertIsNone(_parse_ts(bad), bad)


class TestWindowedCounting(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="mnz-esc-logs-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_log(self, name: str, entries: list[dict]) -> Path:
        p = self.tmp / f"{name}.audit.jsonl"
        p.write_text("".join(json.dumps(e) + "\n" for e in entries))
        return p

    def test_counts_only_warns_inside_window(self):
        """Mixed ts dialects; blocks/allows never count; old warns age out."""
        log = self._write_log("pr-rate", [
            {"ts": _iso_z(NOW - timedelta(days=1)), "event": "warn"},
            {"ts": (NOW - timedelta(days=3)).isoformat(), "event": "warn"},  # +00:00 form
            {"ts": _iso_z(NOW - timedelta(days=10)), "event": "warn"},       # aged out
            {"ts": _iso_z(NOW - timedelta(days=1)), "event": "block"},
            {"ts": _iso_z(NOW - timedelta(days=1)), "event": "allow"},
        ])
        self.assertEqual(_count_warns_in_window(log, NOW - timedelta(days=7)), 2)

    def test_unparseable_ts_skipped(self):
        log = self._write_log("pr-rate", [
            {"ts": "garbage", "event": "warn"},
            {"event": "warn"},  # missing ts
            {"ts": _iso_z(NOW - timedelta(days=1)), "event": "warn"},
        ])
        self.assertEqual(_count_warns_in_window(log, NOW - timedelta(days=7)), 1)

    def test_missing_log_counts_zero(self):
        self.assertEqual(
            _count_warns_in_window(self.tmp / "absent.audit.jsonl", NOW), 0
        )


class _EscalationTreeMixin(unittest.TestCase):
    """Scratch tree: memory/ + logs/ + hooks output dir."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="mnz-esc-tree-"))
        self.memory = self.root / "memory"
        self.logs = self.root / "logs"
        self.out = self.root / "hooks-out"
        for d in (self.memory, self.logs, self.out):
            d.mkdir(parents=True)
        # Warn rule whose audit_log points into our scratch logs dir.
        fixture = (FIXTURE_DIR / "warn-rule.md").read_text()
        self.rule_md = fixture.replace(
            "  mode: warn\n",
            "  audit_log: logs/pr-rate.audit.jsonl\n  mode: warn\n",
        )
        self.rule_path = self.memory / "feedback_api_batching.md"
        self.rule_path.write_text(self.rule_md)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _write_warns(self, n: int, age_days: float = 1.0, name: str = "pr-rate"):
        """Append n fresh warn events (real now — CLI paths use wall clock)."""
        p = self.logs / f"{name}.audit.jsonl"
        now = datetime.now(timezone.utc)
        with p.open("a") as fh:
            for _ in range(n):
                fh.write(json.dumps(
                    {"ts": _iso_z(now - timedelta(days=age_days)), "event": "warn"}
                ) + "\n")
        return p


class TestLoadEscalationConfigs(_EscalationTreeMixin):
    def test_loads_warn_rule_with_escalation(self):
        configs = load_escalation_configs(self.memory)
        self.assertIn("pr-rate", configs)
        cfg = configs["pr-rate"]
        self.assertEqual(cfg["threshold"], 3)
        self.assertEqual(cfg["window_days"], 7)
        self.assertEqual(Path(cfg["rule_path"]), self.rule_path)

    def test_rules_without_escalation_skipped(self):
        (self.memory / "plain.md").write_text(
            "---\nname: plain\ntype: feedback\nenforce:\n"
            "  tool: Bash\n  pattern: \"rm -rf\"\n"
            "  hook: .claude/hooks/auto/rm.ts\n"
            "  generated_from: memory/plain.md\n"
            "  template: block-on-match-guard.ts.template\n"
            "---\nBody.\n"
        )
        configs = load_escalation_configs(self.memory)
        self.assertEqual(set(configs), {"pr-rate"})

    def test_invalid_enforce_block_skipped_not_fatal(self):
        (self.memory / "broken.md").write_text(
            "---\nname: broken\nenforce:\n  tool: NotATool\n---\nBody.\n"
        )
        configs = load_escalation_configs(self.memory)  # must not raise
        self.assertEqual(set(configs), {"pr-rate"})

    def test_missing_memory_dir_returns_empty(self):
        self.assertEqual(load_escalation_configs(self.root / "absent"), {})


class TestEvaluateEscalations(_EscalationTreeMixin):
    def _rules_for(self, log_path: Path) -> list[dict]:
        return [{
            "rule": "pr-rate", "warns": 3, "blocks": 0, "allows": 0,
            "skip_overrides": 0, "total": 3, "first_seen": "", "last_seen": "",
            "log_path": str(log_path),
        }]

    def test_ready_when_threshold_crossed_in_window(self):
        log = self._write_warns(3)
        rules = self._rules_for(log)
        ready = evaluate_escalations(rules, load_escalation_configs(self.memory))
        self.assertEqual(len(ready), 1)
        self.assertTrue(rules[0]["escalation_ready"])
        self.assertEqual(rules[0]["warns_in_window"], 3)
        self.assertEqual(rules[0]["escalation_threshold"], 3)

    def test_not_ready_when_warns_aged_out(self):
        log = self._write_warns(5, age_days=30.0)
        rules = self._rules_for(log)
        ready = evaluate_escalations(rules, load_escalation_configs(self.memory))
        self.assertEqual(ready, [])
        self.assertFalse(rules[0]["escalation_ready"])
        self.assertEqual(rules[0]["warns_in_window"], 0)

    def test_rules_without_config_untouched(self):
        rules = [{"rule": "other", "log_path": "/nonexistent", "warns": 9}]
        ready = evaluate_escalations(rules, load_escalation_configs(self.memory))
        self.assertEqual(ready, [])
        self.assertNotIn("escalation_ready", rules[0])


class TestApplyEscalation(_EscalationTreeMixin):
    def test_apply_flips_mode_removes_policy_and_regenerates(self):
        rc = apply_escalation(
            self.rule_path, template_dir=TEMPLATE_DIR, output_dir=self.out,
        )
        self.assertEqual(rc, 0)
        rewritten = self.rule_path.read_text()
        self.assertIn("mode: block", rewritten)
        self.assertNotIn("mode: warn", rewritten)
        # Consumed policy is removed — a block rule with escalation is
        # a schema error, and the promotion is the policy's terminal state.
        self.assertNotIn("escalation:", rewritten)
        self.assertNotIn("threshold:", rewritten)
        # Rewritten rule revalidates as a hard rule.
        meta, _ = parse_memory_entry(rewritten)
        normalized = validate_enforce_block(meta["enforce"])
        self.assertEqual(normalized["mode"], "block")
        # Regenerated hook is the hard form.
        hook = self.out / "pr-rate.ts"
        self.assertTrue(hook.exists(), "regenerated hook missing")
        src = hook.read_text()
        self.assertIn("emitBlock('pattern matched')", src)
        self.assertNotIn("emitWarn('pattern matched')", src)

    def test_apply_preserves_unrelated_content(self):
        before = self.rule_path.read_text()
        apply_escalation(self.rule_path, template_dir=TEMPLATE_DIR, output_dir=self.out)
        after = self.rule_path.read_text()
        # Body and unrelated frontmatter intact.
        self.assertIn("# API token batching", after)
        self.assertIn("pattern: \"gh pr create\"", after)
        self.assertEqual(before.count("---"), after.count("---"))

    def test_apply_on_non_warn_rule_fails_safe(self):
        (self.memory / "hard.md").write_text(
            (FIXTURE_DIR / "warn-rule.md").read_text()
            .replace("  mode: warn\n", "")
            .replace("  escalation:\n    threshold: 3\n    window_days: 7\n", "")
        )
        rc = apply_escalation(
            self.memory / "hard.md", template_dir=TEMPLATE_DIR, output_dir=self.out,
        )
        self.assertNotEqual(rc, 0)


class TestWebhook(unittest.TestCase):
    def test_posts_json_with_discord_content(self):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode())
            captured["timeout"] = timeout

            class _Resp:
                status = 204
                def __enter__(self): return self
                def __exit__(self, *a): return False
            return _Resp()

        with mock.patch("enforce.audit.urllib.request.urlopen", fake_urlopen):
            ok = _post_webhook("https://discord.test/webhook", {
                "rule": "pr-rate", "warns_in_window": 3,
                "threshold": 3, "window_days": 7, "log_path": "/x",
            })
        self.assertTrue(ok)
        self.assertEqual(captured["url"], "https://discord.test/webhook")
        self.assertEqual(captured["body"]["rule"], "pr-rate")
        self.assertIn("content", captured["body"])  # Discord renders this
        self.assertIn("pr-rate", captured["body"]["content"])

    def test_non_http_scheme_refused(self):
        with mock.patch("enforce.audit.urllib.request.urlopen") as m:
            ok = _post_webhook("file:///etc/passwd", {"rule": "x"})
        self.assertFalse(ok)
        m.assert_not_called()

    def test_network_failure_fail_soft(self):
        with mock.patch(
            "enforce.audit.urllib.request.urlopen", side_effect=OSError("down")
        ):
            ok = _post_webhook("https://discord.test/webhook", {"rule": "x"})
        self.assertFalse(ok)  # no raise


class TestCliEscalation(_EscalationTreeMixin):
    def _argv(self, *extra: str) -> list[str]:
        return [
            "--logs-dir", str(self.logs),
            "--memory-dir", str(self.memory),
            *extra,
        ]

    def test_json_reports_ready(self):
        self._write_warns(3)
        rc, out, _ = _run_main(self._argv("--json"))
        self.assertEqual(rc, 0)
        rules = json.loads(out)
        rule = next(r for r in rules if r["rule"] == "pr-rate")
        self.assertTrue(rule["escalation_ready"])
        self.assertEqual(rule["warns_in_window"], 3)

    def test_table_shows_ready_section(self):
        self._write_warns(3)
        rc, out, _ = _run_main(self._argv())
        self.assertEqual(rc, 0)
        self.assertIn("READY TO ESCALATE", out)
        self.assertIn("pr-rate", out)

    def test_below_threshold_not_ready(self):
        self._write_warns(2)
        rc, out, _ = _run_main(self._argv("--json"))
        rules = json.loads(out)
        rule = next(r for r in rules if r["rule"] == "pr-rate")
        self.assertFalse(rule["escalation_ready"])

    def test_fail_on_escalation_exit_3(self):
        self._write_warns(3)
        rc, _, _ = _run_main(self._argv("--fail-on-escalation"))
        self.assertEqual(rc, 3)

    def test_fail_on_escalation_quiet_when_not_ready(self):
        self._write_warns(1)
        rc, _, _ = _run_main(self._argv("--fail-on-escalation"))
        self.assertEqual(rc, 0)

    def test_apply_yes_promotes_and_exits_zero(self):
        self._write_warns(3)
        rc, out, _ = _run_main(self._argv(
            "--apply", "--yes",
            "--output-dir", str(self.out),
            "--template-dir", str(TEMPLATE_DIR),
        ))
        self.assertEqual(rc, 0)
        self.assertIn("mode: block", self.rule_path.read_text())
        self.assertTrue((self.out / "pr-rate.ts").exists())

    def test_webhook_called_per_ready_rule(self):
        self._write_warns(3)
        with mock.patch("enforce.audit._post_webhook", return_value=True) as m:
            rc, _, _ = _run_main(self._argv(
                "--webhook-url", "https://discord.test/webhook",
            ))
        self.assertEqual(rc, 0)
        m.assert_called_once()
        self.assertEqual(m.call_args.args[1]["rule"], "pr-rate")

    def test_no_memory_dir_degrades_gracefully(self):
        """Absent memory dir → legacy behavior, no escalation fields."""
        self._write_warns(3)
        rc, out, _ = _run_main([
            "--logs-dir", str(self.logs),
            "--memory-dir", str(self.root / "absent"),
            "--json",
        ])
        self.assertEqual(rc, 0)
        rules = json.loads(out)
        self.assertNotIn("escalation_ready", rules[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
