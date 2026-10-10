"""Tests for latest-entry convergence and finding resolution (protocol 0.2.0)."""

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from wags import Finding, WagsWorkspace

FIXTURE = Path(__file__).parent / "fixtures" / "rev-govbench-results-001"
GO_DIR = Path(__file__).parent.parent / "wags" / "go"


def _f(fid, sev):
    return Finding(fid, sev, "docs", f"finding {fid}", "x:1", "fix it")


class TestResolution(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wags_res_")
        self.ws = WagsWorkspace(self.tmp)
        tgt = Path(self.tmp) / "t.md"
        tgt.write_text("# t\n", encoding="utf-8")
        self.rid = self.ws.init_review(tgt, review_id="rev-res-001")["review_id"]
        for r in ("author", "rev-a", "rev-b"):
            self.ws.register_reviewer(self.rid, r)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _govbench_shape(self, use_refs=True):
        """Reproduce rev-govbench-results-001 with canonical resolution fields."""
        self.ws.submit_entry(self.rid, "author", findings=[_f("a-P2-01", "P2")], verdict="approve")
        e1 = self.ws.submit_entry(self.rid, "rev-a", findings=[_f("a-P1-01", "P1"), _f("a-P1-02", "P1")],
                                  verdict="request_changes")
        e2 = self.ws.submit_entry(self.rid, "rev-a", findings=[_f("a-r2-P1-01", "P1")], verdict="request_changes")
        kw = {}
        if use_refs:
            kw = dict(resolves=["a-P1-01", "a-P1-02", "a-r2-P1-01"], supersedes=[e1.entry_hash, e2.entry_hash])
        self.ws.submit_entry(self.rid, "rev-a", findings=[_f("a-r3-N-01", "N")], verdict="approve", **kw)
        self.ws.submit_entry(self.rid, "rev-b", findings=[_f("b-P2-01", "P2")], verdict="approve")

    def test_govbench_shape_with_resolves_approves(self):
        """Same shape as rev-govbench-results-001, but using the protocol fields."""
        self._govbench_shape(use_refs=True)
        self.assertTrue(self.ws.verify_review(self.rid)["valid"])
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["overall_verdict"], "APPROVE")
        self.assertEqual(c["summary"]["open_findings_by_severity"]["P1"], 0)
        self.assertEqual(len(c["resolved_findings"]), 3)
        self.assertEqual(len(c["all_findings"]), 6)
        self.assertEqual(c["blocking_findings"], [])

    def test_legacy_latest_verdict_wins(self):
        """Old-style log (no resolves): the earlier P1s stay OPEN; it approves only via
        the latest-verdict rule (open P1 under an approve is non-blocking)."""
        self._govbench_shape(use_refs=False)
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["overall_verdict"], "APPROVE")
        self.assertEqual(c["summary"]["findings_by_severity"]["P1"], 3)
        self.assertEqual(c["blocking_findings"], [])

    def test_open_p1_blocks_when_reviewer_not_approving(self):
        self.ws.submit_entry(self.rid, "rev-a", findings=[_f("a-P1-01", "P1")], verdict="defer")
        self.ws.submit_entry(self.rid, "rev-b", verdict="approve")
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["overall_verdict"], "REQUEST_CHANGES")

    def test_latest_request_changes_overrides_earlier_approve(self):
        self.ws.submit_entry(self.rid, "rev-a", verdict="approve")
        self.ws.submit_entry(self.rid, "rev-a", findings=[_f("a-P1-09", "P1")], verdict="request_changes")
        self.ws.submit_entry(self.rid, "rev-b", verdict="approve")
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "REQUEST_CHANGES")

    def test_open_p0_vetoes_even_with_approve(self):
        self.ws.submit_entry(self.rid, "rev-a", findings=[_f("a-P0-01", "P0")], verdict="block")
        self.ws.submit_entry(self.rid, "rev-a", verdict="approve")
        self.ws.submit_entry(self.rid, "rev-b", verdict="approve")
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "BLOCK")

    def test_resolved_p0_no_longer_vetoes(self):
        self.ws.submit_entry(self.rid, "rev-a", findings=[_f("a-P0-01", "P0")], verdict="block")
        self.ws.submit_entry(self.rid, "rev-a", verdict="approve", resolves=["a-P0-01"])
        self.ws.submit_entry(self.rid, "rev-b", verdict="approve")
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "APPROVE")

    def test_cannot_resolve_other_reviewers_findings(self):
        self.ws.submit_entry(self.rid, "rev-a", findings=[_f("a-P0-01", "P0")], verdict="block")
        with self.assertRaises(ValueError):
            self.ws.submit_entry(self.rid, "rev-b", verdict="approve", resolves=["a-P0-01"])
        e = self.ws.tail_review(self.rid)[0]
        with self.assertRaises(ValueError):
            self.ws.submit_entry(self.rid, "rev-b", verdict="approve", supersedes=[e.entry_hash])
        with self.assertRaises(ValueError):
            self.ws.submit_entry(self.rid, "rev-a", verdict="approve", resolves=["nope"])
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "BLOCK")

    def test_forged_cross_stream_resolve_fails_verify_and_is_ignored(self):
        """A hand-written (hash-valid) entry resolving someone else's finding is rejected."""
        from wags import StreamEntry, GENESIS_HASH, _canonical_json
        self.ws.submit_entry(self.rid, "rev-a", findings=[_f("a-P0-01", "P0")], verdict="block")
        e = StreamEntry(1, "2026-01-01T00:00:00Z", self.rid, "rev-b", "review", GENESIS_HASH, [],
                        "approve", metadata={"resolves": ["a-P0-01"]})
        e.sign(None)
        p = Path(self.tmp) / "reviews" / self.rid / "rev-b.jsonl"
        p.write_text(_canonical_json(e.to_dict()) + "\n", encoding="utf-8")
        v = self.ws.verify_review(self.rid)
        self.assertFalse(v["valid"])
        self.assertFalse(v["streams"]["rev-b"]["valid"])
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "BLOCK")

    def test_hash_chain_untouched_by_resolution(self):
        self._govbench_shape(use_refs=True)
        lines = (Path(self.tmp) / "reviews" / self.rid / "rev-a.jsonl").read_text().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(json.loads(lines[0])["verdict"], "request_changes")  # never rewritten


class TestGovbenchFixture(unittest.TestCase):
    """Real-world log from rev-govbench-results-001 (written by wags 0.1.0)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wags_fix_")
        shutil.copytree(FIXTURE, self.tmp, dirs_exist_ok=True)
        self.ws = WagsWorkspace(self.tmp)
        self.rid = "rev-govbench-results-001"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_fixture_verifies(self):
        self.assertTrue(self.ws.verify_review(self.rid)["valid"])

    def test_fixture_converges_approve(self):
        """Approves via latest-verdict only. MTSMU's three P1s stay OPEN: entry #3 used
        non-protocol keys (resolved_findings / supersedes_entries), so nothing is resolved."""
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["resolved_findings"], [])
        self.assertEqual(c["summary"]["open_findings_by_severity"]["P1"], 3)
        self.assertEqual(c["overall_verdict"], "APPROVE")
        self.assertEqual(c["summary"]["verdicts"]["approve"], 3)
        self.assertEqual(c["blocking_findings"], [])

    def test_go_fixture_parity(self):
        if shutil.which("go") is None:
            self.skipTest("go not installed")
        import os
        env = dict(os.environ, WAGS_WORKSPACE=self.tmp)
        for cmd, want in (("verify", "VERIFIED"), ("converge", "Converged: APPROVE")):
            r = subprocess.run(["go", "run", "wags.go", cmd, self.rid], cwd=GO_DIR, env=env,
                               capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn(want, r.stdout)


if __name__ == "__main__":
    unittest.main()


class TestReviewRound2(unittest.TestCase):
    """Fixes from Parallax review of PR #4 (MTSMU + Quilter)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wags_r2_")
        self.ws = WagsWorkspace(self.tmp)
        tgt = Path(self.tmp) / "t.md"
        tgt.write_text("# t\n", encoding="utf-8")
        self.rid = self.ws.init_review(tgt, review_id="rev-r2")["review_id"]
        for r in ("a", "b"):
            self.ws.register_reviewer(self.rid, r)
        self.stream = Path(self.tmp) / "reviews" / self.rid

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _go(self, cmd):
        if shutil.which("go") is None:
            self.skipTest("go not installed")
        import os
        return subprocess.run(["go", "run", "wags.go", cmd, self.rid], cwd=GO_DIR,
                              env=dict(os.environ, WAGS_WORKSPACE=self.tmp),
                              capture_output=True, text=True, timeout=120)

    # P0-01 / quilter P1-01: positional resolution
    def test_reraised_p0_after_resolve_vetoes(self):
        self.ws.submit_entry(self.rid, "a", findings=[_f("X", "P0")], verdict="block")
        self.ws.submit_entry(self.rid, "a", verdict="approve", resolves=["X"])
        self.ws.submit_entry(self.rid, "a", findings=[_f("X", "P0")], verdict="approve")
        self.ws.submit_entry(self.rid, "b", verdict="approve")
        self.assertTrue(self.ws.verify_review(self.rid)["valid"])
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["overall_verdict"], "BLOCK")
        self.assertEqual(len(c["resolved_findings"]), 1)
        self.assertEqual(len(c["open_findings"]), 1)
        self.assertIn("BLOCK", self._go("converge").stdout)

    def test_resolve_in_same_entry_rejected(self):
        with self.assertRaises(ValueError):
            self.ws.submit_entry(self.rid, "a", findings=[_f("S", "P0")], verdict="approve", resolves=["S"])

    # P1-01: integrity + registration
    def test_reordered_stream_excluded_and_blocks(self):
        self.ws.submit_entry(self.rid, "a", verdict="approve")
        self.ws.submit_entry(self.rid, "a", verdict="block")
        self.ws.submit_entry(self.rid, "b", verdict="approve")
        p = self.stream / "a.jsonl"
        p.write_text("\n".join(p.read_text().splitlines()[::-1]) + "\n")
        self.assertFalse(self.ws.verify_review(self.rid)["valid"])
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["overall_verdict"], "BLOCK")
        self.assertEqual([x["reviewer"] for x in c["invalid_streams"]], ["a"])
        self.assertIn("BLOCK", self._go("converge").stdout)

    def test_unregistered_stream_excluded(self):
        self.ws.submit_entry(self.rid, "b", verdict="request_changes")
        (self.stream / "zz.jsonl").write_text('{"verdict":"approve","findings":[]}\n')
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["unregistered_streams"], ["zz"])
        self.assertEqual(c["summary"]["total_reviewers"], 1)
        self.assertEqual(c["overall_verdict"], "REQUEST_CHANGES")

    # P2s
    def test_unknown_severity_rejected_and_conservative(self):
        with self.assertRaises(ValueError):
            self.ws.submit_entry(self.rid, "a", findings=[{"id": "x", "severity": "critical"}], verdict="approve")
        from wags import StreamEntry, GENESIS_HASH, _canonical_json
        e = StreamEntry(1, "2026-01-01T00:00:00Z", self.rid, "a", "review", GENESIS_HASH,
                        [{"id": "x", "severity": "critical"}], "approve")
        e.sign(None)
        (self.stream / "a.jsonl").write_text(_canonical_json(e.to_dict()) + "\n")
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["overall_verdict"], "BLOCK")
        self.assertEqual(len(c["unknown_severity_findings"]), 1)
        self.assertIn("BLOCK", self._go("converge").stdout)

    def test_metadata_must_be_dict(self):
        with self.assertRaises(ValueError):
            self.ws.submit_entry(self.rid, "a", verdict="approve", metadata=["resolves"])
        with self.assertRaises(ValueError):
            self.ws.submit_entry(self.rid, "a", verdict="approve", metadata=["x"], resolves=[])

    def test_resolves_null_rejected(self):
        self.ws.submit_entry(self.rid, "a", findings=[_f("X", "P1")], verdict="request_changes")
        with self.assertRaises(ValueError):
            self.ws.submit_entry(self.rid, "a", verdict="approve", metadata={"resolves": None})

    def test_findings_by_severity_compat(self):
        self.ws.submit_entry(self.rid, "a", findings=[_f("X", "P1")], verdict="request_changes")
        self.ws.submit_entry(self.rid, "a", verdict="approve", resolves=["X"])
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["summary"]["findings_by_severity"]["P1"], 1)       # all, as in 0.1.0
        self.assertEqual(c["summary"]["open_findings_by_severity"]["P1"], 0)  # open only

    # Quilter P2-02 / P2-03: canonical JSON parity with Go
    def test_go_verifies_python_numbers_and_literal_u2028(self):
        self.ws.submit_entry(self.rid, "a", findings=[Finding("t", "P3", "s", "lit \\u2028 real \u2028 <b>&", "e", "r")],
                             verdict="approve",
                             metadata={"one": 1.0, "negz": -0.0, "exp": 1e-07, "f": 0.1, "big": 10**20})
        self.assertTrue(self.ws.verify_review(self.rid)["valid"])
        r = self._go("verify")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class TestLegacyGoFixture(unittest.TestCase):
    """Entry written by wags-go 0.1.0 (HTML-escaped hash, empty reviewers.json)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wags_lg_")
        shutil.copytree(Path(__file__).parent / "fixtures" / "legacy-go-010", self.tmp, dirs_exist_ok=True)
        self.ws = WagsWorkspace(self.tmp)
        self.rid = "rev-legacy-go-010"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_python_accepts_legacy_go_hash(self):
        self.assertTrue(self.ws.verify_review(self.rid)["valid"])
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["overall_verdict"], "APPROVE")
        self.assertTrue(c["registry_empty"])

    def test_go_accepts_legacy_go_hash(self):
        if shutil.which("go") is None:
            self.skipTest("go not installed")
        import os
        env = dict(os.environ, WAGS_WORKSPACE=self.tmp)
        for cmd, want in (("verify", "VERIFIED"), ("converge", "Converged: APPROVE")):
            r = subprocess.run(["go", "run", "wags.go", cmd, self.rid], cwd=GO_DIR, env=env,
                               capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn(want, r.stdout)
