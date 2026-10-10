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
        self.ws.submit_entry(self.rid, "author", verdict="approve")
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

    def test_unregistered_stream_fails_closed(self):
        """0.2.0: an unregistered stream with content never votes and BLOCKs (round 2)."""
        self.ws.submit_entry(self.rid, "b", verdict="request_changes")
        (self.stream / "zz.jsonl").write_text('{"verdict":"approve","findings":[]}\n')
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["unregistered_streams"], ["zz"])
        self.assertEqual(c["summary"]["total_reviewers"], 1)
        self.assertEqual(c["overall_verdict"], "BLOCK")

    def test_empty_unregistered_stream_ignored(self):
        self.ws.submit_entry(self.rid, "a", verdict="approve")
        self.ws.submit_entry(self.rid, "b", verdict="approve")
        (self.stream / "zz.jsonl").write_text("")
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "APPROVE")

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


class TestReviewRound3(unittest.TestCase):
    """Fixes from Parallax re-review at f48df76 (MTSMU P1-r2-01 etc., Quilter P1-01 etc.)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wags_r3_")
        self.ws = WagsWorkspace(self.tmp)
        tgt = Path(self.tmp) / "t.md"
        tgt.write_text("# t\n", encoding="utf-8")
        self.rid = self.ws.init_review(tgt, review_id="rev-r3")["review_id"]
        for r in ("a", "b"):
            self.ws.register_reviewer(self.rid, r)
        self.dir = Path(self.tmp) / "reviews" / self.rid

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _go(self, cmd="converge"):
        if shutil.which("go") is None:
            self.skipTest("go not installed")
        import os
        return subprocess.run(["go", "run", "wags.go", cmd, self.rid], cwd=GO_DIR,
                              env=dict(os.environ, WAGS_WORKSPACE=self.tmp),
                              capture_output=True, text=True, timeout=120).stdout

    def _veto_then_converge(self):
        self.ws.submit_entry(self.rid, "a", verdict="approve")
        self.ws.submit_entry(self.rid, "a", findings=[_f("X", "P0")], verdict="block")
        self.ws.submit_entry(self.rid, "b", verdict="approve")
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "BLOCK")  # sets anchors

    # MTSMU P1-r2-01: truncation / deletion vs anchor
    def test_truncation_after_anchor_blocks(self):
        self._veto_then_converge()
        p = self.dir / "a.jsonl"
        p.write_text(p.read_text().splitlines()[0] + "\n")
        self.assertTrue(self.ws.verify_review(self.rid)["valid"])  # hash chain alone can't see it
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["overall_verdict"], "BLOCK")
        self.assertEqual([x["reviewer"] for x in c["regressed_streams"]], ["a"])
        # BLOCK persists (old anchor kept)
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "BLOCK")

    def test_truncation_go_parity(self):
        self._veto_then_converge()
        p = self.dir / "a.jsonl"
        p.write_text(p.read_text().splitlines()[0] + "\n")
        self.assertIn("BLOCK", self._go())

    def test_deleted_and_emptied_stream_block(self):
        self._veto_then_converge()
        (self.dir / "a.jsonl").unlink()
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "BLOCK")
        (self.dir / "a.jsonl").write_text("")
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "BLOCK")

    def test_no_anchor_truncation_is_undetectable(self):
        """Documented limit: without a prior convergence anchor, truncation is invisible."""
        self.ws.submit_entry(self.rid, "a", verdict="approve")
        self.ws.submit_entry(self.rid, "a", findings=[_f("X", "P0")], verdict="block")
        self.ws.submit_entry(self.rid, "b", verdict="approve")
        p = self.dir / "a.jsonl"
        p.write_text(p.read_text().splitlines()[0] + "\n")
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "APPROVE")

    def test_growth_after_anchor_is_fine(self):
        self._veto_then_converge()
        self.ws.submit_entry(self.rid, "a", verdict="approve", resolves=["X"])
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "APPROVE")

    # Quilter P1-01: deregistering a vetoer
    def test_deregistered_vetoer_blocks(self):
        self.ws.submit_entry(self.rid, "a", findings=[_f("X", "P0")], verdict="block")
        self.ws.submit_entry(self.rid, "b", verdict="approve")
        reg = json.loads((self.dir / "reviewers.json").read_text())
        del reg["a"]
        (self.dir / "reviewers.json").write_text(json.dumps(reg))
        self.assertFalse(self.ws.verify_review(self.rid)["valid"])
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["overall_verdict"], "BLOCK")
        self.assertIn("a", c["unregistered_streams"])
        self.assertIn("BLOCK", self._go())

    # Quilter P2-01 / MTSMU registry P2
    def test_wiped_registry_does_not_enable_legacy_on_020(self):
        self.ws.submit_entry(self.rid, "a", verdict="defer")
        self.ws.submit_entry(self.rid, "b", verdict="defer")
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "DEFER")
        (self.dir / "reviewers.json").write_text("{}")
        self.ws.submit_entry(self.rid, "e1", verdict="approve")
        self.ws.submit_entry(self.rid, "e2", verdict="approve")
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["registry_mode"], "registered")
        self.assertEqual(c["overall_verdict"], "BLOCK")
        self.assertIn("BLOCK", self._go())
        (self.dir / "reviewers.json").unlink()
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "BLOCK")

    # Quilter P3-01: legacy hash form only for 0.1.0 targets, never after canonical
    def _restamp_legacy(self, line_no):
        from wags import StreamEntry
        p = self.dir / "a.jsonl"
        lines = p.read_text().splitlines()
        d = json.loads(lines[line_no])
        e = StreamEntry(**{k: d[k] for k in ["sequence", "timestamp", "review_id", "reviewer", "phase",
                                             "prev_hash", "findings", "verdict", "rebuttal_to", "metadata"]})
        d["entry_hash"] = e.compute_legacy_go_hash()
        lines[line_no] = json.dumps(d)
        p.write_text("\n".join(lines) + "\n")

    def test_legacy_hash_rejected_on_020_target(self):
        self.ws.submit_entry(self.rid, "a", findings=[Finding("x", "P2", "s", "<b> & c", "e", "r")], verdict="approve")
        self._restamp_legacy(0)
        self.assertFalse(self.ws.verify_review(self.rid)["valid"])
        self.assertIn("BLOCK", self._go())

    def test_legacy_after_canonical_rejected_on_010_target(self):
        # (legacy-only streams on 0.1.0 targets verify: see TestLegacyGoFixture)
        shutil.rmtree(self.dir)
        self.setUp_review_010()
        self.ws.submit_entry(self.rid, "a", findings=[Finding("x", "P2", "s", "plain", "e", "r")], verdict="approve")
        self.ws.submit_entry(self.rid, "a", findings=[Finding("y", "P2", "s", "<&>", "e", "r")], verdict="approve")
        self._restamp_legacy(1)
        v = self.ws.verify_review(self.rid)
        self.assertFalse(v["valid"])
        self.assertTrue(any("legacy-form" in e for e in v["streams"]["a"]["errors"]))

    def setUp_review_010(self):
        tgt = Path(self.tmp) / "t.md"
        self.ws.init_review(tgt, review_id=self.rid)
        for r in ("a", "b"):
            self.ws.register_reviewer(self.rid, r)
        t = json.loads((self.dir / "target.json").read_text())
        t["protocol_version"] = "0.1.0"
        (self.dir / "target.json").write_text(json.dumps(t))
        # simulate a genuine 0.1.0 workspace (no 0.2.0 markers in index.json)
        ip = Path(self.tmp) / "index.json"
        idx = json.loads(ip.read_text())
        idx["protocol_version"] = "0.1.0"
        idx["reviews"][self.rid].pop("protocol_version", None)
        ip.write_text(json.dumps(idx))

    # MTSMU P2: empty refs
    def test_empty_resolves_supersedes_rejected(self):
        self.ws.submit_entry(self.rid, "a", findings=[_f("X", "P1")], verdict="request_changes")
        for kw in (dict(resolves=[]), dict(supersedes=[])):
            with self.assertRaises(ValueError):
                self.ws.submit_entry(self.rid, "a", verdict="approve", **kw)


class TestReviewRound4(unittest.TestCase):
    """Fixes from round-3 reviews at 05e2974 (Quilter P1-01 / MTSMU P2-a,b,c, Quilter P3s)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wags_r4_")
        self.ws = WagsWorkspace(self.tmp)
        tgt = Path(self.tmp) / "t.md"
        tgt.write_text("# t\n", encoding="utf-8")
        self.rid = self.ws.init_review(tgt, review_id="rev-r4")["review_id"]
        for r in ("a", "b"):
            self.ws.register_reviewer(self.rid, r)
        self.dir = Path(self.tmp) / "reviews" / self.rid

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _go(self, *args):
        if shutil.which("go") is None:
            self.skipTest("go not installed")
        import os
        return subprocess.run(["go", "run", "wags.go", "converge", self.rid, *args], cwd=GO_DIR,
                              env=dict(os.environ, WAGS_WORKSPACE=self.tmp),
                              capture_output=True, text=True, timeout=120).stdout

    def _downgrade(self):
        t = json.loads((self.dir / "target.json").read_text())
        t["protocol_version"] = "0.1.0"
        (self.dir / "target.json").write_text(json.dumps(t))
        (self.dir / "reviewers.json").write_text("{}")

    def _evil(self):
        self.ws.submit_entry(self.rid, "evil", verdict="approve")
        self.ws.submit_entry(self.rid, "evil2", verdict="approve")

    def test_R6d_downgrade_without_anchor_blocks(self):
        self.ws.submit_entry(self.rid, "a", verdict="defer")
        self.ws.submit_entry(self.rid, "b", verdict="defer")
        self._evil()
        self._downgrade()
        self.assertFalse(self.ws.verify_review(self.rid)["valid"])
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["registry_mode"], "registered")
        self.assertEqual(c["overall_verdict"], "BLOCK")
        self.assertIn("BLOCK", self._go())

    def test_R6da_downgrade_after_anchor_blocks_and_persists(self):
        self.ws.submit_entry(self.rid, "a", verdict="defer")
        self.ws.submit_entry(self.rid, "b", verdict="defer")
        self.ws.converge_review(self.rid)
        self._evil()
        self._downgrade()
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["overall_verdict"], "BLOCK")
        self.assertTrue(any("disappeared" in p for p in c["anchor_problems"]))
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "BLOCK")
        self.assertIn("BLOCK", self._go())

    def test_anchor_records_context(self):
        self.ws.submit_entry(self.rid, "a", verdict="approve")
        self.ws.submit_entry(self.rid, "b", verdict="approve")
        c1 = self.ws.converge_review(self.rid)
        self.assertEqual(c1["anchor_status"], "absent")
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["anchor_status"], "present")
        self.assertEqual(c["anchor_context"], {"protocol_version": "0.2.0", "registry_mode": "registered",
                                               "registered_reviewers": ["a", "b"]})
        self.assertEqual(c["overall_verdict"], "APPROVE")

    def test_010_target_with_resolves_fails_closed(self):
        t = json.loads((self.dir / "target.json").read_text())
        t["protocol_version"] = "0.1.0"
        (self.dir / "target.json").write_text(json.dumps(t))
        self.ws.submit_entry(self.rid, "a", findings=[_f("X", "P1")], verdict="request_changes")
        self.ws.submit_entry(self.rid, "a", verdict="approve", resolves=["X"])
        self.ws.submit_entry(self.rid, "b", verdict="approve")
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["overall_verdict"], "BLOCK")
        self.assertTrue(any("resolves/supersedes" in p for p in c["anchor_problems"]))
        self.assertIn("BLOCK", self._go())

    def test_unparseable_converged_blocks_and_persists(self):
        self.ws.submit_entry(self.rid, "a", verdict="approve")
        self.ws.submit_entry(self.rid, "b", verdict="approve")
        self.ws.converge_review(self.rid)
        (self.dir / "converged.json").write_text("garbage")
        self.assertIn("BLOCK", self._go())  # go first on the garbage file
        (self.dir / "converged.json").write_text("garbage")
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["anchor_status"], "unparseable")
        self.assertEqual(c["overall_verdict"], "BLOCK")
        self.assertTrue(c["anchor_lost"])
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "BLOCK")

    def test_unregistered_message_has_no_line_zero(self):
        self.ws.submit_entry(self.rid, "zz", verdict="approve")
        errs = self.ws.verify_review(self.rid)["streams"]["zz"]["errors"]
        self.assertTrue(any("has 1 entry but reviewer is not registered" in e for e in errs))
        self.assertFalse(any("line 0" in e for e in errs))

    def test_R11_quorum_requires_all_registered(self):
        self.ws.register_reviewer(self.rid, "silent")
        self.ws.submit_entry(self.rid, "a", verdict="approve")
        self.ws.submit_entry(self.rid, "b", verdict="approve")
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["overall_verdict"], "DEFER")
        self.assertEqual(c["quorum"]["required"], 3)
        self.assertFalse(c["quorum_met"])
        self.assertIn("DEFER", self._go())
        self.assertEqual(self.ws.converge_review(self.rid, min_quorum=2)["overall_verdict"], "APPROVE")
        self.assertIn("APPROVE", self._go("-min-quorum", "2"))
        self.ws.submit_entry(self.rid, "silent", findings=[_f("S", "P0")], verdict="block")
        self.assertEqual(self.ws.converge_review(self.rid)["overall_verdict"], "BLOCK")

    def test_R5d_downgraded_target_does_not_reenable_legacy_hash(self):
        from wags import StreamEntry
        self.ws.submit_entry(self.rid, "a", findings=[Finding("x", "P2", "s", "<b> & c", "e", "r")], verdict="approve")
        p = self.dir / "a.jsonl"
        d = json.loads(p.read_text())
        e = StreamEntry(**{k: d[k] for k in ["sequence", "timestamp", "review_id", "reviewer", "phase",
                                             "prev_hash", "findings", "verdict", "rebuttal_to", "metadata"]})
        d["entry_hash"] = e.compute_legacy_go_hash()
        p.write_text(json.dumps(d) + "\n")
        t = json.loads((self.dir / "target.json").read_text())
        t["protocol_version"] = "0.1.0"
        (self.dir / "target.json").write_text(json.dumps(t))
        self.assertFalse(self.ws.verify_review(self.rid)["valid"])


class TestReviewRound5(unittest.TestCase):
    """Final round (reviews at 2cf5040): min_quorum validation, chained protocol marker, anchor_status."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wags_r5_")
        self.ws = WagsWorkspace(self.tmp)
        tgt = Path(self.tmp) / "t.md"
        tgt.write_text("# t\n", encoding="utf-8")
        self.tgt = tgt
        self.rid = self.ws.init_review(tgt, review_id="rev-r5")["review_id"]
        for r in ("a", "b", "c"):
            self.ws.register_reviewer(self.rid, r)
        self.dir = Path(self.tmp) / "reviews" / self.rid

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _go(self, *args, rid=None):
        if shutil.which("go") is None:
            self.skipTest("go not installed")
        import os
        return subprocess.run(["go", "run", "wags.go", "converge", rid or self.rid, *args], cwd=GO_DIR,
                              env=dict(os.environ, WAGS_WORKSPACE=self.tmp),
                              capture_output=True, text=True, timeout=120)

    def _pycli(self, *args):
        import sys
        return subprocess.run([sys.executable, "-c", "import sys,wags; sys.exit(wags.main())",
                               "--workspace", self.tmp, "converge", self.rid, *args],
                              capture_output=True, text=True, timeout=60)

    def test_min_quorum_python_cli_rejects_bad_values(self):
        self._two_approve()
        for bad in ("0", "-1", "1.5", "abc", "true", "\u00b2"):
            r = self._pycli("--min-quorum", bad)
            self.assertNotEqual(r.returncode, 0, bad)
            self.assertIn("min_quorum must be a positive integer", r.stderr)
        r = self._pycli("--min-quorum", "2")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def _two_approve(self):
        self.ws.submit_entry(self.rid, "a", verdict="approve")
        self.ws.submit_entry(self.rid, "b", verdict="approve")

    # Finding 1: min_quorum validation
    def test_min_quorum_api_rejects_bad_values(self):
        self._two_approve()
        for bad in (0, -1, -5, 1.5, True, False, "2", "abc", 2.0):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.ws.converge_review(self.rid, min_quorum=bad)
        c = self.ws.converge_review(self.rid, min_quorum=2)
        self.assertEqual(c["overall_verdict"], "APPROVE")
        self.assertEqual(c["quorum"]["min_quorum"], 2)

    def test_min_quorum_cli_rejects_bad_values_py_and_go(self):
        self._two_approve()
        for bad in ("0", "-1", "1.5", "abc", "true", " 2"):
            g = self._go("-min-quorum", bad)
            self.assertNotEqual(g.returncode, 0, bad)
            self.assertIn("min_quorum must be a positive integer", g.stderr)
        g = self._go("-min-quorum", "2")
        self.assertEqual(g.returncode, 0, g.stdout + g.stderr)
        self.assertIn("APPROVE", g.stdout)

    def test_min_quorum_above_registered_defers_with_warning(self):
        self._two_approve()
        self.ws.submit_entry(self.rid, "c", verdict="approve")
        c = self.ws.converge_review(self.rid, min_quorum=5)
        self.assertEqual(c["overall_verdict"], "DEFER")
        self.assertIn("exceeds", c["quorum"]["warning"])
        self.assertIn("DEFER", self._go("-min-quorum", "5").stdout)

    def test_defer_counts_toward_quorum(self):
        self.ws.submit_entry(self.rid, "a", verdict="approve")
        self.ws.submit_entry(self.rid, "b", verdict="approve")
        self.ws.submit_entry(self.rid, "c", verdict="defer")
        c = self.ws.converge_review(self.rid)
        self.assertTrue(c["quorum_met"])
        self.assertEqual(c["overall_verdict"], "APPROVE")

    # Finding 3: hash-chained protocol marker
    def test_new_entries_carry_marker_only_for_020_targets(self):
        e = self.ws.submit_entry(self.rid, "a", verdict="approve")
        self.assertEqual(e.metadata.get("wags_protocol"), "0.2.0")
        t = json.loads((self.dir / "target.json").read_text())
        t["protocol_version"] = "0.1.0"
        (self.dir / "target.json").write_text(json.dumps(t))
        e2 = self.ws.submit_entry(self.rid, "b", verdict="approve")
        self.assertNotIn("wags_protocol", e2.metadata)

    def _ncase(self, anchored, scrub_index, ctx=None):
        self.ws.submit_entry(self.rid, "a", verdict="defer")
        self.ws.submit_entry(self.rid, "b", verdict="defer")
        self.ws.submit_entry(self.rid, "c", verdict="defer")
        if anchored:
            self.ws.converge_review(self.rid)
        self.ws.submit_entry(self.rid, "evil", verdict="approve")
        self.ws.submit_entry(self.rid, "evil2", verdict="approve")
        (self.dir / "reviewers.json").write_text("{}")
        t = json.loads((self.dir / "target.json").read_text())
        t["protocol_version"] = "0.1.0"
        (self.dir / "target.json").write_text(json.dumps(t))
        if scrub_index:
            ip = Path(self.tmp) / "index.json"
            idx = json.loads(ip.read_text())
            idx["protocol_version"] = "0.1.0"
            idx["reviews"][self.rid].pop("protocol_version", None)
            ip.write_text(json.dumps(idx))
        if ctx == "delete_converged":
            (self.dir / "converged.json").unlink()
        elif ctx in ("edit", "remove"):
            c = json.loads((self.dir / "converged.json").read_text())
            if ctx == "edit":
                c["anchor_context"] = {"protocol_version": "0.1.0", "registry_mode": "legacy_all_streams",
                                       "registered_reviewers": []}
            else:
                c.pop("anchor_context")
            (self.dir / "converged.json").write_text(json.dumps(c))
        c = self.ws.converge_review(self.rid)
        self.assertEqual(c["overall_verdict"], "BLOCK")
        self.assertEqual(c["registry_mode"], "registered")
        self.assertIn("BLOCK", self._go().stdout)

    def test_N1_preanchor_downgrade_scrubbed_index(self):
        self._ncase(False, True)

    def test_N2_converged_deleted_scrubbed_index(self):
        self._ncase(True, True, "delete_converged")

    def test_N4_anchor_context_edited_scrubbed_index(self):
        self._ncase(True, True, "edit")

    def test_N5_anchor_context_removed_scrubbed_index(self):
        self._ncase(True, True, "remove")

    # Finding 4
    def test_present_no_context(self):
        for r in "abc":
            self.ws.submit_entry(self.rid, r, verdict="approve")
        self.ws.converge_review(self.rid)
        c = json.loads((self.dir / "converged.json").read_text())
        c.pop("anchor_context")
        (self.dir / "converged.json").write_text(json.dumps(c))
        g = self._go()
        self.assertIn("APPROVE", g.stdout)
        gc = json.loads((self.dir / "converged.json").read_text())
        (self.dir / "converged.json").write_text(json.dumps(c))
        out = self.ws.converge_review(self.rid)
        self.assertEqual(out["anchor_status"], "present_no_context")
        self.assertEqual(gc["anchor_status"], "present_no_context")
        self.assertEqual(out["overall_verdict"], "APPROVE")


class TestConcurrentConverge(unittest.TestCase):
    def test_parallel_converges_never_see_partial_files(self):
        import concurrent.futures as cf
        tmp = tempfile.mkdtemp(prefix="wags_cc_")
        try:
            ws = WagsWorkspace(tmp)
            t = Path(tmp) / "t.md"
            t.write_text("x")
            rid = ws.init_review(t, review_id="rev-cc")["review_id"]
            for r in ("a", "b"):
                ws.register_reviewer(rid, r)
                ws.submit_entry(rid, r, verdict="approve")
            ws.converge_review(rid)
            with cf.ThreadPoolExecutor(8) as ex:
                res = list(ex.map(lambda _: WagsWorkspace(tmp).converge_review(rid)["overall_verdict"], range(32)))
            self.assertEqual(set(res), {"APPROVE"})
            json.loads((Path(tmp) / "reviews" / rid / "converged.json").read_text())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestReviewRound6(unittest.TestCase):
    """Round-5 P3s: min_quorum CLI parity, durable/loud writes."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wags_r6_")
        self.ws = WagsWorkspace(self.tmp)
        t = Path(self.tmp) / "t.md"
        t.write_text("x")
        self.rid = self.ws.init_review(t, review_id="rev-r6")["review_id"]
        for r in ("a", "b"):
            self.ws.register_reviewer(self.rid, r)
            self.ws.submit_entry(self.rid, r, verdict="approve")
        self.dir = Path(self.tmp) / "reviews" / self.rid

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _cli(self, *args):
        import sys
        py = subprocess.run([sys.executable, "-c", "import sys,wags; sys.exit(wags.main())",
                             "--workspace", self.tmp, "converge", self.rid, *args],
                            capture_output=True, text=True, timeout=60)
        if shutil.which("go") is None:
            return py, None
        import os
        go = subprocess.run(["go", "run", "wags.go", "converge", self.rid, *args], cwd=GO_DIR,
                            env=dict(os.environ, WAGS_WORKSPACE=self.tmp), capture_output=True, text=True, timeout=120)
        return py, go

    def test_empty_and_huge_min_quorum_rejected_same_message(self):
        for bad in ("", "100000000000000000000", "1000001"):
            py, _ = self._cli("--min-quorum", bad)
            go = shutil.which("go")
            want = f"min_quorum must be a positive integer (1..1000000); got '{bad}'"
            self.assertNotEqual(py.returncode, 0)
            self.assertIn(want, py.stderr)
            if go is not None:
                go = subprocess.run(["go", "run", "wags.go", "converge", self.rid, "-min-quorum", bad], cwd=GO_DIR,
                                    env=dict(__import__("os").environ, WAGS_WORKSPACE=self.tmp),
                                    capture_output=True, text=True, timeout=120)
                self.assertNotEqual(go.returncode, 0, bad)
                self.assertIn(want, go.stderr)
        with self.assertRaises(ValueError):
            self.ws.converge_review(self.rid, min_quorum=10 ** 20)
        self.assertEqual(self.ws.converge_review(self.rid, min_quorum=1_000_000)["overall_verdict"], "DEFER")

    def test_converge_write_failure_is_loud(self):
        (self.dir / "converged.json").mkdir()  # rename over a directory fails
        with self.assertRaises(OSError):
            self.ws.converge_review(self.rid)
        py, go = self._cli()
        self.assertNotEqual(py.returncode, 0)
        self.assertIn("failed to write", py.stderr)
        if go is not None:
            self.assertNotEqual(go.returncode, 0)
            self.assertIn("failed to write converged.json", go.stderr)
        self.assertEqual([p.name for p in self.dir.iterdir() if p.name.endswith(".tmp")], [])

    def test_atomic_write_fsyncs_and_retries_on_permission_error(self):
        import os
        import wags as W
        calls = {"fsync": 0, "replace": 0}
        real_fsync, real_replace = os.fsync, os.replace

        def fake_fsync(fd):
            calls["fsync"] += 1
            return real_fsync(fd)

        def flaky_replace(a, b):
            calls["replace"] += 1
            if calls["replace"] < 3:
                raise PermissionError("held open (simulated Windows)")
            return real_replace(a, b)
        target = Path(self.tmp) / "x.json"
        from unittest import mock
        with mock.patch.object(os, "fsync", fake_fsync), mock.patch.object(os, "replace", flaky_replace):
            W._atomic_write_json(target, {"ok": 1})
        self.assertEqual(json.loads(target.read_text()), {"ok": 1})
        self.assertGreaterEqual(calls["fsync"], 1)
        self.assertEqual(calls["replace"], 3)

        def always_fail(a, b):
            raise PermissionError("held open forever")
        with mock.patch.object(os, "replace", always_fail), mock.patch("time.sleep", lambda s: None):
            with self.assertRaises(PermissionError):
                W._atomic_write_json(target, {"ok": 2})
        self.assertEqual(json.loads(target.read_text()), {"ok": 1})
        self.assertEqual([p.name for p in Path(self.tmp).iterdir() if p.name.endswith(".tmp")], [])
