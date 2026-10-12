"""Unit and integration tests for wags v0.1.0 reference engine.

100% stdlib - runnable air-gapped without external dependencies.
"""

import json
from pathlib import Path
import shutil
import tempfile
import unittest

from wags import Finding, PROTOCOL_VERSION, StreamEntry, WagsWorkspace


class TestWagsEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="wags_test_")
        self.workspace = WagsWorkspace(self.temp_dir)
        # Create a mock target file
        self.target_file = Path(self.temp_dir) / "sample_module.py"
        self.target_file.write_text("def process_queue(items):\n    return items.pop()\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init_review(self):
        res = self.workspace.init_review(
            target_path=self.target_file,
            target_type="code",
            description="Queue processing unit",
            initiator="gemini",
        )
        self.assertIn("review_id", res)
        self.assertEqual(res["protocol_version"], PROTOCOL_VERSION)
        self.assertEqual(res["target"]["type"], "code")
        self.assertTrue(len(res["target"]["sha256"]) == 64)

    def test_reviewer_registration_and_hash_chaining(self):
        rev = self.workspace.init_review(self.target_file)
        review_id = rev["review_id"]

        self.workspace.register_reviewer(review_id, "alice", secret_key="devin_secret")
        self.workspace.register_reviewer(review_id, "codex", secret_key="codex_secret")

        # Entry 1 by alice
        f1 = Finding(
            id="alice-P1-01",
            severity="P1",
            surface="queue_safety",
            finding="items.pop() raises IndexError on empty list",
            evidence="sample_module.py:2",
            recommendation="Add empty guard",
        )
        e1 = self.workspace.submit_entry(
            review_id=review_id,
            reviewer_name="alice",
            phase="review",
            findings=[f1],
            verdict="request_changes",
            secret_key="devin_secret",
        )
        self.assertEqual(e1.sequence, 1)
        self.assertEqual(e1.prev_hash, "0000000000000000000000000000000000000000000000000000000000000000")
        self.assertTrue(len(e1.entry_hash) == 64)
        self.assertTrue(len(e1.signature) == 64)

        # Entry 2 by alice (rebuttal/update)
        e2 = self.workspace.submit_entry(
            review_id=review_id,
            reviewer_name="alice",
            phase="meta-review",
            verdict="approve",
            secret_key="devin_secret",
        )
        self.assertEqual(e2.sequence, 2)
        self.assertEqual(e2.prev_hash, e1.entry_hash)

        # Verify integrity
        ver = self.workspace.verify_review(review_id, keys={"alice": "devin_secret", "codex": "codex_secret"})
        self.assertTrue(ver["valid"])
        self.assertTrue(ver["streams"]["alice"]["valid"])

    def test_tamper_detection(self):
        rev = self.workspace.init_review(self.target_file)
        review_id = rev["review_id"]

        self.workspace.register_reviewer(review_id, "alice")
        self.workspace.submit_entry(review_id, "alice", phase="review", verdict="approve")
        self.workspace.submit_entry(review_id, "alice", phase="convergence", verdict="approve")

        # Mutate the first line in alice.jsonl
        stream_file = Path(self.temp_dir) / "reviews" / review_id / "alice.jsonl"
        lines = stream_file.read_text(encoding="utf-8").splitlines()
        tampered_entry = json.loads(lines[0])
        tampered_entry["verdict"] = "block"  # maliciously altered
        lines[0] = json.dumps(tampered_entry)
        stream_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # Verify must fail
        ver = self.workspace.verify_review(review_id)
        self.assertFalse(ver["valid"])
        self.assertFalse(ver["streams"]["alice"]["valid"])

    def test_consensus_p0_veto(self):
        rev = self.workspace.init_review(self.target_file)
        review_id = rev["review_id"]

        self.workspace.register_reviewer(review_id, "alice")
        self.workspace.register_reviewer(review_id, "codex")
        self.workspace.register_reviewer(review_id, "gemini")

        # alice approves
        self.workspace.submit_entry(review_id, "alice", phase="review", verdict="approve")

        # Gemini approves
        self.workspace.submit_entry(review_id, "gemini", phase="review", verdict="approve")

        # Codex finds a P0 critical vulnerability and blocks
        p0_finding = Finding(
            id="codex-P0-01",
            severity="P0",
            surface="security",
            finding="Arbitrary code execution path identified",
            evidence="sample_module.py:1",
            recommendation="Remove unvalidated eval",
        )
        self.workspace.submit_entry(
            review_id,
            "codex",
            phase="review",
            findings=[p0_finding],
            verdict="block",
        )

        conv = self.workspace.converge_review(review_id)
        self.assertEqual(conv["overall_verdict"], "BLOCK")
        self.assertIn("P0", conv["rationale"])
        self.assertEqual(len(conv["blocking_findings"]), 1)

    def test_consensus_majority_approval(self):
        rev = self.workspace.init_review(self.target_file)
        review_id = rev["review_id"]

        self.workspace.register_reviewer(review_id, "alice")
        self.workspace.register_reviewer(review_id, "gemini")

        # alice submits a minor P2 polish note and approves
        p2_finding = Finding(
            id="alice-P2-01",
            severity="P2",
            surface="docs",
            finding="Add docstring for return type",
            evidence="sample_module.py:1",
            recommendation="Add -> Any type hint",
        )
        self.workspace.submit_entry(review_id, "alice", phase="review", findings=[p2_finding], verdict="approve")
        self.workspace.submit_entry(review_id, "gemini", phase="review", verdict="approve")

        conv = self.workspace.converge_review(review_id)
        self.assertEqual(conv["overall_verdict"], "APPROVE")
        self.assertTrue(conv["quorum_met"])
        self.assertEqual(conv["summary"]["findings_by_severity"]["P2"], 1)
        self.assertEqual(conv["summary"]["findings_by_severity"]["P0"], 0)


if __name__ == "__main__":
    unittest.main()
