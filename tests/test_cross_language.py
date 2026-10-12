"""Cross-language compatibility integration test for wags (Python <-> Go).

Tests that Go can verify Python-written entries and vice versa, including:
- Go verify on a valid Python workspace reports VERIFIED
- Go verify on a tampered Python workspace reports FAILED
- Go verify on a non-existent review reports FAILED
- Go converge on a Python workspace produces the same verdict as Python
"""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from wags import Finding, WagsWorkspace

GO_DIR = Path(__file__).parent.parent / "wags" / "go"


def _go_env(workspace: str) -> dict:
    """Build env for Go subprocess with WAGS_WORKSPACE set."""
    env = dict(os.environ)
    env["WAGS_WORKSPACE"] = workspace
    return env


def _go_verify(review_id: str, workspace: str) -> subprocess.CompletedProcess:
    """Run Go verify CLI against the given workspace."""
    return subprocess.run(
        ["go", "run", "wags.go", "verify", review_id],
        cwd=str(GO_DIR),
        env=_go_env(workspace),
        capture_output=True,
        text=True,
        timeout=60,
    )


def _go_converge(review_id: str, workspace: str) -> subprocess.CompletedProcess:
    """Run Go converge CLI against the given workspace."""
    return subprocess.run(
        ["go", "run", "wags.go", "converge", review_id],
        cwd=str(GO_DIR),
        env=_go_env(workspace),
        capture_output=True,
        text=True,
        timeout=60,
    )


class TestCrossLanguageCompatibility(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="wags_cross_")
        self.target_file = Path(self.temp_dir) / "shared_spec.md"
        self.target_file.write_text(
            "# Shared Specification\n\nMust support polyglot multi-agent consensus.\n",
            encoding="utf-8",
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_go_verifies_valid_python_workspace(self):
        """Go CLI reports VERIFIED for a workspace created and signed by Python."""
        ws = WagsWorkspace(self.temp_dir)
        rev = ws.init_review(
            target_path=self.target_file,
            target_type="doc",
            description="Polyglot specification review",
            initiator="py-agent",
            review_id="rev-cross-valid-001",
        )
        review_id = rev["review_id"]

        ws.register_reviewer(review_id, "py-reviewer", secret_key="py_secret")
        f_py = Finding(
            id="py-P2-01",
            severity="P2",
            surface="spec",
            finding="Add JSON schema formal specification reference",
            evidence="shared_spec.md:3",
            recommendation="Link to wags-protocol.md",
        )
        ws.submit_entry(
            review_id, "py-reviewer", phase="review",
            findings=[f_py], verdict="approve", secret_key="py_secret",
        )

        result = _go_verify(review_id, self.temp_dir)
        self.assertEqual(
            result.returncode, 0,
            f"Go verify should succeed on valid Python workspace. "
            f"stdout={result.stdout!r}, stderr={result.stderr!r}",
        )
        self.assertIn("VERIFIED", result.stdout)

    def test_go_rejects_tampered_python_workspace(self):
        """Go CLI reports FAILED when a Python-written entry is tampered."""
        ws = WagsWorkspace(self.temp_dir)
        rev = ws.init_review(
            target_path=self.target_file,
            review_id="rev-cross-tamper-001",
        )
        review_id = rev["review_id"]

        ws.register_reviewer(review_id, "py-reviewer")
        ws.submit_entry(
            review_id, "py-reviewer", phase="review", verdict="approve",
        )

        # Tamper with the verdict in the JSONL
        stream_file = Path(self.temp_dir) / "reviews" / review_id / "py-reviewer.jsonl"
        lines = stream_file.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[0])
        entry["verdict"] = "block"  # malicious alteration
        lines[0] = json.dumps(entry)
        stream_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = _go_verify(review_id, self.temp_dir)
        self.assertNotEqual(
            result.returncode, 0,
            f"Go verify should fail on tampered workspace. stdout={result.stdout!r}",
        )
        self.assertIn("FAILED", result.stdout)

    def test_go_rejects_nonexistent_review(self):
        """Go CLI reports FAILED for a review ID that doesn't exist."""
        ws = WagsWorkspace(self.temp_dir)
        ws.init_review(
            target_path=self.target_file,
            review_id="rev-cross-real-001",
        )

        result = _go_verify("rev-does-not-exist-999", self.temp_dir)
        self.assertNotEqual(
            result.returncode, 0,
            f"Go verify should fail for non-existent review. stdout={result.stdout!r}",
        )

    def test_go_converge_matches_python_verdict(self):
        """Go converge produces the same overall verdict as Python converge."""
        ws = WagsWorkspace(self.temp_dir)
        rev = ws.init_review(
            target_path=self.target_file,
            review_id="rev-cross-converge-001",
        )
        review_id = rev["review_id"]

        ws.register_reviewer(review_id, "alice")
        ws.register_reviewer(review_id, "gemini")

        p2 = Finding(
            id="alice-P2-01", severity="P2", surface="docs",
            finding="Add docstring", evidence="shared_spec.md:1",
            recommendation="Add type hint",
        )
        ws.submit_entry(
            review_id, "alice", phase="review",
            findings=[p2], verdict="approve",
        )
        ws.submit_entry(review_id, "gemini", phase="review", verdict="approve")

        # Python converge
        py_conv = ws.converge_review(review_id)
        self.assertEqual(py_conv["overall_verdict"], "APPROVE")

        # Go converge
        result = _go_converge(review_id, self.temp_dir)
        self.assertEqual(
            result.returncode, 0,
            f"Go converge should succeed. stdout={result.stdout!r}, stderr={result.stderr!r}",
        )
        self.assertIn("APPROVE", result.stdout)


if __name__ == "__main__":
    unittest.main()
