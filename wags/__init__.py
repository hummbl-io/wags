"""wags - Lightweight, polyglot, air-gappable multi-agent peer review protocol engine.

Reference Implementation (v0.1.0)
Stdlib-only: zero third-party runtime dependencies.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Tuple

PROTOCOL_VERSION = "0.1.0"
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def _canonical_json(data: Any) -> str:
    """Deterministic JSON serialization without whitespace drift."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _compute_sha256(content_bytes: bytes) -> str:
    return hashlib.sha256(content_bytes).hexdigest()


def _now_iso_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class Finding:
    id: str
    severity: str  # P0, P1, P2, P3, N
    surface: str
    finding: str
    evidence: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StreamEntry:
    sequence: int
    timestamp: str
    review_id: str
    reviewer: str
    phase: str  # review, rebuttal, meta-review, convergence
    prev_hash: str
    findings: List[Dict[str, Any]]
    verdict: Optional[str]  # approve, request_changes, block, defer
    rebuttal_to: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    entry_hash: str = ""
    signature: str = ""

    def compute_hash(self) -> str:
        payload = {
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "review_id": self.review_id,
            "reviewer": self.reviewer,
            "phase": self.phase,
            "prev_hash": self.prev_hash,
            "findings": self.findings,
            "verdict": self.verdict,
            "rebuttal_to": self.rebuttal_to,
            "metadata": self.metadata,
        }
        return _compute_sha256(_canonical_json(payload).encode("utf-8"))

    def sign(self, secret_key: Optional[str]) -> None:
        self.entry_hash = self.compute_hash()
        if secret_key:
            sig = hmac.new(
                secret_key.encode("utf-8"),
                self.entry_hash.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            self.signature = sig
        else:
            self.signature = ""

    def verify_entry(self, secret_key: Optional[str] = None) -> Tuple[bool, str]:
        expected_hash = self.compute_hash()
        if self.entry_hash != expected_hash:
            return False, f"Hash mismatch: stored {self.entry_hash} != computed {expected_hash}"
        if secret_key and self.signature:
            expected_sig = hmac.new(
                secret_key.encode("utf-8"),
                self.entry_hash.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(self.signature, expected_sig):
                return False, "HMAC signature verification failed"
        return True, "OK"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class WagsWorkspace:
    """Air-gapped filesystem workspace managing wags peer reviews."""

    def __init__(self, workspace_root: Optional[Path | str] = None):
        if workspace_root is None:
            workspace_root = Path.cwd() / ".wags"
        self.root = Path(workspace_root).resolve()
        self.reviews_dir = self.root / "reviews"
        self.index_file = self.root / "index.json"
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.reviews_dir.mkdir(parents=True, exist_ok=True)
        if not self.index_file.exists():
            self._write_index({"protocol_version": PROTOCOL_VERSION, "reviews": {}})

    def _read_index(self) -> Dict[str, Any]:
        try:
            with open(self.index_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"protocol_version": PROTOCOL_VERSION, "reviews": {}}

    def _write_index(self, data: Dict[str, Any]) -> None:
        with open(self.index_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def init_review(
        self,
        target_path: Path | str,
        target_type: str = "code",
        description: str = "",
        initiator: str = "gemini",
        review_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        target_p = Path(target_path).resolve()
        if not target_p.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_p}")

        content_bytes = target_p.read_bytes()
        target_sha256 = _compute_sha256(content_bytes)

        if not review_id:
            ts_compact = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
            short_hash = target_sha256[:8]
            review_id = f"rev-{ts_compact}-{short_hash}"

        rev_dir = self.reviews_dir / review_id
        rev_dir.mkdir(parents=True, exist_ok=True)

        target_manifest = {
            "protocol_version": PROTOCOL_VERSION,
            "review_id": review_id,
            "created_at": _now_iso_utc(),
            "initiator": initiator,
            "target": {
                "type": target_type,
                "path": str(target_p),
                "sha256": target_sha256,
                "size_bytes": len(content_bytes),
                "description": description or target_p.name,
            },
            "phases": ["review", "rebuttal", "meta-review", "convergence"],
            "current_phase": "review",
            "status": "OPEN",
        }

        with open(rev_dir / "target.json", "w", encoding="utf-8") as f:
            json.dump(target_manifest, f, indent=2, ensure_ascii=False)

        with open(rev_dir / "reviewers.json", "w", encoding="utf-8") as f:
            json.dump({}, f, indent=2, ensure_ascii=False)

        # Update index
        idx = self._read_index()
        idx.setdefault("reviews", {})[review_id] = {
            "target": str(target_p),
            "target_sha256": target_sha256,
            "created_at": target_manifest["created_at"],
            "status": "OPEN",
        }
        self._write_index(idx)

        return target_manifest

    def register_reviewer(
        self,
        review_id: str,
        reviewer_name: str,
        secret_key: Optional[str] = None,
        role: str = "reviewer",
    ) -> Dict[str, Any]:
        rev_dir = self.reviews_dir / review_id
        if not rev_dir.exists():
            raise ValueError(f"Review {review_id} not found")

        reg_file = rev_dir / "reviewers.json"
        data = {}
        if reg_file.exists():
            with open(reg_file, "r", encoding="utf-8") as f:
                data = json.load(f)

        data[reviewer_name] = {
            "registered_at": _now_iso_utc(),
            "role": role,
            "has_hmac": bool(secret_key),
        }

        with open(reg_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        # Ensure reviewer JSONL file exists
        stream_path = rev_dir / f"{reviewer_name}.jsonl"
        if not stream_path.exists():
            stream_path.touch()

        return data[reviewer_name]

    def _get_reviewer_last_entry(self, review_id: str, reviewer_name: str) -> Tuple[int, str]:
        stream_path = self.reviews_dir / review_id / f"{reviewer_name}.jsonl"
        if not stream_path.exists():
            return 0, GENESIS_HASH

        last_seq = 0
        last_hash = GENESIS_HASH
        with open(stream_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    last_seq = entry.get("sequence", last_seq)
                    last_hash = entry.get("entry_hash", last_hash)
                except Exception:
                    pass
        return last_seq, last_hash

    def submit_entry(
        self,
        review_id: str,
        reviewer_name: str,
        phase: str = "review",
        findings: Optional[List[Dict[str, Any] | Finding]] = None,
        verdict: Optional[str] = None,
        rebuttal_to: Optional[str] = None,
        secret_key: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> StreamEntry:
        rev_dir = self.reviews_dir / review_id
        if not rev_dir.exists():
            raise ValueError(f"Review {review_id} not found")

        findings_dicts: List[Dict[str, Any]] = []
        if findings:
            for item in findings:
                if isinstance(item, Finding):
                    findings_dicts.append(item.to_dict())
                elif isinstance(item, dict):
                    findings_dicts.append(item)

        last_seq, prev_hash = self._get_reviewer_last_entry(review_id, reviewer_name)
        new_seq = last_seq + 1

        entry = StreamEntry(
            sequence=new_seq,
            timestamp=_now_iso_utc(),
            review_id=review_id,
            reviewer=reviewer_name,
            phase=phase,
            prev_hash=prev_hash,
            findings=findings_dicts,
            verdict=verdict,
            rebuttal_to=rebuttal_to,
            metadata=metadata or {},
        )
        entry.sign(secret_key)

        stream_path = rev_dir / f"{reviewer_name}.jsonl"
        with open(stream_path, "a", encoding="utf-8") as f:
            f.write(_canonical_json(entry.to_dict()) + "\n")

        return entry

    def tail_review(self, review_id: str) -> List[StreamEntry]:
        rev_dir = self.reviews_dir / review_id
        if not rev_dir.exists():
            raise ValueError(f"Review {review_id} not found")

        all_entries: List[StreamEntry] = []
        for path in rev_dir.glob("*.jsonl"):
            reviewer_name = path.stem
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                        all_entries.append(
                            StreamEntry(
                                sequence=d["sequence"],
                                timestamp=d["timestamp"],
                                review_id=d["review_id"],
                                reviewer=d["reviewer"],
                                phase=d["phase"],
                                prev_hash=d["prev_hash"],
                                findings=d.get("findings", []),
                                verdict=d.get("verdict"),
                                rebuttal_to=d.get("rebuttal_to"),
                                metadata=d.get("metadata", {}),
                                entry_hash=d.get("entry_hash", ""),
                                signature=d.get("signature", ""),
                            )
                        )
                    except Exception:
                        pass

        # Sort chronologically by timestamp and sequence
        all_entries.sort(key=lambda e: (e.timestamp, e.sequence))
        return all_entries

    def verify_review(self, review_id: str, keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        rev_dir = self.reviews_dir / review_id
        if not rev_dir.exists():
            raise ValueError(f"Review {review_id} not found")

        keys = keys or {}
        results: Dict[str, Any] = {"review_id": review_id, "streams": {}, "valid": True}

        for path in rev_dir.glob("*.jsonl"):
            reviewer = path.stem
            stream_valid = True
            errors = []
            expected_prev = GENESIS_HASH

            with open(path, "r", encoding="utf-8") as f:
                for idx, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                        entry = StreamEntry(
                            sequence=d["sequence"],
                            timestamp=d["timestamp"],
                            review_id=d["review_id"],
                            reviewer=d["reviewer"],
                            phase=d["phase"],
                            prev_hash=d["prev_hash"],
                            findings=d.get("findings", []),
                            verdict=d.get("verdict"),
                            rebuttal_to=d.get("rebuttal_to"),
                            metadata=d.get("metadata", {}),
                            entry_hash=d.get("entry_hash", ""),
                            signature=d.get("signature", ""),
                        )
                        # Check prev_hash link
                        if entry.prev_hash != expected_prev:
                            stream_valid = False
                            errors.append(
                                f"Line {idx} sequence {entry.sequence}: prev_hash mismatch "
                                f"got {entry.prev_hash} expected {expected_prev}"
                            )

                        # Check cryptographic integrity
                        secret_key = keys.get(reviewer)
                        ok, msg = entry.verify_entry(secret_key)
                        if not ok:
                            stream_valid = False
                            errors.append(f"Line {idx} sequence {entry.sequence}: {msg}")

                        expected_prev = entry.entry_hash
                    except Exception as ex:
                        stream_valid = False
                        errors.append(f"Line {idx} parse error: {ex}")

            results["streams"][reviewer] = {
                "valid": stream_valid,
                "errors": errors,
            }
            if not stream_valid:
                results["valid"] = False

        return results

    def converge_review(self, review_id: str) -> Dict[str, Any]:
        """Compute final consensus verdict using P0-Veto + Majority Approval rules."""
        rev_dir = self.reviews_dir / review_id
        if not rev_dir.exists():
            raise ValueError(f"Review {review_id} not found")

        target_file = rev_dir / "target.json"
        with open(target_file, "r", encoding="utf-8") as f:
            target_data = json.load(f)

        # Collect latest verdict and all findings per reviewer
        reviewer_latest_verdicts: Dict[str, str] = {}
        all_findings: List[Dict[str, Any]] = []
        severity_counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "N": 0}
        blocking_findings: List[Dict[str, Any]] = []

        for path in rev_dir.glob("*.jsonl"):
            reviewer = path.stem
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                        if d.get("verdict"):
                            reviewer_latest_verdicts[reviewer] = d["verdict"]
                        for finding in d.get("findings", []):
                            all_findings.append(finding)
                            sev = finding.get("severity", "N").upper()
                            severity_counts[sev] = severity_counts.get(sev, 0) + 1
                            if sev == "P0" or (sev == "P1" and d.get("verdict") == "block"):
                                blocking_findings.append(finding)
                    except Exception:
                        pass

        total_reviewers = len(reviewer_latest_verdicts)
        verdict_counts = {"approve": 0, "request_changes": 0, "block": 0, "defer": 0}
        for v in reviewer_latest_verdicts.values():
            normalized_v = v.lower()
            verdict_counts[normalized_v] = verdict_counts.get(normalized_v, 0) + 1

        # Consensus Evaluation
        if severity_counts.get("P0", 0) > 0 or verdict_counts.get("block", 0) > 0:
            overall_verdict = "BLOCK"
            rationale = f"Blocked by {severity_counts.get('P0', 0)} P0 critical finding(s) or explicit block vote."
        elif severity_counts.get("P1", 0) > 0 or verdict_counts.get("request_changes", 0) > 0:
            overall_verdict = "REQUEST_CHANGES"
            rationale = f"Changes required: {severity_counts.get('P1', 0)} P1 finding(s) or request_changes vote(s)."
        elif total_reviewers > 0 and (verdict_counts.get("approve", 0) >= (total_reviewers / 2.0)):
            overall_verdict = "APPROVE"
            rationale = f"Approved by majority ({verdict_counts.get('approve', 0)}/{total_reviewers}) with 0 blockers."
        else:
            overall_verdict = "DEFER"
            rationale = "Insufficient quorum or inconclusive vote."

        converged_manifest = {
            "protocol_version": PROTOCOL_VERSION,
            "review_id": review_id,
            "converged_at": _now_iso_utc(),
            "target": target_data.get("target", {}),
            "overall_verdict": overall_verdict,
            "rationale": rationale,
            "quorum_met": total_reviewers > 0,
            "summary": {
                "total_reviewers": total_reviewers,
                "verdicts": verdict_counts,
                "findings_by_severity": severity_counts,
            },
            "blocking_findings": blocking_findings,
            "all_findings": all_findings,
        }

        with open(rev_dir / "converged.json", "w", encoding="utf-8") as f:
            json.dump(converged_manifest, f, indent=2, ensure_ascii=False)

        # Update target status
        target_data["status"] = "CONVERGED"
        target_data["current_phase"] = "convergence"
        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(target_data, f, indent=2, ensure_ascii=False)

        return converged_manifest


def main() -> int:
    parser = argparse.ArgumentParser(prog="wags", description="wags Multi-Agent Peer Review CLI")
    parser.add_argument("--workspace", "-w", help="Path to .wags workspace directory", default=None)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = subparsers.add_parser("init", help="Initialize a new review for a target file")
    p_init.add_argument("target", help="Path to artifact/code/doc file to review")
    p_init.add_argument("--type", default="code", choices=["code", "doc", "proposal", "artifact"])
    p_init.add_argument("--desc", default="", help="Description of the target")
    p_init.add_argument("--initiator", default="gemini", help="Initiating agent name")
    p_init.add_argument("--id", default=None, help="Custom review ID")

    # add-reviewer
    p_reg = subparsers.add_parser("add-reviewer", help="Register a reviewer for a review")
    p_reg.add_argument("review_id", help="Target review ID")
    p_reg.add_argument("--reviewer", required=True, help="Reviewer agent/human identifier")
    p_reg.add_argument("--role", default="reviewer", help="Reviewer role")
    p_reg.add_argument("--secret", default=None, help="Optional HMAC secret key")

    # submit
    p_sub = subparsers.add_parser("submit", help="Submit a review entry or findings")
    p_sub.add_argument("review_id", help="Target review ID")
    p_sub.add_argument("--reviewer", required=True, help="Reviewer agent identifier")
    p_sub.add_argument("--phase", default="review", choices=["review", "rebuttal", "meta-review", "convergence"])
    p_sub.add_argument("--verdict", default=None, choices=["approve", "request_changes", "block", "defer"])
    p_sub.add_argument("--sev", default="P2", choices=["P0", "P1", "P2", "P3", "N"], help="Severity for finding")
    p_sub.add_argument("--surface", default="general", help="Target surface/component")
    p_sub.add_argument("--finding", default=None, help="Finding description statement")
    p_sub.add_argument("--evidence", default="", help="Evidence citation (e.g. file:line)")
    p_sub.add_argument("--recommendation", default="", help="Recommended remediation")
    p_sub.add_argument("--secret", default=None, help="HMAC secret key")

    # tail
    p_tail = subparsers.add_parser("tail", help="Tail and view all entries in a review chronologically")
    p_tail.add_argument("review_id", help="Review ID")

    # verify
    p_ver = subparsers.add_parser("verify", help="Verify hash chains and signatures for a review")
    p_ver.add_argument("review_id", help="Review ID")

    # converge
    p_conv = subparsers.add_parser("converge", help="Calculate consensus and converge review")
    p_conv.add_argument("review_id", help="Review ID")

    # list
    subparsers.add_parser("list", help="List all reviews in the workspace")

    args = parser.parse_args()
    ws = WagsWorkspace(args.workspace)

    if args.command == "init":
        res = ws.init_review(
            target_path=args.target,
            target_type=args.type,
            description=args.desc,
            initiator=args.initiator,
            review_id=args.id,
        )
        print(f"[wags] Initialized review {res['review_id']} for target {res['target']['path']}")
        print(f"[wags] SHA256: {res['target']['sha256']}")
        return 0

    elif args.command == "add-reviewer":
        res = ws.register_reviewer(
            review_id=args.review_id,
            reviewer_name=args.reviewer,
            secret_key=args.secret,
            role=args.role,
        )
        print(f"[wags] Registered reviewer '{args.reviewer}' on review {args.review_id}")
        return 0

    elif args.command == "submit":
        findings_list = []
        if args.finding:
            finding_id = f"{args.reviewer}-{args.sev}-01"
            findings_list.append(
                Finding(
                    id=finding_id,
                    severity=args.sev,
                    surface=args.surface,
                    finding=args.finding,
                    evidence=args.evidence,
                    recommendation=args.recommendation,
                )
            )
        entry = ws.submit_entry(
            review_id=args.review_id,
            reviewer_name=args.reviewer,
            phase=args.phase,
            findings=findings_list,
            verdict=args.verdict,
            secret_key=args.secret,
        )
        print(f"[wags] Appended entry seq={entry.sequence} for reviewer '{args.reviewer}' (hash: {entry.entry_hash[:12]}...)")
        return 0

    elif args.command == "tail":
        entries = ws.tail_review(args.review_id)
        print(f"=== wags tail: {args.review_id} ({len(entries)} total entries) ===")
        for e in entries:
            verdict_str = f" [verdict: {e.verdict}]" if e.verdict else ""
            print(f"[{e.timestamp}] {e.reviewer} (seq {e.sequence}, phase {e.phase}){verdict_str}")
            for f in e.findings:
                print(f"  - [{f.get('severity')}] {f.get('id')}: {f.get('finding')} (Evidence: {f.get('evidence')})")
        return 0

    elif args.command == "verify":
        res = ws.verify_review(args.review_id)
        if res["valid"]:
            print(f"[wags] Review {args.review_id} integrity: VERIFIED (All hash chains & signatures valid)")
            return 0
        else:
            print(f"[wags] Review {args.review_id} integrity: FAILED")
            for rev, detail in res["streams"].items():
                if not detail["valid"]:
                    print(f"  Stream '{rev}': {detail['errors']}")
            return 1

    elif args.command == "converge":
        res = ws.converge_review(args.review_id)
        print(f"=== wags Convergence Report: {args.review_id} ===")
        print(f"Overall Verdict: {res['overall_verdict']}")
        print(f"Rationale:       {res['rationale']}")
        print(f"Summary:         {json.dumps(res['summary'], indent=2)}")
        return 0

    elif args.command == "list":
        idx = ws._read_index()
        reviews = idx.get("reviews", {})
        print(f"=== wags Workspace Catalog ({len(reviews)} reviews) ===")
        for rid, meta in reviews.items():
            print(f"- {rid} [{meta.get('status')}] Target: {meta.get('target')} (Created: {meta.get('created_at')})")
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
