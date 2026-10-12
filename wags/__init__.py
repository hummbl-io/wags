"""wags - Lightweight, polyglot, air-gappable multi-agent peer review protocol engine.

Reference Implementation (v0.2.0)
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

PROTOCOL_VERSION = "0.2.0"
MAX_MIN_QUORUM = 1_000_000  # same bound in Go; larger values are rejected, not DEFERred


def validate_min_quorum(value: Any) -> Optional[int]:
    """None (default: all registered reviewers) or an int in 1..MAX_MIN_QUORUM. Rejects
    bools, floats, strings, 0, negatives and oversized values. Identical rule in Go."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > MAX_MIN_QUORUM:
        raise ValueError(f"min_quorum must be a positive integer (1..{MAX_MIN_QUORUM}); got {value!r}")
    return value


def _cli_min_quorum(text: str) -> int:
    """CLI parser; identical rule and message to Go ParseMinQuorum (empty string rejected)."""
    import argparse
    msg = f"min_quorum must be a positive integer (1..{MAX_MIN_QUORUM}); got '{text}'"
    if not (text.isascii() and text.isdigit()) or len(text) > 7:
        raise argparse.ArgumentTypeError(msg)
    try:
        return validate_min_quorum(int(text))  # type: ignore[return-value]
    except ValueError:
        raise argparse.ArgumentTypeError(msg)


VALID_SEVERITIES = ("P0", "P1", "P2", "P3", "N")
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def _canonical_json(data: Any) -> str:
    """Deterministic JSON serialization without whitespace drift."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _fsync_dir(directory: Path) -> None:
    """fsync a directory so a rename is durable (POSIX). No-op where unsupported (Windows)."""
    import os
    flags = getattr(os, "O_DIRECTORY", None)
    if flags is None:
        return
    try:
        dfd = os.open(str(directory), os.O_RDONLY | flags)
    except OSError:
        return
    try:
        os.fsync(dfd)
    except OSError:
        pass
    finally:
        os.close(dfd)


def _atomic_write_json(path: Path, data: Any) -> None:
    """Write JSON via temp file + os.replace so concurrent readers never see a partial file."""
    import os
    import tempfile
    path = Path(path)
    import time
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        # Windows: replacing a file another process holds open raises PermissionError.
        # Retry briefly (~1s), then fail loudly rather than silently skipping the write.
        for attempt in range(20):
            try:
                os.replace(tmp, path)
                break
            except PermissionError:
                if attempt == 19:
                    raise
                time.sleep(0.05)
        _fsync_dir(path.parent)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _read_json(path: Path) -> Any:
    """Read a JSON file with retry on transient Windows file-lock errors.

    ``_atomic_write_json`` uses ``os.replace``, which on Windows can expose a
    brief window where a concurrent reader of the same path fails with
    ``PermissionError`` while the replace is in flight. Mirror the write-side
    retry so parallel converges don't spuriously fail on the read.
    """
    import os
    import time
    path = Path(path)
    for attempt in range(20):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.05)


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

    def compute_legacy_go_hash(self) -> str:
        """Hash as written by wags-go 0.1.0 (encoding/json.Marshal escaped <, >, &,
        U+2028 and U+2029). Accepted on verify only; never produced."""
        payload = {
            "sequence": self.sequence, "timestamp": self.timestamp, "review_id": self.review_id,
            "reviewer": self.reviewer, "phase": self.phase, "prev_hash": self.prev_hash,
            "findings": self.findings, "verdict": self.verdict, "rebuttal_to": self.rebuttal_to,
            "metadata": self.metadata,
        }
        text = _canonical_json(payload)
        for raw, esc in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"),
                         ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
            text = text.replace(raw, esc)
        return _compute_sha256(text.encode("utf-8"))

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

    def hash_form(self) -> str:
        """'canonical', 'legacy' (wags-go 0.1.0 encoding) or 'none'."""
        if self.entry_hash == self.compute_hash():
            return "canonical"
        if self.entry_hash == self.compute_legacy_go_hash():
            return "legacy"
        return "none"

    def verify_entry(self, secret_key: Optional[str] = None, allow_legacy: bool = False) -> Tuple[bool, str]:
        expected_hash = self.compute_hash()
        if allow_legacy and self.entry_hash != expected_hash and self.compute_legacy_go_hash() == self.entry_hash:
            expected_hash = self.entry_hash  # accepted: wags-go 0.1.0 legacy encoding (0.1.0 targets only)
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
        _atomic_write_json(self.index_file, data)

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

        _atomic_write_json(rev_dir / "target.json", target_manifest)

        _atomic_write_json(rev_dir / "reviewers.json", {})

        # Update index
        idx = self._read_index()
        idx.setdefault("reviews", {})[review_id] = {
            "target": str(target_p),
            "target_sha256": target_sha256,
            "created_at": target_manifest["created_at"],
            "status": "OPEN",
            "protocol_version": PROTOCOL_VERSION,
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

        _atomic_write_json(reg_file, data)

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
        resolves: Optional[List[str]] = None,
        supersedes: Optional[List[str]] = None,
    ) -> StreamEntry:
        rev_dir = self.reviews_dir / review_id
        if not rev_dir.exists():
            raise ValueError(f"Review {review_id} not found")

        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("metadata must be a JSON object (dict)")
        if resolves is not None or supersedes is not None:
            metadata = dict(metadata or {})
            if resolves is not None:
                metadata["resolves"] = list(resolves)
            if supersedes is not None:
                metadata["supersedes"] = list(supersedes)

        findings_dicts: List[Dict[str, Any]] = []
        if findings:
            for item in findings:
                if isinstance(item, Finding):
                    findings_dicts.append(item.to_dict())
                elif isinstance(item, dict):
                    findings_dicts.append(item)

        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("metadata must be a JSON object (dict)")
        for fd in findings_dicts:
            sev = fd.get("severity") if isinstance(fd, dict) else None
            if not isinstance(sev, str) or sev.upper() not in VALID_SEVERITIES:
                raise ValueError(f"invalid finding severity {sev!r}; must be one of {', '.join(VALID_SEVERITIES)}")
        md = metadata or {}
        if "resolves" in md or "supersedes" in md:
            stream_path = rev_dir / f"{reviewer_name}.jsonl"
            prior = self._read_stream_dicts(stream_path) if stream_path.exists() else []
            errs = self._check_resolution_refs(prior, md.get("resolves", []), md.get("supersedes", []), md)
            if errs:
                raise ValueError("; ".join(errs))

        # Hash-chained protocol marker: new entries in reviews whose target is NOT
        # 0.1.0 carry metadata.wags_protocol, so a later downgrade of target.json is
        # detectable from the chain itself (0.1.0 reviews stay unmarked).
        if self._target_protocol(rev_dir) != "0.1.0":
            metadata = dict(metadata or {})
            metadata["wags_protocol"] = PROTOCOL_VERSION

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
        target_proto = self._target_protocol(rev_dir)
        # Legacy Go hash form only for genuine 0.1.0 reviews (no 0.2.0 markers).
        legacy_target = target_proto == "0.1.0" and not self._uses_020_features(rev_dir)
        registered = self._registered(rev_dir)
        legacy_all = self._registry_mode(rev_dir) == "legacy_all_streams"
        results["registry_mode"] = "legacy_all_streams" if legacy_all else "registered"

        for path in rev_dir.glob("*.jsonl"):
            reviewer = path.stem
            stream_valid = True
            errors = []
            expected_prev = GENESIS_HASH
            prior_dicts: List[Dict[str, Any]] = []
            seen_canonical = False

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
                        ok, msg = entry.verify_entry(secret_key, allow_legacy=legacy_target and not seen_canonical)
                        if ok and entry.entry_hash == entry.compute_hash():
                            seen_canonical = True
                        elif not ok and legacy_target and seen_canonical and entry.hash_form() == "legacy":
                            msg = "legacy-form hash after a canonical-form entry is not allowed"
                        if not ok:
                            stream_valid = False
                            errors.append(f"Line {idx} sequence {entry.sequence}: {msg}")

                        if entry.sequence != len(prior_dicts) + 1:
                            stream_valid = False
                            errors.append(f"Line {idx}: sequence {entry.sequence} out of order (expected {len(prior_dicts) + 1})")
                        if entry.reviewer != reviewer:
                            stream_valid = False
                            errors.append(f"Line {idx}: reviewer '{entry.reviewer}' does not match stream '{reviewer}'")
                        # Validate resolution refs (own stream, earlier entries only)
                        res, sup = self._resolution_refs(d)
                        md_d = d.get("metadata") if isinstance(d.get("metadata"), dict) else {}
                        for msg2 in self._check_resolution_refs(prior_dicts, res, sup, md_d):
                            stream_valid = False
                            errors.append(f"Line {idx} sequence {entry.sequence}: {msg2}")
                        prior_dicts.append(d)

                        expected_prev = entry.entry_hash
                    except Exception as ex:
                        stream_valid = False
                        errors.append(f"Line {idx} parse error: {ex}")

            if prior_dicts and not legacy_all and reviewer not in registered:
                stream_valid = False
                errors.append(f"stream '{reviewer}' has {len(prior_dicts)} entr{'y' if len(prior_dicts) == 1 else 'ies'} but reviewer is not registered in reviewers.json")
            results["streams"][reviewer] = {
                "valid": stream_valid,
                "errors": errors,
            }
            if not stream_valid:
                results["valid"] = False

        return results

    # ------------------------------------------------------------------
    # Finding resolution (protocol 0.2.0)
    # ------------------------------------------------------------------
    @staticmethod
    def _load_prev_convergence(rev_dir: Path) -> Tuple[str, Dict[str, Any]]:
        """Return (anchor_status, data): 'absent' | 'unparseable' | 'present'."""
        conv_file = rev_dir / "converged.json"
        if not conv_file.exists():
            return "absent", {}
        try:
            data = _read_json(conv_file)
        except Exception:
            return "unparseable", {}
        if not isinstance(data, dict) or not isinstance(data.get("anchors", {}), dict):
            return "unparseable", {}
        return "present", data

    @classmethod
    def _uses_020_features(cls, rev_dir: Path) -> List[str]:
        """0.2.0-only features found in a review (entries or converged.json)."""
        found: List[str] = []
        for path in sorted(rev_dir.glob("*.jsonl")):
            for d in cls._read_stream_dicts(path):
                md = d.get("metadata")
                if isinstance(md, dict) and ("resolves" in md or "supersedes" in md):
                    found.append(f"{path.stem} seq {d.get('sequence')}: resolves/supersedes")
                if isinstance(md, dict) and str(md.get("wags_protocol", "0.1.0")) != "0.1.0":
                    found.append(f"{path.stem} seq {d.get('sequence')}: chained wags_protocol {md.get('wags_protocol')}")
        try:
            with open(rev_dir.parent.parent / "index.json", "r", encoding="utf-8") as f:
                idx = json.load(f)
            wpv = str(idx.get("protocol_version", ""))
            rpv = str(((idx.get("reviews") or {}).get(rev_dir.name) or {}).get("protocol_version", ""))
            if wpv not in ("", "0.1.0"):
                found.append(f"index.json workspace protocol_version {wpv}")
            if rpv not in ("", "0.1.0"):
                found.append(f"index.json review protocol_version {rpv}")
        except Exception:
            pass
        status, prev = cls._load_prev_convergence(rev_dir)
        ctx = prev.get("anchor_context") if status == "present" else None
        if isinstance(ctx, dict) and str(ctx.get("protocol_version", "")) not in ("", "0.1.0"):
            found.append(f"converged.json anchor_context protocol_version {ctx.get('protocol_version')}")
        if isinstance(ctx, dict) and ctx.get("registry_mode") == "registered":
            found.append("converged.json recorded registry_mode=registered")
        return found

    @classmethod
    def _registry_mode(cls, rev_dir: Path) -> str:
        """Legacy count-all mode only for a 0.1.0 target with an empty/missing
        registry that shows NO 0.2.0 features and never recorded registered mode."""
        if cls._target_protocol(rev_dir) != "0.1.0" or cls._registered(rev_dir):
            return "registered"
        status, _ = cls._load_prev_convergence(rev_dir)
        if status == "unparseable" or cls._uses_020_features(rev_dir):
            return "registered"
        return "legacy_all_streams"

    @staticmethod
    def _target_protocol(rev_dir: Path) -> str:
        try:
            return str(_read_json(rev_dir / "target.json").get("protocol_version", ""))
        except Exception:
            return ""

    @staticmethod
    def _registered(rev_dir: Path) -> set:
        try:
            with open(rev_dir / "reviewers.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            return set(data.keys()) if isinstance(data, dict) else set()
        except Exception:
            return set()

    @staticmethod
    def _read_stream_dicts(path: Path) -> List[Dict[str, Any]]:
        """Read a reviewer stream in file (append) order."""
        out: List[Dict[str, Any]] = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
        return out

    @staticmethod
    def _resolution_refs(d: Dict[str, Any]) -> Tuple[Any, Any]:
        md = d.get("metadata") or {}
        if not isinstance(md, dict):
            return [], []
        return md.get("resolves", []), md.get("supersedes", [])

    @staticmethod
    def _check_resolution_refs(
        prior: List[Dict[str, Any]], resolves: Any, supersedes: Any, present: Optional[Any] = None
    ) -> List[str]:
        """Validate resolves/supersedes against the reviewer's OWN earlier entries."""
        errors: List[str] = []
        prior_ids = {f.get("id") for e in prior for f in e.get("findings", []) if isinstance(f, dict)}
        prior_hashes = {e.get("entry_hash") for e in prior}
        if not isinstance(resolves, list) or not all(isinstance(x, str) for x in resolves):
            errors.append("metadata.resolves must be a list of finding id strings")
        elif present is not None and "resolves" in present and not resolves:
            errors.append("metadata.resolves must not be empty")
        else:
            for fid in resolves:
                if fid not in prior_ids:
                    errors.append(f"metadata.resolves references unknown finding '{fid}' (not in this reviewer's earlier entries)")
        if not isinstance(supersedes, list) or not all(isinstance(x, str) for x in supersedes):
            errors.append("metadata.supersedes must be a list of entry_hash strings")
        elif present is not None and "supersedes" in present and not supersedes:
            errors.append("metadata.supersedes must not be empty")
        else:
            for h in supersedes:
                if h not in prior_hashes:
                    errors.append(f"metadata.supersedes references unknown entry '{h}' (not an earlier entry in this reviewer's stream)")
        return errors

    @classmethod
    def _stream_state(cls, entries: List[Dict[str, Any]]) -> Tuple[Optional[str], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Return (latest_verdict, open_findings, resolved_findings) for one stream.

        Entries are processed in ``sequence`` order. A resolving entry at
        position k closes only finding INSTANCES raised in entries before k:
        ids in ``metadata.resolves`` and every finding of an entry named in
        ``metadata.supersedes``. A finding id raised again after it was
        resolved is a new, open instance. Invalid refs are ignored here
        (verify_review reports them).
        """
        entries = sorted(entries, key=lambda e: e.get("sequence", 0))
        latest_verdict: Optional[str] = None
        instances: List[Dict[str, Any]] = []  # {"pos", "hash", "finding", "resolved"}
        for idx, d in enumerate(entries):
            resolves, supersedes = cls._resolution_refs(d)
            md_d = d.get("metadata") if isinstance(d.get("metadata"), dict) else {}
            if not cls._check_resolution_refs(entries[:idx], resolves, supersedes, md_d):
                res_ids, sup = set(resolves), set(supersedes)
                for inst in instances:  # all instances are from earlier entries
                    if inst["finding"].get("id") in res_ids or inst["hash"] in sup:
                        inst["resolved"] = True
            if d.get("verdict"):
                latest_verdict = d["verdict"]
            for finding in d.get("findings", []):
                instances.append({"hash": d.get("entry_hash", ""), "finding": finding, "resolved": False})
        open_f = [i["finding"] for i in instances if not i["resolved"]]
        resolved_f = [i["finding"] for i in instances if i["resolved"]]
        return latest_verdict, open_f, resolved_f

    def converge_review(self, review_id: str, keys: Optional[Dict[str, str]] = None,
                        min_quorum: Optional[int] = None) -> Dict[str, Any]:
        """Compute consensus using each reviewer's latest verdict and open findings.

        - Verdict per reviewer = verdict of their latest entry that has one.
        - Only OPEN findings count (see ``_stream_state``).
        - BLOCK if any open P0 or any latest ``block`` vote.
        - REQUEST_CHANGES if any latest ``request_changes`` vote, or any open
          P1 whose reviewer's latest verdict is not ``approve``.
        - Otherwise APPROVE on >= 50% approve, else DEFER.
        """
        min_quorum = validate_min_quorum(min_quorum)
        rev_dir = self.reviews_dir / review_id
        if not rev_dir.exists():
            raise ValueError(f"Review {review_id} not found")

        target_file = rev_dir / "target.json"
        target_data = _read_json(target_file)

        verification = self.verify_review(review_id, keys)
        registered = self._registered(rev_dir)
        # Legacy "count every stream" mode ONLY for protocol 0.1.0 targets with an
        # empty/missing registry (wags-go 0.1.0 never populated it). For 0.2.0
        # targets an unregistered stream with entries fails verify -> BLOCK.
        legacy_all = verification.get("registry_mode") == "legacy_all_streams"
        registry_mode = "legacy_all_streams" if legacy_all else "registered"
        invalid_streams: List[Dict[str, Any]] = []
        unregistered_streams: List[str] = []

        # Anchors from the previous convergence (truncation / deletion / downgrade detection).
        anchor_status, prev = self._load_prev_convergence(rev_dir)
        prev_anchors: Dict[str, Any] = prev.get("anchors", {}) or {}
        prev_ctx: Dict[str, Any] = prev.get("anchor_context") or {} if isinstance(prev.get("anchor_context"), dict) else {}
        target_proto = self._target_protocol(rev_dir)
        anchor_problems: List[str] = []
        if anchor_status == "unparseable":
            anchor_problems.append("converged.json is unparseable; previous anchors lost")
        if prev.get("anchor_lost"):
            anchor_problems.append("an earlier convergence found converged.json unparseable; operator must review")
        if prev_ctx:
            pv = str(prev_ctx.get("protocol_version", ""))
            if pv and pv != "0.1.0" and target_proto == "0.1.0":
                anchor_problems.append(f"protocol downgrade: anchored {pv}, target.json now {target_proto}")
            if prev_ctx.get("registry_mode") == "registered" and registry_mode == "legacy_all_streams":
                anchor_problems.append("registry mode changed from registered to legacy_all_streams")
            gone = sorted(set(prev_ctx.get("registered_reviewers") or []) - registered)
            if gone and prev_ctx.get("registry_mode") == "registered":
                anchor_problems.append(f"registered reviewer(s) disappeared from reviewers.json: {', '.join(gone)}")
        if target_proto == "0.1.0":
            feats = self._uses_020_features(rev_dir)
            if feats and not self._registered(rev_dir):
                anchor_problems.append("target.json says 0.1.0 but review uses 0.2.0 features: " + "; ".join(feats))
            elif any("chained wags_protocol" in x for x in feats):
                anchor_problems.append("protocol downgrade: target.json says 0.1.0 but hash-chained entries are "
                                       + "; ".join(x for x in feats if "chained wags_protocol" in x))
            elif any("resolves/supersedes" in x for x in feats):
                anchor_problems.append("target.json says 0.1.0 but entries use resolves/supersedes (0.2.0): "
                                       + "; ".join(x for x in feats if "resolves/supersedes" in x))
        regressed_streams: List[Dict[str, Any]] = []
        for anchored, a in sorted(prev_anchors.items()):
            ap = rev_dir / f"{anchored}.jsonl"
            cur = self._read_stream_dicts(ap) if ap.exists() else []
            seq, h = a.get("sequence", 0), a.get("entry_hash", "")
            by_seq = {e.get("sequence"): e.get("entry_hash") for e in cur}
            if not ap.exists():
                reason = "stream deleted"
            elif len(cur) < seq:
                reason = f"stream shorter than anchor ({len(cur)} < {seq})"
            elif by_seq.get(seq) != h:
                reason = f"anchored entry_hash missing at sequence {seq}"
            elif not legacy_all and anchored not in registered:
                reason = "reviewer removed from reviewers.json"
            else:
                continue
            regressed_streams.append({"reviewer": anchored, "anchor": {"sequence": seq, "entry_hash": h}, "reason": reason})

        reviewer_latest_verdicts: Dict[str, str] = {}
        all_findings: List[Dict[str, Any]] = []
        all_severity_counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "N": 0}
        unknown_severity_findings: List[Dict[str, Any]] = []
        open_findings: List[Dict[str, Any]] = []
        resolved_findings: List[Dict[str, Any]] = []
        severity_counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "N": 0}
        blocking_findings: List[Dict[str, Any]] = []

        for path in sorted(rev_dir.glob("*.jsonl")):
            reviewer = path.stem
            sv = verification["streams"].get(reviewer, {})
            if not legacy_all and reviewer not in registered:
                unregistered_streams.append(reviewer)
                if not sv.get("valid", False):  # has entries (or garbage): fail closed
                    invalid_streams.append({"reviewer": reviewer, "errors": sv.get("errors", [])})
                continue
            if not sv.get("valid", False):
                invalid_streams.append({"reviewer": reviewer, "errors": sv.get("errors", [])})
                continue
            entries = self._read_stream_dicts(path)
            latest, open_f, resolved_f = self._stream_state(entries)
            if latest:
                reviewer_latest_verdicts[reviewer] = latest
            for d in entries:
                for finding in d.get("findings", []):
                    all_findings.append(finding)
                    s0 = str(finding.get("severity", "N")).upper()
                    all_severity_counts[s0] = all_severity_counts.get(s0, 0) + 1
            resolved_findings.extend(resolved_f)
            for finding in open_f:
                open_findings.append(finding)
                sev = str(finding.get("severity", "N")).upper()
                if sev not in VALID_SEVERITIES:
                    # Unknown severity: treat conservatively as P0.
                    unknown_severity_findings.append(finding)
                    sev = "P0"
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                if sev == "P0" or (sev == "P1" and (latest or "").lower() != "approve"):
                    blocking_findings.append(finding)

        total_reviewers = len(reviewer_latest_verdicts)
        verdict_counts = {"approve": 0, "request_changes": 0, "block": 0, "defer": 0}
        for v in reviewer_latest_verdicts.values():
            normalized_v = v.lower()
            verdict_counts[normalized_v] = verdict_counts.get(normalized_v, 0) + 1

        open_p0 = severity_counts.get("P0", 0)  # includes unknown severities (treated as P0)
        blocking_p1 = len(blocking_findings) - open_p0

        # Quorum: by default every registered reviewer must have a latest verdict
        # before the review can APPROVE (min_quorum overrides; legacy mode = voters).
        quorum_required = (len(registered) if registry_mode == "registered" else total_reviewers) \
            if min_quorum is None else min_quorum
        quorum_warning = None
        if min_quorum is not None and registry_mode == "registered" and min_quorum > len(registered):
            quorum_warning = (f"min_quorum {min_quorum} exceeds the {len(registered)} registered reviewer(s); "
                              f"quorum can never be met")
        quorum_met = total_reviewers > 0 and total_reviewers >= quorum_required and quorum_warning is None

        if anchor_problems:
            overall_verdict = "BLOCK"
            rationale = "Anchor/protocol problem: " + "; ".join(anchor_problems)
        elif regressed_streams:
            overall_verdict = "BLOCK"
            rationale = (f"Regression: {len(regressed_streams)} stream(s) lost entries or registration since the last "
                         f"convergence anchor ({', '.join(x['reviewer'] for x in regressed_streams)}).")
        elif invalid_streams:
            overall_verdict = "BLOCK"
            rationale = (f"Integrity failure: {len(invalid_streams)} stream(s) failed verification "
                         f"({', '.join(x['reviewer'] for x in invalid_streams)}); excluded and review blocked.")
        elif open_p0 > 0 or verdict_counts.get("block", 0) > 0:
            overall_verdict = "BLOCK"
            rationale = f"Blocked by {open_p0} open P0 finding(s) or explicit block vote."
        elif blocking_p1 > 0 or verdict_counts.get("request_changes", 0) > 0:
            overall_verdict = "REQUEST_CHANGES"
            rationale = f"Changes required: {blocking_p1} blocking open P1 finding(s) or request_changes vote(s)."
        elif quorum_warning:
            overall_verdict = "DEFER"
            rationale = "Pending quorum: " + quorum_warning
        elif not quorum_met:
            overall_verdict = "DEFER"
            rationale = (f"Pending quorum: {total_reviewers}/{quorum_required} required reviewers have voted "
                         f"({len(registered)} registered).")
        elif total_reviewers > 0 and (verdict_counts.get("approve", 0) >= (total_reviewers / 2.0)):
            overall_verdict = "APPROVE"
            rationale = f"Approved by majority ({verdict_counts.get('approve', 0)}/{total_reviewers}) with 0 blockers."
        else:
            overall_verdict = "DEFER"
            rationale = "Insufficient quorum or inconclusive vote."

        # New anchors: each stream's latest (sequence, entry_hash). A regressed
        # stream keeps its OLD anchor so the BLOCK persists until an operator
        # intervenes. Anchors only help if converged.json is kept somewhere
        # tamper-resistant (committed to git or published) -- see spec 4.6.
        regressed_names = {x["reviewer"] for x in regressed_streams}
        anchors: Dict[str, Any] = {n: a for n, a in prev_anchors.items() if n in regressed_names}
        for path in sorted(rev_dir.glob("*.jsonl")):
            name = path.stem
            if name in regressed_names or (not legacy_all and name not in registered):
                continue
            ents = sorted(self._read_stream_dicts(path), key=lambda e: e.get("sequence", 0))
            if ents:
                anchors[name] = {"sequence": ents[-1].get("sequence"), "entry_hash": ents[-1].get("entry_hash")}

        # Anchor context: a problem keeps the OLD context so the BLOCK persists.
        if prev_ctx and anchor_problems:
            anchor_context = prev_ctx
        else:
            anchor_context = {
                "protocol_version": target_proto,
                "registry_mode": registry_mode,
                "registered_reviewers": sorted(set(registered) | set(prev_ctx.get("registered_reviewers") or []))
                if anchor_problems else sorted(registered),
            }
        if anchor_status == "present" and not isinstance(prev.get("anchor_context"), dict):
            anchor_status = "present_no_context"  # older converged.json (pre round-3)
        anchor_lost = bool(prev.get("anchor_lost")) or anchor_status == "unparseable"
        if anchor_status == "unparseable":
            anchors = {}

        converged_manifest = {
            "protocol_version": PROTOCOL_VERSION,
            "review_id": review_id,
            "converged_at": _now_iso_utc(),
            "target": target_data.get("target", {}),
            "overall_verdict": overall_verdict,
            "rationale": rationale,
            "quorum_met": quorum_met,
            "quorum": {"required": quorum_required, "voted": total_reviewers, "registered": len(registered),
                       "min_quorum": min_quorum, "warning": quorum_warning},
            "anchor_status": anchor_status,
            "anchor_problems": anchor_problems,
            "anchor_context": anchor_context,
            "anchor_lost": anchor_lost,
            "summary": {
                "total_reviewers": total_reviewers,
                "verdicts": verdict_counts,
                "findings_by_severity": all_severity_counts,
                "open_findings_by_severity": severity_counts,
            },
            "invalid_streams": invalid_streams,
            "unregistered_streams": unregistered_streams,
            "registry_empty": not registered,
            "registry_mode": registry_mode,
            "regressed_streams": regressed_streams,
            "verify_valid": bool(verification.get("valid")),
            "verify_scope": "all stream files; invalid_streams lists the ones that failed (registered or unregistered-with-entries)",
            "anchors": anchors,
            "unknown_severity_findings": unknown_severity_findings,
            "blocking_findings": blocking_findings,
            "open_findings": open_findings,
            "resolved_findings": resolved_findings,
            "all_findings": all_findings,
        }

        _atomic_write_json(rev_dir / "converged.json", converged_manifest)

        # Update target status
        target_data["status"] = "CONVERGED"
        target_data["current_phase"] = "convergence"
        _atomic_write_json(target_file, target_data)

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
    p_sub.add_argument("--resolves", action="append", default=None, help="Finding id from your own earlier entry that this entry resolves (repeatable)")
    p_sub.add_argument("--supersedes", action="append", default=None, help="entry_hash of your own earlier entry whose findings this entry supersedes (repeatable)")

    # tail
    p_tail = subparsers.add_parser("tail", help="Tail and view all entries in a review chronologically")
    p_tail.add_argument("review_id", help="Review ID")

    # verify
    p_ver = subparsers.add_parser("verify", help="Verify hash chains and signatures for a review")
    p_ver.add_argument("review_id", help="Review ID")

    # converge
    p_conv = subparsers.add_parser("converge", help="Calculate consensus and converge review")
    p_conv.add_argument("review_id", help="Review ID")
    p_conv.add_argument("--min-quorum", type=_cli_min_quorum, default=None,
                        help="Minimum reviewers with a verdict before APPROVE (default: all registered)")

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
            resolves=args.resolves,
            supersedes=args.supersedes,
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
        try:
            res = ws.converge_review(args.review_id, min_quorum=args.min_quorum)
        except OSError as ex:
            print(f"Error: failed to write convergence result: {ex}", file=sys.stderr)
            return 1
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
