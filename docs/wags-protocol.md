# wags Protocol Specification (v0.1.0)

**Status:** DRAFT / PROPOSED  
**Author:** Multi-Agent Collective (`devin`, `gemini`, `operator`)  
**Date:** 2026-08-23  

---

## 1. Abstract & Principles

**wags** is a lightweight, polyglot, air-gappable protocol for multi-agent peer reviews. It enables heterogeneous AI agents and human reviewers to independently assess artifacts (code, documentation, architectural proposals, evidence bundles), debate findings through structured rounds, and converge on an auditable decision without relying on central servers, network connections, or external platforms.

### Core Principles
1. **Local-First & Air-Gappable**: Requires only standard filesystem read/write operations. No daemon, database, or network socket required.
2. **Polyglot & Stdlib-Only**: Protocol data formats are standard JSON and JSON Lines (JSONL). Reference implementations must rely strictly on standard library utilities.
3. **Single-Writer-Per-Stream**: Each reviewer appends solely to their dedicated log (`<reviewer>.jsonl`). Eliminates concurrency locks and merge conflicts.
4. **Tamper-Evident Hash Chaining**: Every log entry references the SHA-256 hash of the preceding entry (`prev_hash`), ensuring chronological auditability.
5. **Decisive Consensus**: Employs a strict **P0-Veto + Majority Rule** model to guarantee safety while avoiding deadlock.

---

## 2. File & Directory Layout

A review workspace is structured under a root directory (default: `.wags/` or specified review directory):

```text
.wags/
├── reviews/
│   └── <review_id>/
│       ├── target.json           # Target metadata, content hash, description
│       ├── reviewers.json        # Registered reviewers, public keys/identities
│       ├── <reviewer_1>.jsonl    # Reviewer 1 append-only tamper-evident stream
│       ├── <reviewer_2>.jsonl    # Reviewer 2 append-only tamper-evident stream
│       ├── meta_review.jsonl     # Synthesis / Meta-reviewer log
│       └── converged.json        # Final convergence summary & verdict
└── index.json                    # Workspace catalog of all reviews
```

---

## 3. Data Schemas

### 3.1 Target Manifest (`target.json`)
```json
{
  "protocol_version": "0.1.0",
  "review_id": "rev-20260823-7f8a9b",
  "created_at": "2026-08-23T23:55:00Z",
  "initiator": "gemini",
  "target": {
    "type": "code",
    "path": "src/core/router.py",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "description": "Core routing logic update"
  },
  "phases": ["review", "rebuttal", "meta-review", "convergence"],
  "current_phase": "review"
}
```

### 3.2 Reviewer Stream Entry (`<reviewer>.jsonl`)
Each line is a JSON object with cryptographic chaining:

```json
{
  "sequence": 1,
  "timestamp": "2026-08-23T23:56:10Z",
  "review_id": "rev-20260823-7f8a9b",
  "reviewer": "devin",
  "phase": "review",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "findings": [
    {
      "id": "devin-P1-01",
      "severity": "P1",
      "surface": "routing",
      "finding": "Missing boundary check on empty queue input",
      "evidence": "router.py:42-45",
      "recommendation": "Guard with explicit len check before pop"
    }
  ],
  "verdict": "request_changes",
  "entry_hash": "9f83c6b12a874b096f9a882e3465...",
  "signature": "hmac_sha256_signature_or_empty"
}
```

### 3.3 Convergence Manifest (`converged.json`)
```json
{
  "protocol_version": "0.1.0",
  "review_id": "rev-20260823-7f8a9b",
  "converged_at": "2026-08-23T23:58:30Z",
  "target_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "overall_verdict": "REQUEST_CHANGES",
  "quorum_met": true,
  "summary": {
    "total_reviewers": 3,
    "verdicts": {
      "approve": 1,
      "request_changes": 2,
      "block": 0
    },
    "findings_by_severity": {
      "P0": 0,
      "P1": 2,
      "P2": 1,
      "P3": 0,
      "N": 0
    }
  },
  "blocking_findings": []
}
```

---

## 4. Severity Ladder & Consensus Engine

### 4.1 Severity Definitions
- **`P0` (Critical / Blocker)**: Violates security, data integrity, invariant doctrine, or causes fatal crashes. **A single unresolved P0 vetoes convergence and forces `BLOCK`.**
- **`P1` (Major / Change Required)**: Significant defect, missing edge case, architectural drift, or lacking test coverage. Requires fixes before approval.
- **`P2` (Minor / Improvement)**: Non-critical efficiency, style divergence, or documentation gap.
- **`P3` (Nit / Polish)**: Minor cosmetic or phrasing suggestion.
- **`N` (Note / Praise)**: Positive verification or context observation.

### 4.2 Consensus Decision Rules
1. **P0 Rule (Absolute Veto)**: If any active reviewer submits a verified `P0` finding with a `block` verdict, the overall review verdict is **`BLOCK`**.
2. **P1 Rule**: If any active reviewer has unresolved `P1` findings and votes `request_changes`, the overall verdict is **`REQUEST_CHANGES`**.
3. **Majority Approval**: If there are zero `P0` and zero `P1` blockers, and $\ge 50\%$ of participating reviewers submit `approve`, the verdict is **`APPROVE`**.
4. **Tie / Inconclusive**: If no quorum or tied without consensus, the review defaults to **`DEFER`** pending operator intervention.

---

## 5. 4-Phase Lifecycle Model

1. **`review`**: Reviewers independently read the target artifact and submit initial findings.
2. **`rebuttal`**: Author or peers submit counter-evidence or patch references in response to specific finding IDs.
3. **`meta-review`**: Synthesis pass to deduplicate findings and evaluate rebuttals.
4. **`convergence`**: Evaluates all final entries and seals `converged.json`.
