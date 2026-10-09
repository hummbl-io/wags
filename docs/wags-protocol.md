# wags Protocol Specification (v0.2.0)

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
  "protocol_version": "0.2.0",
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
  "protocol_version": "0.2.0",
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
  "blocking_findings": [],
  "open_findings": [],
  "resolved_findings": []
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

### 4.2 Consensus Decision Rules (protocol 0.2.0)
Convergence is computed **per reviewer stream**, in append order:

- **Latest verdict wins.** A reviewer's vote is the `verdict` of their most recent entry that has one. Earlier verdicts are history, not votes.
- **Only open findings count.** A finding is *open* unless a **later entry in the same reviewer's stream** resolves it (see 4.3). Resolved findings stay in the log and are reported in `converged.json` under `resolved_findings`; `findings_by_severity` counts open findings only.

Rules, in order:
1. **P0 Rule (Absolute Veto)**: Any **open** `P0` finding, or any reviewer whose latest verdict is `block`, makes the overall verdict **`BLOCK`**. An approving reviewer cannot veto-proof their own open P0; they must resolve it explicitly.
2. **P1 Rule**: Any reviewer whose latest verdict is `request_changes`, or any **open** `P1` whose reviewer's latest verdict is not `approve`, makes the verdict **`REQUEST_CHANGES`**. (An open P1 from a reviewer whose latest verdict is `approve` is reported in `open_findings` but does not block.)
3. **Majority Approval**: If there are no blockers and $\ge 50\%$ of reviewers with a verdict submit `approve`, the verdict is **`APPROVE`**.
4. **Tie / Inconclusive**: Otherwise **`DEFER`** pending operator intervention.

### 4.3 Resolving and Superseding Findings
An entry MAY carry, inside `metadata` (which is already covered by `entry_hash`, so the hash format is unchanged):

```json
"metadata": {
  "resolves":   ["mtsmu-P1-01", "mtsmu-P1-02"],
  "supersedes": ["a3ec45df030df633...ee6b"]
}
```

- `resolves`: list of finding `id`s. Each MUST appear in an **earlier entry of the same reviewer's stream**.
- `supersedes`: list of `entry_hash` values. Each MUST be an **earlier entry of the same reviewer's stream**; all findings raised in those entries become resolved.
- A reviewer can never resolve another reviewer's findings. Implementations MUST reject such refs at submit time, and `verify` MUST mark a stream containing invalid refs as invalid. Convergence ignores invalid refs.
- Entries are never rewritten; resolution is purely additive, preserving append-only and hash-chain guarantees.

**Backward compatibility:** logs written by 0.1.0 (no `resolves`/`supersedes`) verify unchanged and converge with the latest-verdict rule. Ad-hoc metadata keys (e.g. `resolved_findings`) carry no protocol meaning.

### 4.4 Canonical JSON
Entry hashes are SHA-256 over JSON with sorted keys, separators `,` and `:`, UTF-8, non-ASCII emitted raw, and **no HTML escaping** (`<`, `>`, `&` emitted literally), matching Python `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.

---

## 5. 4-Phase Lifecycle Model

1. **`review`**: Reviewers independently read the target artifact and submit initial findings.
2. **`rebuttal`**: Author or peers submit counter-evidence or patch references in response to specific finding IDs.
3. **`meta-review`**: Synthesis pass to deduplicate findings and evaluate rebuttals.
4. **`convergence`**: Evaluates all final entries and seals `converged.json`.
