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
**Step 0: integrity and registration.** Before counting anything, convergence runs `verify`:
- Streams whose reviewer is not in `reviewers.json` are **excluded** and listed in `unregistered_streams`. Legacy exception: if `reviewers.json` is empty (wags-go 0.1.0 never populated it), every stream counts and `registry_empty: true` is reported.
- Registered streams that fail verification (bad hash, broken `prev_hash`, `sequence` not 1..n in file order, `reviewer` not matching the stream name, invalid resolution refs) are **excluded** and listed in `invalid_streams`. **If any registered stream is invalid, the overall verdict is `BLOCK`**: a tampered or corrupt log could be hiding a veto, so the safe result is to stop, not to approve without it.

Then, per valid stream, processed in `sequence` order:
- **Latest verdict wins.** A reviewer's vote is the `verdict` of their highest-sequence entry that has one. A later entry with no verdict does not reset the vote.
- **Only open findings count.** See 4.3 for when a finding is resolved. Resolved findings stay in the log and are reported in `resolved_findings`.

Rules, in order:
1. **P0 Rule (Absolute Veto)**: any **open** `P0`, or any latest verdict `block`, gives **`BLOCK`**. Findings with an unrecognised severity are treated as `P0` (listed in `unknown_severity_findings`). Implementations reject unknown severities at submit.
2. **P1 Rule**: any latest verdict `request_changes`, or any **open** `P1` whose reviewer's latest verdict is not `approve`, gives **`REQUEST_CHANGES`**.
   - **Policy change from 0.1.0:** an open P1 raised by a reviewer whose latest verdict is `approve` **no longer blocks**. That reviewer has accepted their own finding as non-blocking. The finding still appears in `open_findings` and `open_findings_by_severity`. To keep it blocking, the reviewer should vote `request_changes`.
3. **Majority Approval**: if there are no blockers and at least 50% of reviewers with a verdict submit `approve`, the verdict is **`APPROVE`**.
4. **Tie / Inconclusive**: otherwise **`DEFER`**.

`summary.findings_by_severity` counts **all** findings from valid registered streams, as in 0.1.0. `summary.open_findings_by_severity` counts open findings only, **including non-blocking open P1s**.

### 4.3 Resolving and Superseding Findings
An entry MAY carry, inside `metadata` (already covered by `entry_hash`, so the hash format is unchanged):

```json
"metadata": {
  "resolves":   ["mtsmu-P1-01", "mtsmu-P1-02"],
  "supersedes": ["a3ec45df030df633...ee6b"]
}
```

- `resolves`: a list of finding `id` strings. Each MUST appear in an **earlier** entry of the **same reviewer's** stream.
- `supersedes`: a list of `entry_hash` strings. Each MUST name an **earlier** entry of the **same reviewer's** stream. All findings raised in those entries become resolved. `supersedes` resolves **findings only**: it does not retract the earlier entry's verdict, which is simply replaced by the reviewer's latest verdict.
- `null`, non-list, or non-string values are invalid. `metadata` itself must be a JSON object.
- **Positional rule:** a resolving entry at sequence *k* closes only finding **instances** raised in entries with sequence < *k*. If the same id is raised again at a sequence > *k*, it is a new, **open** instance and needs a new, later resolution. An entry cannot resolve findings it raises itself.
- A reviewer can never resolve another reviewer's findings. Invalid refs are rejected at submit, make the stream fail `verify` (and so trigger the Step 0 BLOCK), and are ignored by convergence.
- Entries are never rewritten. Resolution only adds new entries.

**Backward compatibility:** 0.1.0 logs (no `resolves`/`supersedes`) verify and converge with the latest-verdict rule. Ad-hoc metadata keys (e.g. `resolved_findings`, `supersedes_entries`) carry **no** protocol meaning; findings they mention stay open.

### 4.4 Canonical JSON
Entry hashes are SHA-256 over the UTF-8 encoding of Python's `json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`:
- keys are sorted, and there is no whitespace;
- non-ASCII characters, including U+2028/U+2029, are emitted raw;
- there is no HTML escaping (`<`, `>`, `&` are literal);
- only `"`, `\` and control characters below U+0020 are escaped;
- numbers keep their literal form (`1.0`, `-0.0`, `1e-07`, big integers). The Go implementation decodes with `json.Number` and uses its own encoder to preserve this.

### 4.5 Legacy Go Hashes
wags-go 0.1.0 hashed with `encoding/json.Marshal`, which escapes `<`, `>`, `&` as `\u003c`/`\u003e`/`\u0026` and U+2028/U+2029 as `\u2028`/`\u2029`. For compatibility, `verify` (in both implementations) **accepts** an entry whose stored hash matches either the canonical hash or this legacy encoding. New entries are always written with the canonical hash.

---

## 5. 4-Phase Lifecycle Model

1. **`review`**: Reviewers independently read the target artifact and submit initial findings.
2. **`rebuttal`**: Author or peers submit counter-evidence or patch references in response to specific finding IDs.
3. **`meta-review`**: Synthesis pass to deduplicate findings and evaluate rebuttals.
4. **`convergence`**: Evaluates all final entries and seals `converged.json`.
