# wags Protocol Specification (v0.2.0)

**Status:** DRAFT / PROPOSED  
**Author:** Multi-Agent Collective (`alice`, `gemini`, `operator`)  
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
  "reviewer": "alice",
  "phase": "review",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "findings": [
    {
      "id": "alice-P1-01",
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
**Step 0: integrity, registration and anchors.** Before counting anything, convergence runs `verify` and checks the previous anchors (4.6).
- **Registration (fail closed).** Only reviewers listed in `reviewers.json` vote.
  - A stream that has entries (or unparseable content) but no registration **fails `verify`** and forces **`BLOCK`**. It is listed in both `unregistered_streams` and `invalid_streams`. So deleting a vetoer's key from `reviewers.json` cannot silently drop their vote.
  - Empty unregistered stream files are ignored.
  - A missing or empty `reviewers.json` does **not** relax this for 0.2.0 targets.
- **Legacy registry mode** (`registry_mode: "legacy_all_streams"`) applies **only** to a genuine 0.1.0 review. All of these must hold:
  - `target.json` says `protocol_version: "0.1.0"`;
  - the registry is empty or missing;
  - **no 0.2.0 marker** exists anywhere: no entry uses `resolves`/`supersedes`, `index.json` (workspace or per-review entry) doesn't declare 0.2.0, `converged.json` doesn't record a 0.2.0 `anchor_context` or `registry_mode: "registered"`, and `converged.json` isn't unparseable.
  - Once registered mode has been recorded, a review **never** falls back to legacy.
  - **Hash-chained marker:** every new entry in a review whose target is not 0.1.0 carries `metadata.wags_protocol: "0.2.0"`, which `entry_hash` covers. Entries in 0.1.0 reviews stay unmarked, so old reviews can continue. Any chained marker counts as a 0.2.0 marker. On a 0.1.0 target it is reported as a protocol downgrade and gives **BLOCK**.
  - Once a 0.2.0 review has **at least one tool-written entry**, editing `target.json` to 0.1.0, emptying the registry and scrubbing `index.json` or `converged.json` is detected and gives BLOCK, because the marker sits inside a hash-chained entry. This is protection against casual tampering, not a guarantee. See the limits in 4.6 (M1, hand-written entries, full chain regeneration).
- **Integrity.** Streams that fail verification are excluded, listed in `invalid_streams`, and force **`BLOCK`**. Verification covers bad hashes, broken `prev_hash` links, `sequence` not 1..n in file order, `reviewer` not matching the stream, invalid resolution refs, unregistered entries, and disallowed legacy hashes.
  - **Availability caveat:** because of this, anyone who can write a registered reviewer's file (or add an unregistered one) can **stall** a review with garbage. That is a deliberate fail-closed trade-off: wags prefers a stuck review to a silently wrong approval. An operator must repair or remove the stream.
- **Regressions and anchor problems.** If any stream regressed since the last anchor (4.6), or there is any anchor/protocol problem (4.6), the verdict is **`BLOCK`**. Streams are listed in `regressed_streams`, and other problems in `anchor_problems`; both are also stated in `rationale`. So a gate that reads only `overall_verdict` still stops.
- **Protocol consistency.** If `target.json` says 0.1.0 but entries use `resolves`/`supersedes`, the verdict is **BLOCK**. To use 0.2.0 features on an old review, upgrade its `target.json` to 0.2.0 first. If the registry is also empty, any other 0.2.0 marker likewise gives BLOCK.
- **Output.** `verify_valid` is the raw result over all stream files. `invalid_streams` names every stream that failed and why, so an invalid result is never ambiguous.

Then, per valid stream, processed in `sequence` order:
- **Latest verdict wins.** A reviewer's vote is the `verdict` of their highest-sequence entry that has one. A later entry with no verdict does not reset the vote.
- **Only open findings count.** See 4.3 for when a finding is resolved. Resolved findings stay in the log and are reported in `resolved_findings`.

Rules, in order:
1. **P0 Rule (Absolute Veto)**: any **open** `P0`, or any latest verdict `block`, gives **`BLOCK`**. Findings with an unrecognised severity are treated as `P0` (listed in `unknown_severity_findings`). Implementations reject unknown severities at submit.
2. **P1 Rule**: any latest verdict `request_changes`, or any **open** `P1` whose reviewer's latest verdict is not `approve`, gives **`REQUEST_CHANGES`**.
   - **Policy change from 0.1.0:** an open P1 raised by a reviewer whose latest verdict is `approve` **no longer blocks**. That reviewer has accepted their own finding as non-blocking. The finding still appears in `open_findings` and `open_findings_by_severity`. To keep it blocking, the reviewer should vote `request_changes`.
3. **Quorum**: by default **every registered reviewer** must have a latest verdict before the review can be `APPROVE`. Until then the result is **`DEFER`** ("pending quorum"). BLOCK and REQUEST_CHANGES are still reported immediately.
   - **A `defer` vote counts toward quorum.** It is a verdict.
   - **A registered reviewer who never votes stalls the review forever** (DEFER). The remedies are an explicit `min_quorum`, or de-registering that reviewer **before the first anchor**. After an anchor, de-registering is a recorded regression and gives BLOCK.
   - **`min_quorum`:** Python `converge_review(..., min_quorum=N)`, CLI `--min-quorum N`, Go `ConvergeReviewOpts(id, &n)` / `converge <id> -min-quorum N`. It must be an **integer >= 1**. `0`, negatives, floats (`1.5`, `2.0`), booleans and strings (`"2"`, `"abc"`) are **rejected** with "min_quorum must be a positive integer (>= 1)". The CLIs accept only ASCII digits. Python and Go apply the same rule.
   - A `min_quorum` **above the registered count** isn't rejected. The result is **`DEFER`** with `quorum.warning` explaining that quorum can never be met.
   - In legacy mode the default is the number of voters.
   - Output: `quorum {required, voted, registered, min_quorum (the validated integer or null), warning}` and `quorum_met`.
   - **`min_quorum` is a caller-side setting.** Whoever runs converge chooses it, and it isn't stored in the review. Gates that act on `overall_verdict` should also check `quorum.min_quorum` (and `quorum.required` against `quorum.registered`) in `converged.json`, so a lowered quorum isn't accepted unnoticed.
4. **Majority Approval**: if there are no blockers and at least 50% of reviewers with a verdict submit `approve`, the verdict is **`APPROVE`**.
5. **Tie / Inconclusive**: otherwise **`DEFER`**.

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
wags-go 0.1.0 hashed with `encoding/json.Marshal`, which escapes `<`, `>`, `&` as `\u003c`/`\u003e`/`\u0026` and U+2028/U+2029 as `\u2028`/`\u2029`.
- `verify` accepts an entry whose stored hash matches this legacy encoding **only** when `target.json` declares `protocol_version: "0.1.0"`, **and** only while no canonical-form entry has yet appeared in that stream. A legacy-form entry after a canonical-form one is rejected.
- In 0.2.0 reviews only the canonical hash (4.4) is accepted.
- New entries are always written in canonical form.
- The Go encoder widens `float32` to `float64` before formatting, matching what Python would see.

### 4.6 Truncation, Deletion and Anchors
**What the hash chain cannot do.** Each entry commits to its predecessor, so editing, reordering or inserting entries is detectable. But a chain **cannot detect truncation from the tail, or deletion of a whole stream**: a prefix of a valid chain is itself a valid chain, and a missing file has nothing to check. Without an external reference, a reviewer's final `block` can be dropped and `verify` still passes.

**Anchors.** Each convergence writes `anchors` into `converged.json`: for every counted stream, the latest `{sequence, entry_hash}`. On the next convergence, a stream is **regressed** if any of these hold:
- the file is gone;
- it has fewer entries than the anchored sequence;
- the entry at the anchored sequence no longer has the anchored hash;
- the reviewer was removed from `reviewers.json`.

Any regression forces **`BLOCK`**, and the stream is listed in `regressed_streams` with a reason. A regressed stream keeps its old anchor, so the BLOCK persists until an operator intervenes. Streams that only grew are fine.

**Anchor context and status.**
- `converged.json` also records `anchor_context`: `{protocol_version (target's), registry_mode, registered_reviewers}`. On the next converge, each of these is an anchor problem and gives **BLOCK**:
  - a downgrade from a recorded non-0.1.0 protocol to 0.1.0;
  - a change from `registered` to `legacy_all_streams`;
  - a recorded registered reviewer missing from `reviewers.json`.
- The old context is kept while a problem persists.
- `anchor_status` is `absent` (first converge), `present`, `present_no_context` (an older `converged.json` without `anchor_context`, e.g. written by an earlier build; stream anchors are still checked), or `unparseable`. **Unparseable fails closed**: it gives BLOCK and sets `anchor_lost: true`, which is carried forward, so every later converge blocks until an operator reviews it. (Deleting `converged.json` clears this; see the limits.)

**Durability and concurrency.** `converged.json`, `target.json`, `index.json` and `reviewers.json` are written atomically, so a concurrent reader never sees a partial file:
- the data goes to a temp file in the same directory, which is **fsynced**;
- the temp file is renamed over the target;
- the directory is then fsynced (POSIX; skipped where unsupported, e.g. Windows).

A failed write is **never silent**. Python raises `OSError`, and the CLI prints an error and exits 1. Go `ConvergeReview` returns an error, and the CLI exits non-zero.

**Windows:** replacing a file that another process holds open fails with an access error. Both implementations retry the rename for about 1 second (20 × 50 ms), then fail with the error and remove the temp file. Close readers or retry the converge.

**Limits of unsigned files (important).** wags files are plain, unsigned files, so anyone with write access to the workspace can defeat local checks. Known cases:
- Truncation that happens **before the first convergence** is undetectable. There is no anchor yet.
- **A whole stream deleted (together with its registry entry) before the first convergence** is undetectable. The reviewer simply never existed.
- **The anchor itself can be deleted or edited.** Removing `converged.json` resets `anchor_status` to `absent`. Editing out one reviewer's stream anchor *and* that reviewer's `anchor_context.registered_reviewers` entry hides their truncation. Rolling back a stream and `converged.json` together to an earlier consistent snapshot is also undetectable.
- **Renaming a stream** (e.g. `a.jsonl` to `c.jsonl` and re-registering) is caught only when an anchor exists. Without one it looks like a different reviewer.
- **Downgrade cases that need `index.json` scrubbed** (Parallax cases N1, N2, N4, N5), in each case with `target.json` set to 0.1.0 and the registry emptied:
  - **N1:** downgrade before the first anchor.
  - **N2:** `converged.json` deleted.
  - **N4:** `anchor_context` edited to claim legacy/0.1.0.
  - **N5:** `anchor_context` removed.
  Without the chained marker these would rely only on the index marker and could slip through. With the marker, all four give **BLOCK**, because the streams' own hash-chained entries declare 0.2.0. They would be undetectable only if the attacker also rewrites every stream with recomputed hashes and no markers. Any attacker able to regenerate entire chains defeats every local check. Only an external copy of the anchor (or signatures) can catch that.
- **M1, no tool-written entries yet:** if a 0.2.0 review has registered reviewers but **zero entries**, there's no chained marker to find. An attacker who downgrades `target.json`, empties the registry, scrubs `index.json` and adds one unmarked approval gets **APPROVE in legacy mode** (both implementations). The marker only protects a review after its first tool-written entry.
- **Hand-written entries:** the marker is added by the reference tools. A hand-written (or third-party-tool) entry can simply leave it out and still be a valid chain link, so unmarked streams provide no downgrade evidence.
- `index.json` is a hint, not a security boundary.
- The anchor lives in `converged.json`, in the same directory an attacker would edit. **It only means something if a copy is kept somewhere tamper-resistant**: committed to git, published, or sent to another party. Then compare the anchors in your trusted copy before acting on a verdict. Deleting or rolling back `converged.json` locally erases the local anchor.
- The registry (`reviewers.json`) is not hash-chained. It is protected by the fail-closed rule in Step 0 and by the anchor check (removing an anchored reviewer is a regression), not by cryptography.

**Resolution refs** (4.3): `resolves: []` and `supersedes: []` are rejected as no-ops, in both implementations.

---

## 5. 4-Phase Lifecycle Model

1. **`review`**: Reviewers independently read the target artifact and submit initial findings.
2. **`rebuttal`**: Author or peers submit counter-evidence or patch references in response to specific finding IDs.
3. **`meta-review`**: Synthesis pass to deduplicate findings and evaluate rebuttals.
4. **`convergence`**: Evaluates all final entries and seals `converged.json`.
