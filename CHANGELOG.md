# Changelog

## 0.2.0 - 2026-10-09

### Fixed
- `converge` no longer adds up findings from every historical entry. Each reviewer's
  **latest** (highest-sequence) verdict is their vote, and only **open** findings count toward
  the P0 veto and the P1 rule.
- `converge` now runs `verify` first. Registered streams that fail verification are excluded
  and reported in `invalid_streams`, and they force `BLOCK`. Streams not in `reviewers.json` are
  reported in `unregistered_streams` (see the round-2 notes above for fail-closed handling). Verify also checks `sequence` is 1..n and that `reviewer` matches the stream.
- Go: entry hashing now uses a dedicated canonical encoder that matches Python byte for byte
  (no HTML escaping, raw U+2028/9, literal backslash text preserved, number literals such as
  `1.0`, `-0.0`, `1e-07` preserved via `json.Number`). Previously Go could not verify
  Python-written entries containing `<`, `>`, `&` or such numbers.
- Go `RegisterReviewer` now records the reviewer in `reviewers.json`, as Python does.

### Security / integrity (Parallax round 2)
- **Anchors (spec 4.6):** each convergence records every counted stream's latest
  `{sequence, entry_hash}` in `converged.json`. The next convergence BLOCKs and lists
  `regressed_streams` if a stream was truncated, emptied or deleted, lost its anchored entry, or
  its reviewer was removed from `reviewers.json`. The spec now says plainly that a hash chain
  alone cannot detect tail truncation or stream deletion, and that the anchor only helps if
  `converged.json` is kept somewhere tamper-resistant (git, published).
- **Fail-closed registration:** a stream with entries but no `reviewers.json` registration now
  fails `verify` and BLOCKs converge. Deleting a vetoer's key no longer drops their vote.
- **Legacy registry mode** (count every stream) applies only to protocol 0.1.0 targets with an
  empty or missing registry. It is no longer triggered by emptying `reviewers.json` on 0.2.0 reviews.
- **Legacy Go hash form** is accepted only for 0.1.0 targets and never after a canonical-form
  entry in the same stream.
- Go encodes `float32` by widening to `float64` (matches Python).
- `resolves: []` / `supersedes: []` are rejected.
- `converged.json` adds `registry_mode`, `regressed_streams`, `anchors`, `verify_valid` and
  `verify_scope`. `invalid_streams` now also covers unregistered streams with content.
- Documented: a garbage registered stream (or unregistered stream with content) can stall a
  review. This is the deliberate fail-closed trade-off.

### Added
- Optional `metadata.resolves` (finding ids) and `metadata.supersedes` (entry hashes), in Python
  and Go. They are **positional**: they close only finding instances raised in the same reviewer's
  *earlier* entries, so a finding id raised again afterwards is open again. Cross-reviewer, dangling,
  self-entry and `null` refs are rejected at submit and fail `verify`. `supersedes` resolves
  findings, not verdicts.
- `converged.json`: `open_findings`, `resolved_findings`, `summary.open_findings_by_severity`,
  `invalid_streams`, `unregistered_streams`, `registry_empty`, `unknown_severity_findings`.
- Submit rejects unknown severities and non-object `metadata`. Converge treats any unknown
  severity found in a log as P0.

### Changed (policy)
- **An open P1 from a reviewer whose latest verdict is `approve` no longer blocks.** It is still
  reported in `open_findings` / `open_findings_by_severity`, which include such non-blocking P1s.
- The 0.1.0 *implementation* counted every P1 ever filed as blocking. The 0.1.0 *spec text*
  ("P0 finding with a block verdict"; "unresolved P1 ... and votes request_changes") did not
  match that implementation in either direction. 0.2.0 makes spec and code agree: any **open**
  P0 vetoes regardless of verdict, and P1s follow the rule above.

### Compatibility
- Hash format is unchanged for Python-written entries. Entries written by wags-go 0.1.0 with
  `<`, `>`, `&`, U+2028 or U+2029 still verify, through the legacy-hash fallback (spec section 4.5).
- 0.1.0 logs verify and converge, with the latest verdict winning. Ad-hoc metadata keys don't resolve anything.
  Example: `rev-govbench-results-001` converges to APPROVE only through the latest-verdict rule.
  MTSMU's earlier P1s stay **open** (non-blocking under its approve), because its entry #3 used
  non-protocol keys.
- `summary.findings_by_severity` keeps its 0.1.0 meaning (all findings).
- `PROTOCOL_VERSION` is now 0.2.0.
