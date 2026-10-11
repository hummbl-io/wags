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

### Security / integrity (Parallax round 3)
- **Protocol-downgrade fix:** `converged.json` records `anchor_context` (target protocol,
  registry mode, registered reviewers). A later downgrade to 0.1.0, a switch to legacy mode, or a
  disappeared registered reviewer gives BLOCK and is listed in `anchor_problems`. Legacy count-all
  mode now also requires no 0.2.0 markers (resolves/supersedes, `index.json` 0.2.0, a recorded
  registered mode), and is never re-entered once registered mode has been recorded. A 0.1.0
  target using resolves/supersedes gives BLOCK. The legacy Go hash form is likewise rejected
  when 0.2.0 markers exist.
- **Unparseable `converged.json` fails closed** (BLOCK, `anchor_status: "unparseable"`,
  persistent `anchor_lost`). New `anchor_status` field: absent / present / unparseable.
- **Quorum:** by default every registered reviewer must have voted before APPROVE (otherwise
  DEFER, "pending quorum"). `min_quorum` option in Python, both CLIs, and Go `ConvergeReviewOpts`.
- `index.json` per-review entries record `protocol_version`. Go `InitReview` now updates
  `index.json` (parity).
- The unregistered-stream error names the stream and its entry count (no more "line 0").
- Spec 4.6 lists the limits of unsigned files (pre-anchor deletion, anchor deletion/edit,
  joint rollback, rename without an anchor).

### Final review round (Parallax round 4)
- **`min_quorum` validation, identical in Python API/CLI and Go API/CLI:** must be an integer >= 1.
  Rejected: 0, negatives, floats, bools, strings. Values above the registered count give DEFER
  with `quorum.warning`. The output records the validated integer. Go API changed to
  `ConvergeReviewOpts(id, *int)` (nil = default). Previously Python treated -1 as "no quorum"
  while Go treated it as unset.
- **Hash-chained protocol marker:** new entries in non-0.1.0 reviews carry
  `metadata.wags_protocol`. A chained marker on a 0.1.0 target is a downgrade and gives BLOCK. This closes
  the index-scrub downgrade cases (N1, N2, N4, N5). 0.1.0 reviews stay unmarked.
- `anchor_status: "present_no_context"` for older `converged.json` files.
- Atomic JSON writes (temp + rename) in both implementations. Fixes a race where parallel
  converges could read a half-written `target.json` / `converged.json`.
- Spec: defer counts toward quorum, a silent reviewer stalls the review (remedies documented),
  `min_quorum` is a caller-side setting that gates must check, `index.json` is a hint only, and
  the honest downgrade limits.

### Pre-merge P3 fixes (Parallax round 5)
- Spec 4.6: documented that the chained marker only protects after the first tool-written entry
  (M1), and that hand-written entries can leave it out. Softened the "can't downgrade" wording.
- `min_quorum` CLI parity: an explicitly empty value (`-min-quorum ''` / `--min-quorum ''`) and
  oversized values are rejected identically in Python and Go with the same message. Both bound
  `min_quorum` to 1..1,000,000 (API and CLI). Previously Go treated `''` as the default and Python
  DEFERred on 20-digit values.
- Atomic writes now fsync the temp file and (POSIX) the directory before and after the rename.
  Go no longer drops the `converged.json` write error: `ConvergeReview` returns it and the CLI
  exits non-zero. The Python CLI prints the error and exits 1. On Windows the rename is retried
  for about 1s, then fails loudly.

### Note on unreleased intermediate builds
- Go logs written by the round-1 build of this PR (never released) may fail `verify`. Only
  0.1.0 (released) and final 0.2.0 formats are supported.

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
