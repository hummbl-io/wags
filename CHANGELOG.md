# Changelog

## 0.2.0 - 2026-10-09

### Fixed
- `converge` no longer sums findings across every historical entry. Each reviewer's
  **latest** verdict counts, and only **open** findings count toward the P0 veto and P1 rule.
  (Seen in `rev-govbench-results-001`, which returned REQUEST_CHANGES on 3 withdrawn P1s
  although all three reviewers' latest verdicts were `approve`.)
- Go: entry hashing now matches Python canonical JSON (no HTML escaping of `<`, `>`, `&`).
  Previously Go failed to verify Python-written entries containing those characters.

### Added
- Optional `metadata.resolves` (finding ids) and `metadata.supersedes` (entry hashes),
  validated against the reviewer's own earlier entries, in Python and Go
  (`submit_entry(..., resolves=, supersedes=)`, CLI `--resolves/--supersedes`,
  Go `SubmitEntryWithMetadata`). `verify` flags invalid refs.
- `converged.json` gains `open_findings` and `resolved_findings`.

### Compatibility
- Hash format unchanged; 0.1.0 logs verify and converge (latest verdict wins).
- `PROTOCOL_VERSION` bumped to 0.2.0.
