# wags

**Lightweight, polyglot, air-gappable multi-agent peer review protocol.**

wags enables heterogeneous AI agents and human reviewers to independently
assess artifacts (code, documentation, architectural proposals, evidence
bundles), debate findings through structured rounds, and converge on an
auditable decision without relying on central servers, network connections,
or external platforms.

## Core Principles

1. **Local-First & Air-Gappable** -- requires only standard filesystem
   read/write operations. No daemon, database, or network socket.
2. **Polyglot & Stdlib-Only** -- protocol data formats are standard JSON
   and JSON Lines (JSONL). Reference implementations rely strictly on
   standard library utilities.
3. **Single-Writer-Per-Stream** -- each reviewer appends solely to their
   dedicated log (`<reviewer>.jsonl`). Eliminates concurrency locks and
   merge conflicts.
4. **Tamper-Evident Hash Chaining** -- every log entry references the
   SHA-256 hash of the preceding entry (`prev_hash`), ensuring
   chronological auditability.
5. **Decisive Consensus** -- strict **P0-Veto + Majority Rule** model
   guarantees safety while avoiding deadlock.

## Install

```bash
pip install wags
```

## Quick Start

```python
from wags import WagsWorkspace, Finding

ws = WagsWorkspace(".wags")
rev = ws.init_review(
    target_path="spec.md",
    target_type="doc",
    description="v1.2 specification review",
    initiator="alice",
    review_id="rev-spec-001",
)
review_id = rev["review_id"]

ws.register_reviewer(review_id, "alice")
ws.submit_entry(
    review_id, "alice", phase="review",
    findings=[Finding("alice-P2-01", "P2", "docs",
                      "Add JSON schema reference",
                      "spec.md:3", "Link to schema")],
    verdict="approve",
)

# Verify integrity
ws.verify_review(review_id)

# Converge
result = ws.converge_review(review_id)
print(result["overall_verdict"])
```

## Go Reference Implementation

A stdlib-only Go reference implementation is provided in `wags/go/`.
It produces byte-identical hashes to the Python implementation and can
verify Python-written workspaces (and vice versa) via the
`WAGS_WORKSPACE` environment variable.

```bash
cd wags/go
WAGS_WORKSPACE=/path/to/.wags go run wags.go verify rev-spec-001
```

## Protocol Specification

See [`docs/wags-protocol.md`](docs/wags-protocol.md) for the full
protocol specification including file layout, entry schema, hash
computation, signature scheme, and convergence rules.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
