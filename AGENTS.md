# AGENTS.md — wags

## Project

**wags** — Lightweight, polyglot, air-gappable multi-agent peer review protocol. Stdlib-only Python + Go reference implementations for tamper-evident review trails and multi-agent consensus.

## Scope

- In scope: Core protocol specification (`docs/wags-protocol.md`), Python reference implementation (`wags/`), Go reference implementation (`wags/go/`), CLI utilities, verification and convergence algorithms, unit and cross-language compatibility tests.
- Out of scope: Centralized SaaS orchestration, external databases, cloud-specific network bridges.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate  # Or .venv\Scripts\Activate.ps1
pip install -e ".[test]"
```

## Testing

```bash
python -m pytest tests/ -v
```

Ensure Go 1.22+ is available for cross-language compatibility tests.

## Conventions

- Follow HUMMBL agent governance guidelines.
- Python 3.11+ required.
- Standard library only for production core (zero runtime dependencies).
- Commit format: Conventional Commits (`feat:`, `fix:`, `chore:`, etc.).
- Branch naming: `type/agent/short-desc`.
- Never commit secrets, reviewer private keys, or credentials.
- All protocol changes require test coverage in both Python and Go suites.
- License: Apache 2.0.
