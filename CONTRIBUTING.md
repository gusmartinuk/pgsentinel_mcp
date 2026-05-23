# Contributing to PgSentinel MCP

Thank you for your interest in contributing. This document covers the guidelines for reporting issues, proposing changes, and submitting pull requests.

## Security Reports

**Do not open a public issue for security vulnerabilities.**

If you find a security problem (authentication bypass, secret leakage, SQL guard bypass, vault integrity issue), please email the maintainer directly. Include a description of the issue and reproduction steps. We will respond promptly and coordinate disclosure.

## Development Setup

```bash
git clone https://github.com/your-org/pgsentinel.git
cd pgsentinel
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the tests:

```bash
python -m pytest -q
```

Run the linter:

```bash
python -m ruff check app tests
```

Compile-check all modules:

```bash
python -m compileall app tests
```

## Running Locally

```bash
PGSENTINEL_VAULT=/tmp/pgsentinel-dev.enc \
PGSENTINEL_AUDIT_LOG=/tmp/pgsentinel-audit.jsonl \
uvicorn app.main:app --host 127.0.0.1 --port 8088
```

Then open `http://127.0.0.1:8088/admin/setup` for first-run setup.

## Pull Request Guidelines

- **One concern per PR.** Bug fixes, features, and refactors in separate PRs.
- **Tests required.** New functionality must include unit or integration tests. Security-boundary changes (auth, vault, SQL guard) require tests covering both the passing and blocking cases.
- **No new secrets in plaintext.** Do not add real credentials, vault files, SSH keys, or API tokens to the repository in any form.
- **Keep the security model intact.** PRs that add write tools, bypass allowlists, weaken the SQL guard, or expose secrets will not be merged without a detailed design discussion first.
- **Update relevant docs.** If you change behaviour documented in `docs/`, update the corresponding file.

## Code Style

- Python 3.11+ compatible syntax (project targets 3.13).
- `ruff` for linting — run before pushing.
- No commented-out code blocks.
- No `print()` in production paths — use the audit logger or structured logging.

## What Is In Scope

- Bug fixes in existing tools and connection modes.
- New MCP diagnostic tools that are read-only and follow the allowlist model.
- Additional connection modes (e.g. new SSH variants, new direct PostgreSQL modes).
- Web panel improvements (UI clarity, new target fields, better error messages).
- Test coverage improvements.
- Documentation improvements.

## What Requires Prior Discussion

Open an issue before starting work on:

- New write-path MCP tools.
- Changes to the vault format or encryption parameters.
- Changes to the SQL guard logic or policy model.
- New admin web panel capabilities that touch secrets.
- CSRF protection implementation (tracked in backlog).
- CI/CD pipeline setup.

## Commit Messages

Use short imperative present-tense subject lines, for example:

```
fix: handle empty allowed_containers in get_container_logs
feat: add get_container_env_vars diagnostic tool
docs: clarify SSH known_hosts persistence in deployment guide
test: add vault auto-lock timing test
```

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
