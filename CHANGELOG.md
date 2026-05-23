# Changelog

All notable changes to PgSentinel MCP are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Known gaps
- CSRF tokens not yet implemented on web panel forms (mitigated by SameSite=Strict cookies).
- SSH integration tests against real VPS infrastructure are pending.
- CI pipeline not yet configured.

---

## [0.1.0] — 2026-05-22

Initial public release.

### Added

**Security model**
- Two-layer access: master password for admin web panel, Agent API Key (`pgs_ai_*`) for MCP clients.
- Encrypted vault (Argon2id key derivation + AES-256-GCM authenticated encryption).
- Vault auto-lock after configurable inactivity timeout (default 30 min).
- Vault backup file (`vault.enc.bak`) written before every save.
- Startup fail-safe: container exits if initialization marker exists but vault file is missing.
- Envelope versioning for future vault format migrations.
- Multi-vault mode: switch, create, import, and export named vaults from the web panel.

**Web management panel**
- First-run setup wizard (master password + initial agent key generation).
- Login / vault unlock screen.
- Dashboard: vault status, target counts, lock controls.
- Server CRUD: SSH server definitions stored in vault.
- PostgreSQL target CRUD: multi-mode connection definitions.
- Monitoring target CRUD: HTTPS API and health endpoint definitions.
- Agent key management: generate, rotate, enable/disable.
- Security settings: auto-lock timeout, SQL policy mode, SQL category toggles, hard row cap.
- Audit log viewer.
- Vault management: list, switch active vault, create, import, export.
- No-cache response headers on all admin pages.
- No secret prefill on edit forms; placeholder-only display for stored secrets.
- HttpOnly + SameSite=Strict session cookies.

**Agent API Key**
- Format: `pgs_ai_<random high-entropy token>`.
- Stored as bcrypt hash only; raw key never persisted.
- Shown once after generation (server-side session state, not browser cookie).
- Rotatable and disableable from web panel.

**MCP endpoint**
- Streamable HTTP transport via `StreamableHTTPSessionManager`.
- Bearer token authentication middleware for all `/mcp/*` routes.
- Auth middleware checks: path → header format → vault exists → vault unlocked → agent enabled → bcrypt verify.

**MCP tools**
- `health_overview`, `get_docker_containers`, `get_container_logs`, `search_logs`, `get_recent_errors`
- `get_postgres_health`, `list_allowed_tables`, `describe_table`, `get_table_sample`
- `diagnose_recent_failure`
- `query_readonly_sql` (policy-guarded; requires target-level enablement)
- Safe diagnostic extensions: deployment info, container status/image/restart counts, grouped errors, logs since deploy, migrations, failed jobs, table row counts, source file/module symbol checks, diagnosis wrappers (deployment, worker, database, HTTP 5xx).

**Connection modes**
- `local` — local Docker CLI.
- `ssh` — Paramiko SSH to remote VPS.
- `docker_exec_psql_over_ssh` — SSH + docker exec psql.
- `ssh_tunnel_direct_postgres` — SSH tunnel + psycopg direct connection.
- `postgres_direct_tcp` — direct TCP psycopg.
- `postgres_direct_tls` — direct TLS psycopg.
- `https_api` — HTTP requests with Bearer token.
- `monitoring_endpoint` — HTTP health checks.

**SQL execution policy**
- `readonly_default` mode: SELECT, WITH, EXPLAIN, SHOW, VALUES only.
- `guarded_write` mode: non-read categories allowed only when their toggle is explicitly enabled.
- Single-statement enforcement; multi-statement SQL blocked.
- Deny-by-default for unknown or ambiguous statement types.
- Per-call row limit clamped to hard cap from security settings.
- `SHOW`/`EXPLAIN` results returned as text fallback (no LIMIT appended).

**Audit logging**
- JSONL audit log for all admin events and MCP tool calls.
- Covers: vault lifecycle, server/target CRUD, agent key rotation, MCP auth, tool calls.
- No secrets, no raw log payloads, no full SQL result rows in audit entries.

**Secret masking**
- Output masking layer applied before returning any MCP tool result.
- Masks common patterns: `password=`, `token=`, `Authorization:`, `Bearer`, private key headers, etc.

**SSH host key persistence**
- TOFU-style first-seen key persistence to `known_hosts` file.
- Configurable persistent path via `PGSENTINEL_SSH_KNOWN_HOSTS` (survives container restarts when pointed to a persistent volume).

**Docker deployment**
- Bind to `127.0.0.1:8088` by default.
- Read-only container filesystem with `tmpfs /tmp`.
- Non-root `app` user.
- Docker healthcheck via HTTP `/health`.

**Test suite**
- 51 unit and integration tests covering vault encryption/decryption, agent key lifecycle, MCP auth middleware, SQL guard, masking, web panel forms, tool registration, and safe diagnostic tooling.

---

[Unreleased]: https://github.com/your-org/pgsentinel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/pgsentinel/releases/tag/v0.1.0
