# Technical Reference

## Security Boundaries

- No arbitrary shell command tool exists.
- SSH commands are built from fixed command arrays and quoted arguments.
- All secrets (SSH keys, DB passwords, API tokens) stored inside encrypted vault.
- Vault encryption: Argon2id + AES-256-GCM, decrypted contents in memory only.
- Two-layer access: master password for admin web panel, Agent API Key for MCP clients.
- Agent API Key stored as bcrypt hash only, never in plain text.
- Agent API Key hashing uses a fresh bcrypt salt for every rotation/generation.
- One-time Agent API Key display is kept in the server-side admin session only; it is not written to browser cookies.
- Docker access is limited to configured containers (server.allowed_containers).
- Empty Docker/PostgreSQL allowlists deny access unless the target explicitly enables allow-all.
- Local mode: `connection_mode: local` bypasses SSH and uses local Docker CLI.
- Log access is limited to configured log names.
- PostgreSQL access is limited to configured schemas and tables.
- Secrets are masked before outputs are returned to agents.
- Tool calls are audit logged through MCP-registered tool wrappers and admin routes.
- Auto-lock clears decrypted vault from memory after inactivity (default 30 min).

## Runtime

- Python: `3.13.13`
- Base image: `python:3.13-slim`
- App module: `app.main:app`
- Default port: `8088`
- Vault env var: `PGSENTINEL_VAULT` (default `/secure/pgsentinel/vault.enc`)
- Multi-vault dir env var: `PGSENTINEL_VAULT_DIR` (optional)
- Active vault pointer env var: `PGSENTINEL_ACTIVE_VAULT_FILE` (default `<vault_dir>/.active_vault`)
- SSH known_hosts env var: `PGSENTINEL_SSH_KNOWN_HOSTS` (default `<vault_dir>/known_hosts` in multi-vault mode, else `<vault_parent>/known_hosts`)
- Vault marker env var: `PGSENTINEL_VAULT_MARKER` (default `<vault_dir>/.vault_initialized`)
- Startup guard env var: `PGSENTINEL_REQUIRE_EXISTING_VAULT` (when true, startup fails if vault is missing)
- Cookie secure env var: `PGSENTINEL_COOKIE_SECURE` (defaults true in production)
- Legacy config env var: `PGSENTINEL_ALLOW_LEGACY_CONFIG` (defaults false in production)
- Audit log env var: `PGSENTINEL_AUDIT_LOG` (default `audit/pgsentinel-audit.jsonl`)
- Legacy config env var: `PGSENTINEL_CONFIG` (fallback path)
- Docker entrypoint: starts as root to repair persistent bind-mount ownership for data/log paths,
  creates/touches audit and server log files, optionally maps the mounted Docker socket GID to the
  app user, then drops to `app` via `gosu`.

## Module Map

### `app/core/vault.py`
- `ServerDef`, `PostgresTargetDef`, `MonitoringTargetDef` — vault data models
- `VaultData` — full vault contents
- `Vault` — encryption/decryption engine (Argon2id + AES-256-GCM)
- `AgentConfig`, `SecuritySettings` — configuration data models
- `save()` creates `vault.enc.bak` before replacing the active vault file
- Envelope includes format/version metadata (`version`, `data_version`, `app_version`)

### `app/core/vault_manager.py`
- `get_vault()` — singleton vault accessor
- `vault_exists()`, `vault_is_locked()`, `vault_is_unlocked()`
- `unlock_vault()`, `lock_vault()`, `create_vault()`
- `get_vault_data()`, `save_vault()`
- `create_session()`, `get_session()`, `destroy_session()`
- Auto-lock timer management
- `create_vault()` writes an initialization marker file next to the vault
- Multi-vault helpers:
  - `list_vaults()`, `get_active_vault_name()`
  - `switch_active_vault()`, `create_named_vault()`
  - `import_vault_bytes()`, `export_vault_bytes()`
  - `_reset_active_vault_only()` — drops vault cache but preserves admin sessions + runtime master password (used by definition switching)
  - `set_shared_agent_key()`, `set_shared_agent_enabled()` — propagate agent key / enabled state to all definition vaults
  - `_apply_to_all_definitions(mutate)` — apply a mutation function to every vault in the vault dir

### `app/core/agent_key.py`
- `generate_agent_token()` — `pgs_ai_*` format
- `hash_agent_token()` — bcrypt hash with fresh per-hash salt
- `verify_agent_token()` — bcrypt check
- `is_valid_agent_token_format()` — format validation

### `app/admin/routes.py`
- `/admin/setup` — first-run vault creation
- `/admin/login` — unlock vault
- `/admin/login/select_vault` — select existing vault when active vault pointer is missing/wrong
- `/admin/dashboard` — vault status overview
- `/admin/definitions` — definition list (each 8-char code = one vault + VPS + optional PostgreSQL)
- `/admin/definitions/new` — create new definition
- `/admin/definitions/<code>/edit` — edit existing definition
- `/admin/definitions/<code>/archive` — soft-delete (rename) a definition vault
- `/admin/definitions/test` — unified VPS + PostgreSQL connection test (used by the definition form)
- `/admin/vaults/<name>/download` — download vault backup
- `/admin/vaults/import` — import a vault file
- `/admin/agent` — agent key management (rotate, toggle, shared across all definitions)
- `/admin/settings` — security settings (SQL policy mode, SQL category toggles, SQL hard max row cap)
- `/admin/audit` — audit log viewer
- All forms: `autocomplete="off"`, secret fields use `new-password`, no prefill on edit

### `app/mcp/auth.py`
- `MCPAuthMiddleware` — FastAPI middleware for `/mcp/*` routes
- Validates Agent API Key, vault existence, vault unlock state, agent enabled state

### `app/mcp/tools.py`
- `register_tools()` — registers core + safe diagnostic tools with vault target support
- `_resolve_server()`, `_resolve_postgres_target()` — target resolution helpers

### `app/tools/postgres.py`
- Vault PostgreSQL targets use their linked `server_id` server when running Docker/local psql commands.
- Direct PostgreSQL MCP modes (`postgres_direct_tcp`, `postgres_direct_tls`, `ssh_tunnel_direct_postgres`) use `DirectPostgresClient` and psycopg.
- `query_readonly_sql` supports policy-guarded SQL categories and optional per-call `limit` bounded by SQL hard max; MCP execution also requires target-level `sql_query_enabled`.

### `app/core/security.py`
- `guard_sql_query` performs SQL statement classification and policy enforcement.
- Guards include single-statement enforcement, comment blocking, deny-by-default for unknown/ambiguous SQL, and category-based allow toggles.

### `app/tools/safe_diagnostics.py`
- Narrow allowlisted diagnostic tooling layer (no generic exec surface).
- Provides deployment/container/log/PostgreSQL/file-symbol checks:
  - deployment/container: info, status, image, restart counts
  - logs: grouped errors, logs since deploy
  - PostgreSQL: migrations, failed jobs, table row count
  - source checks: allowlisted file contains, allowlisted module symbol checks
  - diagnosis wrappers: deployment/worker/database/http-5xx
- Enforces extra allowlists for source file/module checks via static allowlist sets.

### `app/remote/direct_postgres.py`
- `DirectPostgresClient` — runs generated read-only JSON SQL through psycopg.
- `postgres_direct_tcp` / `postgres_direct_tls` connect directly to `target.host:target.port`.
- `ssh_tunnel_direct_postgres` creates a Paramiko local forwarder through the linked server and connects psycopg to the forwarded local port.
- psycopg connections set PostgreSQL `statement_timeout` from `SecuritySettings.command_timeout_seconds`.
- TLS CA/client cert/key values are written to temporary files only for the active connection and removed afterwards.

### `app/remote/connection.py`
- `ConnectionAdapter` — unified interface for all connection modes
- `CommandResult` — command execution result
- SSH via Paramiko (key from vault, temp file), local via subprocess
- Docker commands: `docker ps`, `docker inspect`, `docker logs`, `docker exec psql`
- SSH host key handling uses persistent known_hosts path with TOFU-style first-seen key persistence.

### Templates (`app/templates/`)
- `base.html.j2` — base layout with dark theme, nav bar, security headers
- `setup.html.j2`, `login.html.j2` — setup and login
- `dashboard.html.j2` — vault/definition status overview
- `definitions.html.j2` — definition list with download/archive and vault import
- `definition_form.html.j2` — single form: VPS (local/ssh) + optional PostgreSQL + access level
- `agent.html.j2` — shared agent key management (rotate, toggle)
- `settings.html.j2` — security settings
- `audit.html.j2` — audit log viewer

## Connection Modes

| Mode | Description | Used For |
|---|---|---|
| `local` | Local Docker CLI | Dev/testing on same machine |
| `ssh` | Paramiko SSH | Remote VPS with Docker |
| `docker_exec_psql_over_ssh` | SSH + docker exec psql | Containerized PostgreSQL |
| `ssh_tunnel_direct_postgres` | SSH tunnel + psycopg | Direct PostgreSQL over SSH |
| `postgres_direct_tcp` | Direct psycopg TCP | Private network PostgreSQL |
| `postgres_direct_tls` | Direct psycopg with TLS | TLS-secured PostgreSQL |

## Audit Events

### Admin
- `first_run_setup_completed`, `vault_unlock_success`, `vault_unlock_failed`, `vault_lock`
- `definition_created`, `definition_updated`, `definition_archived`
- `agent_key_rotated`, `agent_access_enabled`, `agent_access_disabled`
- `settings_updated`
- `connection_test`

### Agent
- `mcp_auth_success`, `mcp_auth_failed`
- Tool calls: `mcp_tool_called` (per-tool audit via `@audit_tool_call` decorator)

## Storage Model

```
/secure/pgsentinel/vault.enc     — encrypted vault (writable mount)
/var/log/pgsentinel/audit.log     — JSONL audit events
/var/log/pgsentinel/server.log    — application logs
```

No plain secrets in: `.env`, YAML, JSON, SQLite, browser localStorage/sessionStorage, cookies.

## Browser Security

- All admin pages: `Cache-Control: no-store`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`
- Session cookies: `HttpOnly`, `SameSite=Strict`
- All forms: `autocomplete="off"`, `autocapitalize="off"`, `spellcheck="false"`
- Password fields: `autocomplete="new-password"` / `current-password`
- No secrets in form prefill, no localStorage/sessionStorage usage
- No Agent API Key values in cookies; only the opaque admin session cookie is stored client-side.

## 2026-05-27 Notes

- `AgentConfig` now includes `expires_at` ISO timestamp; empty value means key does not expire.
- `MCPAuthMiddleware` rejects expired agent keys.
- `register_tools` requires `profile_code` across MCP tools and checks match with active 8-char vault code.
- Server/target resolution errors are intentionally generic to avoid inventory leakage.

## 2026-05-27 Notes (Recovery)

- Added `reset_master_password_with_recovery()` and one-time recovery key reveal flow.
- Recovery sidecar file format: JSON envelope (`scrypt` + `AES-256-GCM`) at `<vault_path>.recovery`.
- Added `consume_pending_recovery_key()` for one-time admin display.
- `reset_vault()` now clears runtime master password state so restart-style tests cannot pass via
  stale in-memory secrets.
- App lifespan attempts auto-unlock from `PGSENTINEL_MASTER_PASSWORD` or
  `PGSENTINEL_MASTER_PASSWORD_FILE` when a vault exists.
