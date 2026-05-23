# Deployment

## Vault-Based Deployment

PgSentinel MCP uses an encrypted vault for all secrets. First-run setup is done through the web panel.

```bash
docker build -t pgsentinel-mcp .
docker run --rm \
  -p 127.0.0.1:8088:8088 \
  -v /secure/pgsentinel:/secure/pgsentinel \
  -v /var/log/pgsentinel:/var/log/pgsentinel \
  --read-only --tmpfs /tmp \
  -e PGSENTINEL_VAULT=/secure/pgsentinel/vault.enc \
  -e PGSENTINEL_ENV=production \
  -e PGSENTINEL_COOKIE_SECURE=true \
  -e PGSENTINEL_ALLOW_LEGACY_CONFIG=false \
  -e PGSENTINEL_REQUIRE_EXISTING_VAULT=true \
  -e PGSENTINEL_AUDIT_LOG=/var/log/pgsentinel/audit.log \
  -e PGSENTINEL_MCP_HTTP_ENABLED=true \
  pgsentinel-mcp
```

On first run, visit `http://127.0.0.1:8088/admin/setup` to create the master password and initial agent key.

## Docker Compose

```bash
PGSENTINEL_DATA_DIR=/secure/pgsentinel docker compose up -d
```

Then visit `http://127.0.0.1:8088/admin/setup`.

After setup, strongly recommended for production:

```bash
export PGSENTINEL_REQUIRE_EXISTING_VAULT=true
docker compose up -d
```

This blocks startup if the vault file disappears unexpectedly and prevents silent re-initialization.

## Multi-Vault Mode

Use a vault directory and active vault pointer:

```bash
PGSENTINEL_VAULT_DIR=/secure/pgsentinel/vaults \
PGSENTINEL_ACTIVE_VAULT_FILE=/secure/pgsentinel/vaults/.active_vault \
PGSENTINEL_SSH_KNOWN_HOSTS=/secure/pgsentinel/vaults/known_hosts \
PGSENTINEL_REQUIRE_EXISTING_VAULT=true \
docker compose up -d
```

In multi-vault mode, active vault path resolves to:
`$PGSENTINEL_VAULT_DIR/<active_name>.vault.enc`

Manage vault switching/import/export from `/admin/vaults`.
Manage SQL execution policy from `/admin/settings`:
- default `readonly_default` keeps SQL read-only,
- optional `guarded_write` allows explicit category toggles,
- `SQL Hard Max Rows` caps per-call SQL result limits.
Generic `query_readonly_sql` must also be enabled explicitly on each PostgreSQL target.

Persistent SSH host keys:

- In multi-vault mode, host keys are persisted to `<vault_dir>/known_hosts` by default.
- Optional override: `PGSENTINEL_SSH_KNOWN_HOSTS=/custom/path/known_hosts`.
- This avoids losing SSH trust state on container restart.

## Vault Safety Guards

- Marker file: `${PGSENTINEL_VAULT_MARKER:-<vault_dir>/.vault_initialized}` is written after first successful setup.
- Startup fail-safe: if marker exists but `vault.enc` is missing, container exits with a fatal error.
- Save backup: each vault save keeps previous content at `vault.enc.bak`.

## Vault Backup

**The vault file contains all server credentials, SSH keys, and database passwords. There is no recovery path if it is lost.**

The automatic `vault.enc.bak` covers only the previous save. For real protection, copy the vault file to an external location regularly:

```bash
cp /secure/pgsentinel/vault.enc /secure/pgsentinel/vault.enc.$(date +%Y%m%d-%H%M%S).bak
```

Alternatively, back up the entire `/secure/pgsentinel` directory to off-host storage (encrypted backup service, object storage, etc.).

Vault files are AES-256-GCM encrypted and safe to store in encrypted backups. Do not store them in plain, unencrypted locations.

You can also export a vault copy from the web panel at `/admin/vaults` → Export.

## SSH Known Hosts: Persistence After Restart

SSH host keys are stored in the `known_hosts` file. By default this resolves to a path inside the container's home (`/tmp/.ssh/known_hosts`), which is **cleared on every container restart**.

After a restart the agent will fail with `Server '<host>' not found in known_hosts` until the key is re-trusted.

**Recommended:** configure `PGSENTINEL_SSH_KNOWN_HOSTS` to point to a path on the persistent volume so trust state survives restarts:

```bash
# Single-vault mode
PGSENTINEL_SSH_KNOWN_HOSTS=/secure/pgsentinel/known_hosts

# Multi-vault mode (default when PGSENTINEL_VAULT_DIR is set)
PGSENTINEL_SSH_KNOWN_HOSTS=/secure/pgsentinel/vaults/known_hosts
```

Add this to your `.env` file or `docker-compose.yml` environment block. The file is created automatically on first SSH connection to a new host (TOFU — Trust On First Use).

## Local Development

Set the vault path to a local temp location for development:

```bash
PGSENTINEL_VAULT=/tmp/pgsentinel-dev.enc \
PGSENTINEL_AUDIT_LOG=/tmp/pgsentinel-audit.jsonl \
uvicorn app.main:app --host 127.0.0.1 --port 8088
```

Then visit `http://127.0.0.1:8088/admin/setup` to set up.

## Legacy YAML Config

The old `config/pgsentinel.secrets.yml` fallback is for development and migration only.

In production (`PGSENTINEL_ENV=production`), legacy YAML fallback is disabled unless explicitly overridden:

```bash
PGSENTINEL_ALLOW_LEGACY_CONFIG=true
```

Production deployments should use the encrypted vault.

## Endpoints

- `GET /health` — health check (includes vault status)
- `GET /version` — version info
- `GET /config/summary` — minimal public config/vault status only
- `/admin/*` — web management panel (requires admin session)
- `/mcp` — MCP endpoint (requires Agent API Key + unlocked vault)
