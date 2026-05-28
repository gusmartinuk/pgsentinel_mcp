# Testing

## Test Suite

```bash
python -m pytest -q
python -m compileall app tests
```

All 51 tests must pass before submitting a pull request.

Optional: run the linter:

```bash
python -m ruff check app tests
```

## Development Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Start a local instance with a temporary vault:

```bash
PGSENTINEL_VAULT=/tmp/pgsentinel-dev.enc \
PGSENTINEL_AUDIT_LOG=/tmp/pgsentinel-dev-audit.jsonl \
uvicorn app.main:app --host 127.0.0.1 --port 8088
```

Then open `http://127.0.0.1:8088/admin/setup` to create the master password and initial agent key.

## Docker Build Test

```bash
docker compose config
docker build -t pgsentinel-mcp:test .
```

## Restart/Recreate Smoke Test

For deployment changes, verify the real container, not only `TestClient`:

```bash
docker compose build pgsentinel-mcp
docker compose up -d --force-recreate pgsentinel-mcp
curl -i http://127.0.0.1:8088/health
curl -i -X POST http://127.0.0.1:8088/admin/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'master_password=definitely-wrong-password'
```

Expected: the login attempt returns `401 Invalid master password`, not `500`; this confirms audit log
writes are not blocked by bind-mount permissions. If `PGSENTINEL_MASTER_PASSWORD_FILE` points to a
valid mounted secret, `/health` should report `vault: unlocked` after startup.

## MCP Endpoint Smoke Test

After setup and vault unlock, test the MCP endpoint with a real agent key:

```bash
# 1) initialize — save the mcp-session-id header value
curl -i -sS \
  -H "Authorization: Bearer pgs_ai_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -X POST http://127.0.0.1:8088/mcp/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'

# 2) list tools
curl -sS \
  -H "Authorization: Bearer pgs_ai_YOUR_KEY" \
  -H "mcp-session-id: YOUR_SESSION_ID" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -X POST http://127.0.0.1:8088/mcp/mcp \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

Expected: `status: ok` from `/health`, non-empty `tools` array from `tools/list`.

## SSH Integration Test

Requires a real server target configured in the vault (connection_mode: `ssh` or `docker_exec_psql_over_ssh`).

Before running SSH-based MCP tools, ensure the server host key is trusted. Either:
- Run the tool once and accept via the admin panel, or
- Pre-populate `known_hosts` at the path configured in `PGSENTINEL_SSH_KNOWN_HOSTS`.

Paramiko uses strict host key checking and will fail with `not found in known_hosts` until the key is trusted.

## Audit Log Verification

After any MCP tool call, check the audit log:

```bash
tail -n 5 /tmp/pgsentinel-dev-audit.jsonl | python -m json.tool
```

Every tool call should produce an entry with `event: mcp_tool_called`, `tool`, `target`, `status`, and `duration_ms`.
Secrets must not appear in audit entries.
