# MCP Client Guide

This guide explains how to connect an AI agent or MCP client to a running PgSentinel instance.

PgSentinel uses the **Streamable HTTP** MCP transport. Any client that supports this transport can connect.

---

## Prerequisites

- PgSentinel is running and reachable (e.g. `http://127.0.0.1:8088`)
- Vault is configured and unlocked (first-run setup completed)
- An Agent API Key has been generated from `/admin/agent`
- You have the key in the format `pgs_ai_...`

Quick health check:

```bash
curl -sS http://127.0.0.1:8088/health
```

Expected response includes `"status": "ok"` and `"vault": "unlocked"`. If the vault shows `"locked"`, log in at `/admin/login` to unlock it before agent calls will work.

---

## Connection Details

| Setting | Value |
|---------|-------|
| Endpoint | `http://127.0.0.1:8088/mcp/mcp` |
| Transport | Streamable HTTP (MCP 2025-03-26) |
| Auth | `Authorization: Bearer pgs_ai_...` |
| Accept | `application/json, text/event-stream` |

---

## Client Configuration Examples

### Claude Code

Add to your project's `.mcp.json` (create it in the project root if it doesn't exist):

```json
{
  "mcpServers": {
    "pgsentinel": {
      "type": "http",
      "url": "http://127.0.0.1:8088/mcp/mcp",
      "headers": {
        "Authorization": "Bearer pgs_ai_YOUR_KEY"
      }
    }
  }
}
```

Restart Claude Code after saving. The PgSentinel tools will appear in the tool list.

### Cursor

In Cursor settings, add a new MCP server under **Tools & Integrations → MCP Servers**:

- **Name**: `pgsentinel`
- **Type**: HTTP / Streamable HTTP
- **URL**: `http://127.0.0.1:8088/mcp/mcp`
- **Authorization**: `Bearer pgs_ai_YOUR_KEY`

### Codex (OpenAI)

In your Codex project's MCP client configuration:

```json
{
  "name": "pgsentinel",
  "transport": "http",
  "url": "http://127.0.0.1:8088/mcp/mcp",
  "auth": {
    "type": "bearer",
    "token": "pgs_ai_YOUR_KEY"
  }
}
```

### Generic / Manual (curl)

If your client is not listed above, follow the standard MCP session handshake:

```bash
# Step 1: initialize — note the mcp-session-id in the response headers
curl -i -sS \
  -H "Authorization: Bearer pgs_ai_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -X POST http://127.0.0.1:8088/mcp/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"my-agent","version":"1.0"}}}'

# Step 2: use the session ID from the response header on all subsequent calls
curl -sS \
  -H "Authorization: Bearer pgs_ai_YOUR_KEY" \
  -H "mcp-session-id: SESSION_ID_FROM_STEP_1" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -X POST http://127.0.0.1:8088/mcp/mcp \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

---

## Remote Access

If PgSentinel runs on a different machine than your agent, replace `127.0.0.1` with the host's IP or DNS name.

```json
"url": "http://192.168.1.10:8088/mcp/mcp"
```

PgSentinel binds to `127.0.0.1` by default. To allow remote connections, either:
- Expose it through a reverse proxy with HTTPS and authentication, or
- Access it over a VPN or SSH tunnel.

Do not expose PgSentinel directly to the public internet without a protective layer in front.

---

## Available Tools

### Docker & infrastructure

| Tool | Description |
|------|-------------|
| `health_overview` | Overall health status across configured targets |
| `get_docker_containers` | List containers and their state |
| `get_deployment_info` | Current image tags and deploy timestamps |
| `get_container_image_info` | Image details for a specific container |
| `get_container_status` | Running/stopped/unhealthy status |
| `get_container_restart_count` | Restart count for a container |
| `get_container_logs` | Raw log lines from a container |
| `search_logs` | Full-text search across logs |
| `get_recent_errors` | Recent error-level log lines |
| `get_errors_grouped` | Error lines grouped by pattern |
| `get_logs_since_deploy` | Log lines since the last deploy event |

### PostgreSQL

| Tool | Description |
|------|-------------|
| `get_postgres_health` | Connection check and basic DB stats |
| `list_allowed_tables` | Tables available to the agent |
| `describe_table` | Column names and types for a table |
| `get_table_sample` | Sample rows (masked) from an allowed table |
| `get_recent_migrations` | Latest migration history entries |
| `get_failed_jobs` | Failed background job rows |
| `get_table_row_count` | Row count for an allowed table |
| `query_readonly_sql` | Policy-guarded SQL (must be enabled per target) |

### Diagnosis

| Tool | Description |
|------|-------------|
| `diagnose_recent_failure` | Cross-source failure diagnosis (logs + DB) |
| `diagnose_deployment_issue` | Deployment-specific failure signals |
| `diagnose_worker_issue` | Background worker failure signals |
| `diagnose_database_issue` | Database connectivity and health signals |
| `diagnose_http_5xx_issue` | HTTP 500-class error pattern analysis |

### Source inspection

| Tool | Description |
|------|-------------|
| `check_source_contains` | Check if an allowlisted source file contains a pattern |
| `check_python_symbols_in_module` | List symbols in an allowlisted Python module |

---

## Specifying Targets

Every tool call **must** include a `profile_code`: the 8-character code of the
definition you want to act on (created in **Admin → Definitions**). The code
selects that definition's vault, auto-unlocks it, and resolves its single VPS
and optional PostgreSQL target. There is no need to name a `server` or
`postgres_target` separately — each definition holds exactly one of each.

Calls without a valid `profile_code` are rejected, and error messages never
reveal other definitions' names.

**Docker/log tools:**
```json
{
  "name": "get_recent_errors",
  "arguments": {
    "profile_code": "abcd1234",
    "log_name": "app",
    "minutes": 30
  }
}
```

**PostgreSQL tools:**
```json
{
  "name": "get_table_sample",
  "arguments": {
    "profile_code": "abcd1234",
    "table": "failed_jobs",
    "limit": 10
  }
}
```

**Diagnosis tools:**
```json
{
  "name": "diagnose_recent_failure",
  "arguments": {
    "profile_code": "abcd1234",
    "minutes": 60
  }
}
```

---

## SQL Policy

`query_readonly_sql` is controlled by two independent gates:

1. **Target-level**: must be explicitly enabled on the definition's PostgreSQL target in **Admin → Definitions → Edit**.
2. **Policy mode** (configured in `/admin/settings`):
   - `readonly_default` — only `SELECT`, `WITH`, `EXPLAIN`, `SHOW`, `VALUES` are permitted.
   - `guarded_write` — write categories (`INSERT`, `UPDATE`, `DELETE`, etc.) are allowed only if their individual toggle is enabled.

Keep production targets in `readonly_default`. Only enable `guarded_write` temporarily for controlled validation on isolated tables.

---

## Troubleshooting

**`503 Vault is locked`**
The vault needs to be unlocked by the operator. Log in at `/admin/login` with the master password.

**`401 Unauthorized` or `Invalid agent key format`**
The `Authorization` header is missing, malformed, or the key has been rotated/disabled. Generate a new key from `/admin/agent`.

**`Server '<host>' not found in known_hosts`**
The SSH host key for the target server has not been trusted yet. This happens after a container restart if `PGSENTINEL_SSH_KNOWN_HOSTS` is not configured to a persistent path. See [deployment.md](deployment.md#ssh-known-hosts-persistence-after-restart).

**`target not found` or `profile_code not found`**
The `profile_code` value does not match any definition in the vault, or the vault for that code could not be unlocked. Check that the definition exists in **Admin → Definitions** and that the master password is correct.

**Tool returns empty or no output**
The requested container or table may not be in the allowlist for that target. Check `allowed_containers` and `allowed_tables` in the target's vault configuration.

---

## Safety Notes

- Keep `readonly_default` SQL policy on production targets at all times.
- Keep allowlists narrow — only list the containers and tables the agent actually needs.
- Rotate the agent key if it was shared with a temporary session or a third party.
- Review `/admin/audit` after any diagnostic session to confirm no unexpected calls were made.
