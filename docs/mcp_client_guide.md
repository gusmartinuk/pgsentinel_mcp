# MCP Client Guide (Codex / Other Agents)

This guide explains how to connect another project's AI agent (for example Codex) to this PgSentinel instance over MCP, and what the agent can safely do.

## 1. Prerequisites

- PgSentinel container is running and reachable (example: `http://127.0.0.1:8088`).
- Vault is configured and unlocked.
- Agent API key is enabled in `/admin/agent`.
- You have the key value in format: `pgs_ai_...`.

Quick check:

```bash
curl -sS http://127.0.0.1:8088/health
```

Expected:
- `status: ok`
- `vault: unlocked` (for tool use)

## 2. MCP Endpoint + Auth

- Endpoint: `POST /mcp/mcp`
- Auth header: `Authorization: Bearer pgs_ai_...`
- Accept header must include both:
  - `application/json`
  - `text/event-stream`

## 3. Minimal Handshake (Client-Agnostic)

1. Send `initialize`.
2. Read `mcp-session-id` response header.
3. Send next MCP calls with the same `mcp-session-id`.

Example `initialize`:

```bash
curl -i -sS \
  -H "Authorization: Bearer pgs_ai_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -X POST http://127.0.0.1:8088/mcp/mcp \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"agent","version":"1.0"}}}'
```

Then call tools (replace `MCP_SESSION_ID`):

```bash
curl -sS \
  -H "Authorization: Bearer pgs_ai_YOUR_KEY" \
  -H "mcp-session-id: MCP_SESSION_ID" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -X POST http://127.0.0.1:8088/mcp/mcp \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
```

## 4. How To Register In Another Codex Project

In the other project, add PgSentinel as an external MCP server in that project's MCP client settings.

Use:
- Base URL: `http://127.0.0.1:8088/mcp/mcp` (or host IP/domain where PgSentinel runs)
- Transport: Streamable HTTP / HTTP MCP
- Bearer token: `pgs_ai_...`

If the other project runs in a separate container/VM, `127.0.0.1` points to itself. In that case use the host IP or DNS name of the machine running PgSentinel.

## 5. What The Agent Can Do

- Docker diagnostics:
  - `health_overview`
  - `get_docker_containers`
  - `get_container_logs`
  - `search_logs`
  - `get_recent_errors`
- PostgreSQL diagnostics:
  - `get_postgres_health`
  - `list_allowed_tables`
  - `describe_table`
  - `get_table_sample`
  - `query_readonly_sql` (must be enabled on the selected target and policy-enforced)
- Cross-source diagnosis:
  - `diagnose_recent_failure`

## 6. SQL Policy Behavior

Configured from `/admin/settings`:

- `readonly_default`:
  - only read statements allowed.
- `guarded_write`:
  - write categories allowed only if their checkbox is enabled.

`query_readonly_sql` is registered, but execution requires target-level enablement plus SQL policy approval at runtime.

## 7. Safety Notes

- Keep production in `readonly_default` except short, controlled validation windows.
- Use isolated test tables for write-path validation.
- Rotate agent key after sharing with a temporary client.
- Keep allowlists tight (containers, tables, schemas).
- Review `/admin/audit` after test runs.
