from __future__ import annotations

import json
import time

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.agent_key import verify_agent_token, is_valid_agent_token_format
from app.core.audit import write_audit_event
from app.core.vault_manager import vault_exists, vault_is_locked, vault_is_unlocked, get_vault_data


class MCPAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/mcp"):
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            self._audit("mcp_auth_failed", reason="missing_bearer")
            return Response(
                content=json.dumps({"error": "Agent API Key required. Use: Authorization: Bearer pgs_ai_YOUR_KEY"}),
                status_code=401,
                media_type="application/json",
            )

        token = auth_header[7:]
        if not is_valid_agent_token_format(token):
            self._audit("mcp_auth_failed", reason="invalid_format")
            return Response(
                content=json.dumps({"error": "Invalid agent key format."}),
                status_code=401,
                media_type="application/json",
            )

        if not vault_exists():
            self._audit("mcp_auth_failed", reason="vault_unconfigured")
            return Response(
                content=json.dumps({"error": "Vault not configured."}),
                status_code=503,
                media_type="application/json",
            )

        if vault_is_locked():
            self._audit("mcp_auth_failed", reason="vault_locked")
            return Response(
                content=json.dumps({"error": "Vault is locked. Unlock via the admin panel first."}),
                status_code=503,
                media_type="application/json",
            )

        try:
            data = get_vault_data()
        except Exception:
            self._audit("mcp_auth_failed", reason="vault_error")
            return Response(
                content=json.dumps({"error": "Vault error."}),
                status_code=503,
                media_type="application/json",
            )

        if not data.agent.enabled:
            self._audit("mcp_auth_failed", reason="agent_disabled")
            return Response(
                content=json.dumps({"error": "Agent access is disabled."}),
                status_code=403,
                media_type="application/json",
            )

        if not data.agent.key_hash:
            self._audit("mcp_auth_failed", reason="no_key_configured")
            return Response(
                content=json.dumps({"error": "No agent key configured."}),
                status_code=403,
                media_type="application/json",
            )

        if not verify_agent_token(token, data.agent.key_hash):
            self._audit("mcp_auth_failed", reason="invalid_key")
            return Response(
                content=json.dumps({"error": "Invalid agent key."}),
                status_code=401,
                media_type="application/json",
            )

        self._audit("mcp_auth_success")
        return await call_next(request)

    @staticmethod
    def _audit(event: str, **fields: str) -> None:
        write_audit_event({"actor_type": "agent", "event": event, **fields})
