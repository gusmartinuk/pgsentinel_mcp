from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from app import __version__
from app.admin.routes import router as admin_router, UnauthorizedRedirect
from app.core.config import ConfigError, get_config
from app.core.vault_manager import vault_exists, vault_is_unlocked
from app.mcp.auth import MCPAuthMiddleware
from app.mcp.server import create_mcp_server


def mcp_http_enabled() -> bool:
    return os.environ.get("PGSENTINEL_MCP_HTTP_ENABLED", "false").lower() in {"1", "true", "yes", "on"}


_mcp_instance = None


def _create_mcp_app():
    global _mcp_instance
    _mcp_instance = create_mcp_server()
    if hasattr(_mcp_instance, "streamable_http_app"):
        return _mcp_instance.streamable_http_app()
    if hasattr(_mcp_instance, "sse_app"):
        return _mcp_instance.sse_app()
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    if _mcp_instance is not None and hasattr(_mcp_instance, 'session_manager'):
        try:
            sm = _mcp_instance.session_manager
            if sm is not None:
                async with sm.run():
                    yield
                return
        except Exception:
            pass
    yield


def create_app() -> FastAPI:
    application = FastAPI(
        title="PgSentinel MCP",
        version=__version__,
        description="Read-only diagnostic MCP gateway for remote Docker and PostgreSQL environments.",
        lifespan=lifespan,
    )

    application.include_router(admin_router)
    application.add_middleware(MCPAuthMiddleware)

    if mcp_http_enabled():
        mcp_app = _create_mcp_app()
        if mcp_app is not None:
            application.mount("/mcp", mcp_app)

    @application.exception_handler(UnauthorizedRedirect)
    def _unauthorized_handler(request: Request, exc: Exception) -> RedirectResponse:
        resp = RedirectResponse(url="/admin/login", status_code=302)
        resp.delete_cookie("pgsentinel_session")
        return resp

    @application.get("/health")
    def health() -> dict[str, str]:
        vault_state = "locked"
        if vault_exists():
            vault_state = "unlocked" if vault_is_unlocked() else "locked"
        else:
            vault_state = "unconfigured"
        try:
            config = get_config()
            service = config.project.name
        except ConfigError:
            service = "PgSentinel MCP"
        return {
            "service": service,
            "status": "ok",
            "mode": "readonly",
            "vault": vault_state,
        }

    @application.get("/version")
    def version() -> dict[str, str]:
        return {"service": "PgSentinel MCP", "version": __version__}

    @application.get("/config/summary")
    def config_summary() -> dict[str, object]:
        if vault_exists():
            return {
                "project": "PgSentinel MCP",
                "vault": "unlocked" if vault_is_unlocked() else "locked",
                "readonly": True,
            }
        try:
            config = get_config()
            return {
                "project": config.project.name,
                "vault": "unconfigured",
                "readonly": True,
            }
        except ConfigError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    return application


app = create_app()
