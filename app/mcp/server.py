from __future__ import annotations

from typing import Any

from app.core.config import ConfigError, get_config
from app.mcp.tools import register_tools


def create_mcp_server() -> Any:
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("PgSentinel MCP")
    try:
        config = get_config()
    except ConfigError:
        config = None
    register_tools(mcp, config=config)
    return mcp


def create_mcp_asgi_app() -> tuple[Any, Any] | None:
    mcp = create_mcp_server()
    if hasattr(mcp, "streamable_http_app"):
        app = mcp.streamable_http_app()
        return app, mcp.session_manager
    if hasattr(mcp, "sse_app"):
        app = mcp.sse_app()
        return app, None
    return None
