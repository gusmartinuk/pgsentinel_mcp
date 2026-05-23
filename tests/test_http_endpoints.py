from app.core.config import clear_config_cache
from app.main import create_app


def _endpoint(app, path: str):
    for route in app.routes:
        if getattr(route, "path", None) == path:
            return route.endpoint
    raise AssertionError(f"route not found: {path}")


def test_http_endpoint_handlers_with_mcp_mount_disabled(monkeypatch):
    monkeypatch.setenv("PGSENTINEL_CONFIG", "config/pgsentinel.secrets.example.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()

    assert _endpoint(app, "/health")() == {
        "service": "PgSentinel MCP",
        "status": "ok",
        "mode": "readonly",
        "vault": "unconfigured",
    }
    assert _endpoint(app, "/version")() == {"service": "PgSentinel MCP", "version": "0.1.0"}
    summary = _endpoint(app, "/config/summary")()
    assert summary["readonly"] is True
    assert "readonly_password" not in str(summary)
    assert "servers" not in summary
    assert "postgres_targets" not in summary
    assert "agent_enabled" not in summary
