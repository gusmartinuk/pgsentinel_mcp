from __future__ import annotations

import os
from fastapi.testclient import TestClient
from app.main import create_app
from app.core.config import clear_config_cache
from app.core.vault_manager import get_vault, vault_is_locked, lock_vault, unlock_vault
from app.core.agent_key import generate_agent_token, hash_agent_token


def _create_vault_with_agent_key(monkeypatch, tmp_path) -> tuple[str, str]:
    """Returns (vault_path, agent_key_hash). Vault remains UNLOCKED after this."""
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)

    r = client.post("/admin/setup", data={"master_password": "testpass123", "confirm_password": "testpass123"})
    assert r.status_code == 302, f"setup failed: {r.status_code}"

    from app.core.vault_manager import get_vault_data
    data = get_vault_data()
    return vault_path, data.agent.key_hash


def test_mcp_rejected_without_auth(monkeypatch, tmp_path):
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)

    r = client.get("/mcp")
    assert r.status_code == 401


def test_mcp_rejected_with_bad_key(monkeypatch, tmp_path):
    vault_path, _ = _create_vault_with_agent_key(monkeypatch, tmp_path)

    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    clear_config_cache()
    app = create_app()
    client = TestClient(app, follow_redirects=False)

    r = client.get("/mcp", headers={"Authorization": "Bearer bad_token"})
    assert r.status_code == 401


def test_mcp_rejected_when_locked(monkeypatch, tmp_path):
    vault_path, key_hash = _create_vault_with_agent_key(monkeypatch, tmp_path)
    from app.core.vault_manager import get_vault_data
    data = get_vault_data()

    lock_vault()
    assert vault_is_locked()

    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    clear_config_cache()
    app = create_app()
    client = TestClient(app, follow_redirects=False)

    r = client.get("/mcp", headers={"Authorization": "Bearer pgs_ai_some_random_test_token_that_looks_valid"})
    assert r.status_code == 503


def test_health_endpoint_unaffected(monkeypatch, tmp_path):
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)

    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["vault"] == "unconfigured"


def test_admin_routes_unaffected_by_mcp_auth(monkeypatch, tmp_path):
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)

    r = client.get("/admin/setup")
    assert r.status_code == 200
