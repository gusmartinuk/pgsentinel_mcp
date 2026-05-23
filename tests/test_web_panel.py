from __future__ import annotations

import os
from fastapi.testclient import TestClient
from app.main import create_app
from app.core.config import clear_config_cache
from app.core.vault_manager import lock_vault, vault_is_locked
from app.core.vault import Vault


def _setup_vault(client):
    r = client.post("/admin/setup", data={"master_password": "testpass123", "confirm_password": "testpass123"})
    assert r.status_code == 302
    assert r.headers["location"] == "/admin/agent"
    return {k: v for k, v in r.cookies.items()}


def _login(client):
    r = client.post("/admin/login", data={"master_password": "testpass123"})
    assert r.status_code == 302
    return {k: v for k, v in r.cookies.items()}


def test_first_run_setup_flow(monkeypatch, tmp_path):
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)

    r = client.get("/admin/setup")
    assert r.status_code == 200
    assert "Master Password" in r.text

    cookies = _setup_vault(client)
    assert "pgs_show_key" not in client.cookies
    r = client.get("/admin/dashboard", cookies=cookies)
    assert r.status_code == 200
    assert "Unlocked" in r.text


def test_login_flow(monkeypatch, tmp_path):
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)

    _setup_vault(client)
    client.post("/admin/lock", cookies=client.cookies)

    r = client.get("/admin/login")
    assert r.status_code == 200

    cookies = _login(client)
    r = client.get("/admin/dashboard", cookies=cookies)
    assert r.status_code == 200
    assert "Unlocked" in r.text


def test_dashboard_requires_session(monkeypatch, tmp_path):
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)

    r = client.get("/admin/dashboard")
    assert r.status_code == 302


def test_add_server(monkeypatch, tmp_path):
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)

    cookies = _setup_vault(client)

    r = client.post("/admin/servers/new", cookies=cookies, data={
        "name": "Test VPS",
        "environment": "staging",
        "connection_mode": "ssh",
        "host": "192.168.1.100",
        "ssh_port": "22",
        "ssh_username": "monitor",
        "ssh_private_key": "fake-key",
        "allowed_containers_text": "postgres,app",
        "allowed_log_sources_text": "app,postgres",
        "enabled": "true",
    })
    assert r.status_code == 302

    r = client.get("/admin/servers", cookies=cookies)
    assert "Test VPS" in r.text


def test_add_postgres_target(monkeypatch, tmp_path):
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)

    cookies = _setup_vault(client)

    r = client.post("/admin/postgres/new", cookies=cookies, data={
        "name": "Main DB",
        "connection_mode": "docker_exec_psql_over_ssh",
        "host": "localhost",
        "port": "5432",
        "container_name": "postgres",
        "database_name": "appdb",
        "readonly_username": "reader",
        "readonly_password": "secret",
        "allowed_schemas_text": "public",
        "allowed_tables_text": "users,orders",
        "max_rows": "50",
        "enabled": "true",
    })
    assert r.status_code == 302

    r = client.get("/admin/postgres", cookies=cookies)
    assert "Main DB" in r.text


def test_secret_not_prefilled_on_edit(monkeypatch, tmp_path):
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)
    cookies = _setup_vault(client)

    client.post("/admin/postgres/new", cookies=cookies, data={
        "name": "Target", "container_name": "pg", "database_name": "db",
        "readonly_username": "u", "readonly_password": "secret123",
        "allowed_tables_text": "t1", "enabled": "true",
    })
    r = client.get("/admin/postgres", cookies=cookies)
    html = r.text

    assert "secret123" not in html


def test_agent_key_rotation(monkeypatch, tmp_path):
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)
    cookies = _setup_vault(client)

    r = client.get("/admin/agent", cookies=cookies)
    assert r.status_code == 200
    assert "Agent Access" in r.text or "Agent" in r.text

    r = client.post("/admin/agent/rotate", cookies=cookies)
    assert r.status_code == 302
    assert "pgs_show_key" not in client.cookies

    r = client.get("/admin/agent", cookies=cookies)
    assert "New Agent API Key" in r.text

    r = client.get("/admin/agent", cookies=cookies)
    assert "New Agent API Key" not in r.text


def test_lock_unlock(monkeypatch, tmp_path):
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)
    cookies = _setup_vault(client)

    r = client.post("/admin/lock", cookies=cookies)
    assert r.status_code == 302

    r = client.get("/admin/dashboard", cookies=cookies)
    assert r.status_code == 302

    cookies = _login(client)
    r = client.get("/admin/dashboard", cookies=cookies)
    assert r.status_code == 200


def test_wrong_password_rejected(monkeypatch, tmp_path):
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)
    _setup_vault(client)
    client.post("/admin/lock", cookies=client.cookies)

    r = client.post("/admin/login", data={"master_password": "wrongpassword"})
    assert r.status_code == 401
    assert "invalid" in r.text.lower()


def test_admin_pages_have_no_cache_headers(monkeypatch, tmp_path):
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)
    cookies = _setup_vault(client)

    r = client.get("/admin/dashboard", cookies=cookies)
    assert r.headers["cache-control"] == "no-store, no-cache, must-revalidate, max-age=0"
    assert r.headers["x-frame-options"] == "DENY"


def test_login_can_select_existing_vault_when_active_missing(monkeypatch, tmp_path):
    vault_dir = tmp_path / "vaults"
    vault_dir.mkdir(parents=True, exist_ok=True)
    Vault(str(vault_dir / "default.vault.enc")).create("defaultpass123")
    Vault(str(vault_dir / "staging.vault.enc")).create("stagingpass123")
    (vault_dir / ".active_vault").write_text("missing\n", encoding="utf-8")

    monkeypatch.setenv("PGSENTINEL_VAULT_DIR", str(vault_dir))
    monkeypatch.setenv("PGSENTINEL_ACTIVE_VAULT_FILE", str(vault_dir / ".active_vault"))
    monkeypatch.setenv("PGSENTINEL_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)

    r = client.get("/admin/login")
    assert r.status_code == 200
    assert "Use Selected Vault" in r.text

    r = client.post("/admin/login/select_vault", data={"name": "default"})
    assert r.status_code == 302
    assert r.headers["location"] == "/admin/login"

    r = client.post("/admin/login", data={"master_password": "defaultpass123"})
    assert r.status_code == 302
    assert r.headers["location"] == "/admin/dashboard"


def test_settings_sql_policy_saved(monkeypatch, tmp_path):
    vault_path = str(tmp_path / "vault.enc")
    monkeypatch.setenv("PGSENTINEL_VAULT", vault_path)
    monkeypatch.setenv("PGSENTINEL_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()

    app = create_app()
    client = TestClient(app, follow_redirects=False)
    cookies = _setup_vault(client)

    r = client.post("/admin/settings", cookies=cookies, data={
        "auto_lock_minutes": "35",
        "max_log_lines": "200",
        "max_query_rows": "120",
        "command_timeout_seconds": "25",
        "sql_policy_mode": "guarded_write",
        "sql_hard_max_query_rows": "1500",
        "sql_allow_update": "true",
        "masking_patterns_text": "token=\npassword=",
    })
    assert r.status_code == 302

    r = client.get("/admin/settings", cookies=cookies)
    assert r.status_code == 200
    assert "guarded_write" in r.text
    assert "sql_allow_update" in r.text
