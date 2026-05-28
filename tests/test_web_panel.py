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


def _setup_multivault(monkeypatch, tmp_path):
    vault_dir = tmp_path / "vaults"
    monkeypatch.setenv("PGSENTINEL_VAULT_DIR", str(vault_dir))
    monkeypatch.setenv("PGSENTINEL_ACTIVE_VAULT_FILE", str(vault_dir / ".active_vault"))
    monkeypatch.setenv("PGSENTINEL_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("PGSENTINEL_CONFIG", "/nonexistent_config.yml")
    monkeypatch.setenv("PGSENTINEL_MCP_HTTP_ENABLED", "false")
    clear_config_cache()
    app = create_app()
    client = TestClient(app, follow_redirects=False)
    r = client.post("/admin/setup", data={"master_password": "testpass123", "confirm_password": "testpass123"})
    assert r.status_code == 302
    return client, {k: v for k, v in r.cookies.items()}


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


def test_create_definition_shows_keys_and_persists(monkeypatch, tmp_path):
    client, cookies = _setup_multivault(monkeypatch, tmp_path)

    # The shared agent key is shown exactly once right after setup.
    r = client.get("/admin/agent", cookies=cookies)
    assert r.status_code == 200
    assert "pgs_ai_" in r.text

    r = client.post("/admin/definitions/new", cookies=cookies, data={
        "code": "alpha123",
        "docker_mode": "ssh",
        "host": "192.168.1.50",
        "ssh_port": "22",
        "ssh_username": "monitor",
        "ssh_private_key": "fake-ssh-key",
        "container_list": "app,postgres",
        "postgres_enabled": "true",
        "postgres_mode": "postgres_direct_tcp",
        "pg_host": "127.0.0.1",
        "pg_port": "5432",
        "pg_database": "appdb",
        "pg_username": "reader",
        "pg_password": "secret123",
        "access_level": "sql",
    })
    assert r.status_code == 302
    assert r.headers["location"] == "/admin/agent"
    new_cookies = {k: v for k, v in r.cookies.items()}

    # A new definition gets its own recovery key shown once (agent key is shared).
    r = client.get("/admin/agent", cookies=new_cookies)
    assert r.status_code == 200
    assert "Recovery Key" in r.text

    # The definition is listed and editable; the password is never reflected back.
    r = client.get("/admin/definitions", cookies=new_cookies)
    assert "alpha123" in r.text
    r = client.get("/admin/definitions/alpha123/edit", cookies=new_cookies)
    assert r.status_code == 200
    assert "192.168.1.50" in r.text
    assert "secret123" not in r.text


def _create_definition(client, cookies, code):
    r = client.post("/admin/definitions/new", cookies=cookies, data={
        "code": code, "docker_mode": "local", "access_level": "readonly"})
    assert r.status_code == 302
    return {k: v for k, v in r.cookies.items()}


def _agent_hashes(tmp_path, names):
    from app.core.vault import Vault
    vault_dir = tmp_path / "vaults"
    out = {}
    for name in names:
        v = Vault(str(vault_dir / f"{name}.vault.enc"))
        v.unlock("testpass123")
        out[name] = v.data.agent.key_hash
    return out


def test_definitions_share_one_agent_key(monkeypatch, tmp_path):
    client, cookies = _setup_multivault(monkeypatch, tmp_path)
    cookies = _create_definition(client, cookies, "alpha123")
    cookies = _create_definition(client, cookies, "bravo456")

    hashes = _agent_hashes(tmp_path, ["default1", "alpha123", "bravo456"])
    assert all(hashes.values())            # every definition has a key
    assert len(set(hashes.values())) == 1  # and they all share the same one


def test_rotate_propagates_to_all_definitions(monkeypatch, tmp_path):
    client, cookies = _setup_multivault(monkeypatch, tmp_path)
    cookies = _create_definition(client, cookies, "alpha123")
    cookies = _create_definition(client, cookies, "bravo456")

    names = ["default1", "alpha123", "bravo456"]
    before = _agent_hashes(tmp_path, names)

    r = client.post("/admin/agent/rotate", cookies=cookies, data={"key_never_expires": "true"})
    assert r.status_code == 302

    after = _agent_hashes(tmp_path, names)
    assert len(set(after.values())) == 1               # still shared
    assert all(after[n] != before[n] for n in names)   # and rotated everywhere


def test_definition_code_must_be_8_chars(monkeypatch, tmp_path):
    client, cookies = _setup_multivault(monkeypatch, tmp_path)
    r = client.post("/admin/definitions/new", cookies=cookies, data={
        "code": "short", "docker_mode": "local", "access_level": "readonly",
    })
    assert r.status_code == 400
    assert "8" in r.text


def test_definition_test_endpoint_skips_without_input(monkeypatch, tmp_path):
    client, cookies = _setup_multivault(monkeypatch, tmp_path)

    r = client.post("/admin/definitions/test", cookies=cookies,
                    data={"target": "postgres", "postgres_mode": "postgres_direct_tcp"})
    assert r.status_code == 200
    assert "username and password" in r.text.lower()

    r = client.post("/admin/definitions/test", cookies=cookies,
                    data={"target": "vps", "docker_mode": "ssh"})
    assert r.status_code == 200
    assert "ssh host and username" in r.text.lower()


def test_audit_write_never_crashes(monkeypatch, tmp_path):
    # Point the audit log under a path whose parent is a file, forcing an OSError
    # on write. This must be swallowed so it can never turn a request into a 500.
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    monkeypatch.setenv("PGSENTINEL_AUDIT_LOG", str(blocker / "audit.jsonl"))
    from app.core.audit import write_audit_event
    write_audit_event({"actor_type": "admin", "event": "unwritable_path_test"})


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
    Vault(str(vault_dir / "default1.vault.enc")).create("defaultpass123")
    Vault(str(vault_dir / "staging1.vault.enc")).create("stagingpass123")
    (vault_dir / ".active_vault").write_text("zzzzzzzz\n", encoding="utf-8")

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

    r = client.post("/admin/login/select_vault", data={"name": "default1"})
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
