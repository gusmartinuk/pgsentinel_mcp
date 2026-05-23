from __future__ import annotations

import os
import json
from app.core.vault import (
    Vault, VaultData, ServerDef, PostgresTargetDef, MonitoringTargetDef,
    VaultError, AgentConfig, SecuritySettings,
)


def _make_vault_path(tmp_path, name="test-vault.enc"):
    return str(tmp_path / name)


def test_vault_create_and_unlock(tmp_path):
    path = _make_vault_path(tmp_path)
    v = Vault(path)
    assert not v.exists()
    assert v.is_locked

    v.create("secure123", agent_enabled=True)
    assert v.exists()
    assert v.is_unlocked

    v.lock()
    assert v.is_locked

    v.unlock("secure123")
    assert v.is_unlocked


def test_vault_wrong_password(tmp_path):
    path = _make_vault_path(tmp_path)
    v = Vault(path)
    v.create("correct123")

    v.lock()
    try:
        v.unlock("wrong123")
        assert False, "expected VaultError"
    except VaultError:
        pass


def test_vault_data_persistence(tmp_path):
    path = _make_vault_path(tmp_path)
    v = Vault(path)
    v.create("master123")
    data = v.data
    data.servers.append(ServerDef(id="srv-1", name="test", host="example.com"))
    data.postgres_targets.append(PostgresTargetDef(id="pg-1", name="main-db",
                                                    database_name="appdb",
                                                    allowed_tables=["users"]))
    v.save()

    v.lock()
    v.unlock("master123")
    data = v.data
    assert len(data.servers) == 1
    assert data.servers[0].name == "test"
    assert data.servers[0].host == "example.com"
    assert data.postgres_targets[0].allowed_tables == ["users"]


def test_vault_data_not_exposed(tmp_path):
    path = _make_vault_path(tmp_path)
    v = Vault(path)
    v.create("master123")
    assert v.is_unlocked

    v.lock()
    try:
        _ = v.data
        assert False, "should raise"
    except VaultError:
        pass


def test_server_default_logic(tmp_path):
    path = _make_vault_path(tmp_path)
    v = Vault(path)
    v.create("pwd")

    data = v.data
    data.servers.append(ServerDef(id="a", name="Only", enabled=True))
    assert data.get_default_server() is not None
    assert data.get_default_server().id == "a"

    data.servers.append(ServerDef(id="b", name="Prod", environment="production", enabled=True))
    assert data.get_default_server() is None  # ambiguous with 2 servers

    data.servers[0].enabled = False
    assert data.get_default_server().id == "b"  # only "b" enabled now


def test_postgres_default_logic(tmp_path):
    path = _make_vault_path(tmp_path)
    v = Vault(path)
    v.create("pwd")

    data = v.data
    data.postgres_targets.append(PostgresTargetDef(id="a", name="Only", enabled=True))
    assert data.get_default_postgres_target().id == "a"

    data.postgres_targets.append(PostgresTargetDef(id="b", name="Second", enabled=True))
    assert data.get_default_postgres_target() is None  # ambiguous


def test_secret_fields_not_in_serialized(tmp_path):
    path = _make_vault_path(tmp_path)
    v = Vault(path)
    v.create("master123")
    data = v.data
    data.servers.append(ServerDef(id="srv", name="s", ssh_private_key="SECRET_KEY_DATA"))
    v.save()

    raw = open(path).read()
    assert "SECRET_KEY_DATA" not in raw  # encrypted


def test_save_without_password_uses_derived(tmp_path):
    path = _make_vault_path(tmp_path)
    v = Vault(path)
    v.create("master123")
    data = v.data
    data.servers.append(ServerDef(id="srv", name="s"))
    v.save()  # uses derived key
    assert v.exists()


def test_agent_config(tmp_path):
    path = _make_vault_path(tmp_path)
    v = Vault(path)
    v.create("master123", agent_enabled=True)
    assert v.data.agent.enabled
    assert v.data.agent.key_hash

    v.data.agent.enabled = False
    v.save()
    v.lock()
    v.unlock("master123")
    assert not v.data.agent.enabled


def test_monitoring_target_model(tmp_path):
    path = _make_vault_path(tmp_path)
    v = Vault(path)
    v.create("master123")
    data = v.data
    data.monitoring_targets.append(
        MonitoringTargetDef(id="m1", name="Health API", base_url="https://example.com/health",
                           api_token="secret-token", allowed_operations=["health", "status"])
    )
    v.save()
    v.lock()
    v.unlock("master123")
    m = v.data.monitoring_targets[0]
    assert m.base_url == "https://example.com/health"
    assert m.allowed_operations == ["health", "status"]


def test_vault_path_property(tmp_path):
    path = _make_vault_path(tmp_path)
    v = Vault(path)
    assert v.path == path


def test_save_creates_backup(tmp_path):
    path = _make_vault_path(tmp_path)
    v = Vault(path)
    v.create("master123")
    v.data.servers.append(ServerDef(id="srv-1", name="one"))
    v.save()
    v.data.servers.append(ServerDef(id="srv-2", name="two"))
    v.save()
    backup_path = path + ".bak"
    assert os.path.exists(backup_path)
