from __future__ import annotations

import yaml
import pytest

from app.core.config import ConfigError, clear_config_cache, load_config


def test_load_config_masks_summary_secrets(tmp_path, config_data):
    path = tmp_path / "pgsentinel.secrets.yml"
    path.write_text(yaml.safe_dump(config_data), encoding="utf-8")

    config = load_config(path)
    summary = config.summary()

    assert summary["readonly"] is True
    assert summary["server_mode"] == "ssh"
    assert summary["write_tools_enabled"] is False
    assert "readonly_password" not in str(summary)
    assert "/secrets/id_ed25519" not in str(summary)


def test_config_rejects_write_mode(tmp_path, config_data):
    config_data["security"]["allow_write_tools"] = True
    path = tmp_path / "pgsentinel.secrets.yml"
    path.write_text(yaml.safe_dump(config_data), encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(path)


def test_local_mode_does_not_require_ssh_fields(tmp_path, config_data):
    config_data["server"] = {"mode": "local"}
    path = tmp_path / "pgsentinel.local.yml"
    path.write_text(yaml.safe_dump(config_data), encoding="utf-8")

    config = load_config(path)

    assert config.server.mode == "local"
    assert config.summary()["server_mode"] == "local"


def test_legacy_yaml_config_disabled_in_production(monkeypatch, tmp_path, config_data):
    path = tmp_path / "pgsentinel.secrets.yml"
    path.write_text(yaml.safe_dump(config_data), encoding="utf-8")
    monkeypatch.setenv("PGSENTINEL_ENV", "production")
    monkeypatch.delenv("PGSENTINEL_ALLOW_LEGACY_CONFIG", raising=False)
    clear_config_cache()

    with pytest.raises(ConfigError):
        load_config(path)


def test_legacy_yaml_config_can_be_explicitly_enabled_in_production(monkeypatch, tmp_path, config_data):
    path = tmp_path / "pgsentinel.secrets.yml"
    path.write_text(yaml.safe_dump(config_data), encoding="utf-8")
    monkeypatch.setenv("PGSENTINEL_ENV", "production")
    monkeypatch.setenv("PGSENTINEL_ALLOW_LEGACY_CONFIG", "true")
    clear_config_cache()

    assert load_config(path).project.name == "PgSentinel MCP"
