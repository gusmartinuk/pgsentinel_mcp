from __future__ import annotations

import pytest

from app.core.config import PgSentinelConfig, clear_config_cache
from app.core.vault_manager import reset_vault


@pytest.fixture(autouse=True)
def _reset_globals():
    clear_config_cache()
    reset_vault()
    yield
    clear_config_cache()
    reset_vault()


@pytest.fixture
def config_data() -> dict[str, object]:
    return {
        "project": {"name": "PgSentinel MCP", "environment": "test"},
        "server": {
            "mode": "ssh",
            "host": "example.test",
            "port": 22,
            "username": "mcp-monitor",
            "ssh_private_key_path": "/secrets/id_ed25519",
            "ssh_private_key_passphrase": None,
        },
        "security": {
            "default_readonly": True,
            "allow_write_tools": False,
            "allow_raw_sql": False,
            "allow_raw_shell": False,
            "max_log_lines": 100,
            "max_query_rows": 50,
            "command_timeout_seconds": 20,
        },
        "docker": {"allowed_containers": ["postgres", "app", "nginx"]},
        "postgres": {
            "container_name": "postgres",
            "database": "appdb",
            "username": "readonly_user",
            "password": "readonly_password",
            "host_inside_container": "localhost",
            "port_inside_container": 5432,
            "allowed_schemas": ["public"],
            "allowed_tables": ["users", "failed_jobs", "migrations"],
        },
        "logs": {
            "allowed_logs": {
                "app": {"type": "docker", "container": "app", "max_lines": 80},
                "postgres": {"type": "docker", "container": "postgres", "max_lines": 80},
            }
        },
        "masking": {"patterns": ["password=", "TOKEN=", "Authorization:", "Bearer "]},
    }


@pytest.fixture
def config(config_data: dict[str, object]) -> PgSentinelConfig:
    return PgSentinelConfig.model_validate(config_data)
