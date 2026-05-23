from __future__ import annotations

import pytest

from app.core.vault import PostgresTargetDef, ServerDef
from app.tools.safe_diagnostics import (
    check_python_symbols_in_module,
    check_source_contains,
    get_table_row_count,
)


def test_check_source_contains_allowlisted_path():
    result = check_source_contains("README.md", "PgSentinel")
    assert result["path"] == "README.md"
    assert isinstance(result["found"], bool)


def test_check_source_contains_blocks_non_allowlisted_path():
    with pytest.raises(ValueError):
        check_source_contains("/etc/passwd", "root")


def test_check_python_symbols_in_module_blocks_non_allowlisted_module():
    with pytest.raises(ValueError):
        check_python_symbols_in_module("os", symbols=["system"])


def test_get_table_row_count_blocks_non_allowlisted_table():
    pg = PostgresTargetDef(
        id="pg1",
        name="PG",
        container_name="postgres",
        database_name="app",
        readonly_username="u",
        readonly_password="p",
        allowed_tables=["users"],
    )
    with pytest.raises(ValueError):
        get_table_row_count("orders", postgres_target=pg)


def test_empty_postgres_allowlist_blocks_table_access():
    pg = PostgresTargetDef(
        id="pg1",
        name="PG",
        container_name="postgres",
        database_name="app",
        readonly_username="u",
        readonly_password="p",
        allowed_tables=[],
    )
    with pytest.raises(ValueError):
        get_table_row_count("users", postgres_target=pg)


def test_server_container_allowlist_enforced():
    target = ServerDef(id="s1", name="S1", allowed_containers=["app"])
    from app.tools.safe_diagnostics import get_container_status
    with pytest.raises(ValueError):
        get_container_status("postgres", target=target)


def test_empty_container_allowlist_blocks_container_access():
    target = ServerDef(id="s1", name="S1", allowed_containers=[])
    from app.tools.safe_diagnostics import get_container_status
    with pytest.raises(ValueError):
        get_container_status("app", target=target)
