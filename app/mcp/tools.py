from __future__ import annotations

from typing import Any

from app.core.audit import audit_tool_call
from app.core.vault_manager import ensure_profile_active_and_unlocked, get_vault_data, vault_is_unlocked
from app.tools.diagnostics import diagnose_recent_failure as diagnose_recent_failure_impl
from app.tools.docker import get_docker_containers as get_docker_containers_impl
from app.tools.health import health_overview as health_overview_impl
from app.tools.logs import (
    get_container_logs as get_container_logs_impl,
    get_recent_errors as get_recent_errors_impl,
    search_logs as search_logs_impl,
)
from app.tools.postgres import (
    describe_table as describe_table_impl,
    get_postgres_health as get_postgres_health_impl,
    get_table_sample as get_table_sample_impl,
    list_allowed_tables as list_allowed_tables_impl,
    query_readonly_sql as query_readonly_sql_impl,
)
from app.tools.safe_diagnostics import (
    check_python_symbols_in_module as check_python_symbols_in_module_impl,
    check_source_contains as check_source_contains_impl,
    diagnose_database_issue as diagnose_database_issue_impl,
    diagnose_deployment_issue as diagnose_deployment_issue_impl,
    diagnose_http_5xx_issue as diagnose_http_5xx_issue_impl,
    diagnose_worker_issue as diagnose_worker_issue_impl,
    get_container_image_info as get_container_image_info_impl,
    get_container_restart_count as get_container_restart_count_impl,
    get_container_status as get_container_status_impl,
    get_deployment_info as get_deployment_info_impl,
    get_errors_grouped as get_errors_grouped_impl,
    get_failed_jobs as get_failed_jobs_impl,
    get_logs_since_deploy as get_logs_since_deploy_impl,
    get_recent_migrations as get_recent_migrations_impl,
    get_table_row_count as get_table_row_count_impl,
)


def _require_profile_code(profile_code: str | None) -> None:
    if not profile_code:
        raise ValueError("profile_code is required")
    ensure_profile_active_and_unlocked(str(profile_code).strip().lower())


def _get_vault_or_raise() -> Any:
    if not vault_is_unlocked():
        raise PermissionError("vault is locked")
    return get_vault_data()


def register_tools(mcp: Any, config: Any | None = None) -> list[str]:
    registered: list[str] = []

    def tool(func):
        decorated = mcp.tool()(func)
        registered.append(func.__name__)
        return decorated

    @tool
    @audit_tool_call("health_overview")
    def health_overview(server: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        target = None
        if server:
            target = vault.get_server(server)
            if target is None:
                return {"error": "server not found"}
        elif not vault.servers:
            return {"error": "no servers configured"}
        else:
            default = vault.get_default_server()
            if default:
                target = default
        return health_overview_impl(target=target)

    @tool
    @audit_tool_call("get_docker_containers")
    def get_docker_containers(server: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        target = _resolve_server(vault, server)
        return get_docker_containers_impl(target=target)

    @tool
    @audit_tool_call("get_container_logs")
    def get_container_logs(container: str, lines: int = 100, level_filter: str | None = None, server: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        target = _resolve_server(vault, server)
        return get_container_logs_impl(container=container, lines=lines, level_filter=level_filter, target=target)

    @tool
    @audit_tool_call("search_logs")
    def search_logs(log_name: str, keyword: str, lines: int = 200, server: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        target = _resolve_server(vault, server)
        return search_logs_impl(log_name=log_name, keyword=keyword, lines=lines, target=target)

    @tool
    @audit_tool_call("get_recent_errors")
    def get_recent_errors(log_name: str, minutes: int = 60, limit: int = 100, server: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        target = _resolve_server(vault, server)
        return get_recent_errors_impl(log_name=log_name, minutes=minutes, limit=limit, target=target)

    @tool
    @audit_tool_call("get_postgres_health")
    def get_postgres_health(postgres_target: str | None = None, server: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        pg = _resolve_postgres_target(vault, postgres_target, server)
        return get_postgres_health_impl(target=pg)

    @tool
    @audit_tool_call("list_allowed_tables")
    def list_allowed_tables(postgres_target: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        pg = _resolve_postgres_target(vault, postgres_target)
        return list_allowed_tables_impl(target=pg)

    @tool
    @audit_tool_call("describe_table")
    def describe_table(table: str, postgres_target: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        pg = _resolve_postgres_target(vault, postgres_target)
        return describe_table_impl(table=table, target=pg)

    @tool
    @audit_tool_call("get_table_sample")
    def get_table_sample(table: str, limit: int = 20, postgres_target: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        pg = _resolve_postgres_target(vault, postgres_target)
        return get_table_sample_impl(table=table, limit=limit, target=pg)

    @tool
    @audit_tool_call("diagnose_recent_failure")
    def diagnose_recent_failure(minutes: int = 60, server: str | None = None, postgres_target: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        srv = _resolve_server(vault, server) if server else None
        pg = _resolve_postgres_target(vault, postgres_target) if postgres_target else None
        return diagnose_recent_failure_impl(minutes=minutes, target=srv, pg_target=pg)

    @tool
    @audit_tool_call("query_readonly_sql")
    def query_readonly_sql(sql: str, limit: int | None = None, postgres_target: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        pg = _resolve_postgres_target(vault, postgres_target)
        if not getattr(pg, "sql_query_enabled", False):
            raise PermissionError("query_readonly_sql is disabled for this PostgreSQL target")
        return query_readonly_sql_impl(sql=sql, limit=limit, target=pg)

    @tool
    @audit_tool_call("get_deployment_info")
    def get_deployment_info(server: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        target = _resolve_server(vault, server)
        return get_deployment_info_impl(target=target)

    @tool
    @audit_tool_call("get_container_image_info")
    def get_container_image_info(container: str, server: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        target = _resolve_server(vault, server)
        return get_container_image_info_impl(container=container, target=target)

    @tool
    @audit_tool_call("get_container_status")
    def get_container_status(container: str, server: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        target = _resolve_server(vault, server)
        return get_container_status_impl(container=container, target=target)

    @tool
    @audit_tool_call("get_container_restart_count")
    def get_container_restart_count(container: str, server: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        target = _resolve_server(vault, server)
        return get_container_restart_count_impl(container=container, target=target)

    @tool
    @audit_tool_call("get_errors_grouped")
    def get_errors_grouped(log_name: str, minutes: int = 60, limit: int = 100, server: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        target = _resolve_server(vault, server)
        return get_errors_grouped_impl(log_name=log_name, minutes=minutes, limit=limit, target=target)

    @tool
    @audit_tool_call("get_logs_since_deploy")
    def get_logs_since_deploy(container: str, limit: int = 200, server: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        target = _resolve_server(vault, server)
        return get_logs_since_deploy_impl(container=container, limit=limit, target=target)

    @tool
    @audit_tool_call("get_recent_migrations")
    def get_recent_migrations(limit: int = 10, postgres_target: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        pg = _resolve_postgres_target(vault, postgres_target)
        return get_recent_migrations_impl(postgres_target=pg, limit=limit)

    @tool
    @audit_tool_call("get_failed_jobs")
    def get_failed_jobs(limit: int = 20, postgres_target: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        pg = _resolve_postgres_target(vault, postgres_target)
        return get_failed_jobs_impl(postgres_target=pg, limit=limit)

    @tool
    @audit_tool_call("get_table_row_count")
    def get_table_row_count(table: str, postgres_target: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        pg = _resolve_postgres_target(vault, postgres_target)
        return get_table_row_count_impl(table=table, postgres_target=pg)

    @tool
    @audit_tool_call("check_source_contains")
    def check_source_contains(path: str, needle: str, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        _get_vault_or_raise()
        return check_source_contains_impl(path=path, needle=needle)

    @tool
    @audit_tool_call("check_python_symbols_in_module")
    def check_python_symbols_in_module(module: str, symbols: list[str] | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        _get_vault_or_raise()
        return check_python_symbols_in_module_impl(module=module, symbols=symbols)

    @tool
    @audit_tool_call("diagnose_deployment_issue")
    def diagnose_deployment_issue(minutes: int = 60, server: str | None = None, postgres_target: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        target = _resolve_server(vault, server)
        pg = _resolve_postgres_target(vault, postgres_target) if postgres_target else None
        return diagnose_deployment_issue_impl(target=target, postgres_target=pg, minutes=minutes)

    @tool
    @audit_tool_call("diagnose_worker_issue")
    def diagnose_worker_issue(log_name: str = "worker", minutes: int = 60, limit: int = 50, server: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        target = _resolve_server(vault, server)
        return diagnose_worker_issue_impl(target=target, log_name=log_name, minutes=minutes, limit=limit)

    @tool
    @audit_tool_call("diagnose_database_issue")
    def diagnose_database_issue(postgres_target: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        pg = _resolve_postgres_target(vault, postgres_target)
        return diagnose_database_issue_impl(postgres_target=pg)

    @tool
    @audit_tool_call("diagnose_http_5xx_issue")
    def diagnose_http_5xx_issue(log_name: str, lines: int = 500, server: str | None = None, profile_code: str | None = None) -> dict[str, object]:
        _require_profile_code(profile_code)
        vault = _get_vault_or_raise()
        target = _resolve_server(vault, server)
        return diagnose_http_5xx_issue_impl(target=target, log_name=log_name, lines=lines)

    return registered


def _resolve_server(vault: Any, server: str | None) -> Any:
    if server:
        target = vault.get_server(server)
        if target is None:
            raise ValueError("server not found")
        return target
    default = vault.get_default_server()
    if default:
        return default
    raise ValueError("specify a server")


def _resolve_postgres_target(vault: Any, postgres_target: str | None, server: str | None = None) -> Any:
    if postgres_target:
        target = vault.get_postgres_target(postgres_target)
        if target is None:
            raise ValueError("postgres_target not found")
        return target
    default = vault.get_default_postgres_target()
    if default:
        return default
    raise ValueError("specify a postgres_target")
