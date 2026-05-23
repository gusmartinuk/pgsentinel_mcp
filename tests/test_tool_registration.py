from app.mcp.tools import register_tools


class FakeMCP:
    def __init__(self):
        self.registered = {}

    def tool(self):
        def decorator(func):
            self.registered[func.__name__] = func
            return func

        return decorator


def test_raw_sql_tool_is_not_registered_by_default(config):
    mcp = FakeMCP()

    registered = register_tools(mcp, config=config)

    assert "query_readonly_sql" in registered
    assert "query_readonly_sql" in mcp.registered
    assert "diagnose_recent_failure" in registered
    assert "get_deployment_info" in registered
    assert "get_container_image_info" in registered
    assert "get_container_status" in registered
    assert "get_container_restart_count" in registered
    assert "get_errors_grouped" in registered
    assert "get_logs_since_deploy" in registered
    assert "get_recent_migrations" in registered
    assert "get_failed_jobs" in registered
    assert "get_table_row_count" in registered
    assert "check_source_contains" in registered
    assert "check_python_symbols_in_module" in registered
    assert "diagnose_deployment_issue" in registered
    assert "diagnose_worker_issue" in registered
    assert "diagnose_database_issue" in registered
    assert "diagnose_http_5xx_issue" in registered


def test_raw_sql_tool_registers_when_explicitly_enabled(config_data):
    config_data["security"]["allow_raw_sql"] = True
    from app.core.config import PgSentinelConfig

    config = PgSentinelConfig.model_validate(config_data)
    mcp = FakeMCP()

    registered = register_tools(mcp, config=config)

    assert "query_readonly_sql" in registered


def test_raw_sql_tool_registers_in_vault_mode_without_legacy_config():
    mcp = FakeMCP()
    registered = register_tools(mcp, config=None)
    assert "query_readonly_sql" in registered
