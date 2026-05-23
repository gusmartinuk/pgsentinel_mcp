from __future__ import annotations

import json
import re

from app.core.config import get_config
from app.core.errors import ConfigError
from app.core.masking import mask_data, mask_text
from app.core.security import SQLPolicy, clamp_limit, guard_sql_query, quote_identifier, tables_referenced_by_sql
from app.core.vault import PostgresTargetDef, ServerDef
from app.remote.connection import ConnectionAdapter
from app.remote.context import build_runtime
from app.remote.direct_postgres import DIRECT_POSTGRES_MODES, DirectPostgresClient

SELECT_LIKE_RE = re.compile(r"^\s*(select|with)\b", re.IGNORECASE)


def get_postgres_health(target: PostgresTargetDef | None = None) -> dict[str, object]:
    if target is not None:
        result = _run_target_sql(target, "SELECT json_build_object('ok', true)")
        ok = result.ok
        return {
            "status": "ok" if ok else "warning",
            "database": target.database_name,
            "connection_test": "ok" if ok else "failed",
            "output": mask_text(result.stdout.strip() + result.stderr.strip(), _get_patterns()),
        }
    try:
        config = get_config()
    except ConfigError:
        return {"error": "config not available and no vault target specified"}
    runtime = build_runtime(config)
    return runtime.postgres.health()


def list_allowed_tables(target: PostgresTargetDef | None = None) -> dict[str, object]:
    if target is not None:
        if target.allow_all_tables:
            tables = ["* (all tables)"]
        else:
            tables = target.allowed_tables
        return {"schemas": target.allowed_schemas, "tables": tables}
    try:
        config = get_config()
    except ConfigError:
        return {"error": "config not available and no vault target specified"}
    return {
        "schemas": config.postgres.allowed_schemas,
        "tables": config.postgres.allowed_tables,
    }


def describe_table(table: str, target: PostgresTargetDef | None = None) -> dict[str, object]:
    if target is not None:
        if not _table_allowed(target, table):
            return {"error": f"table '{table}' not in allowed_tables for target '{target.name}'"}
        schema = target.allowed_schemas[0] if target.allowed_schemas else "public"
        sql = "SELECT json_build_object('name', column_name, 'type', data_type, 'nullable', is_nullable = 'YES') FROM information_schema.columns WHERE table_schema = '%s' AND table_name = '%s' ORDER BY ordinal_position" % (schema.replace("'", "''"), table.replace("'", "''"))
        result = _run_target_sql(target, sql)
        columns = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                col = json.loads(line)
                if isinstance(col, dict) and col.get("name") not in target.sensitive_columns:
                    columns.append(col)
            except json.JSONDecodeError:
                pass
        return {"schema": schema, "table": table, "columns": columns}
    try:
        config = get_config()
    except ConfigError:
        return {"error": "config not available and no vault target specified"}
    runtime = build_runtime(config)
    return runtime.postgres.describe_table(table)


def get_table_sample(table: str, limit: int | None = None,
                     target: PostgresTargetDef | None = None) -> dict[str, object]:
    patterns = _get_patterns()
    if target is not None:
        if not _table_allowed(target, table):
            return {"error": f"table '{table}' not in allowed_tables for target '{target.name}'"}
        schema = target.allowed_schemas[0] if target.allowed_schemas else "public"
        row_limit = clamp_limit(limit, target.max_rows, min(20, target.max_rows))
        sql = f"SELECT row_to_json(t) FROM (SELECT * FROM {quote_identifier(schema)}.{quote_identifier(table)} LIMIT {row_limit}) t"
        result = _run_target_sql(target, sql)
        rows = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append(mask_text(line, patterns))
        return {"schema": schema, "table": table, "limit": row_limit, "rows": mask_data(rows, patterns)}
    try:
        config = get_config()
    except ConfigError:
        return {"error": "config not available and no vault target specified"}
    runtime = build_runtime(config)
    return runtime.postgres.sample_table(table, limit)


def query_readonly_sql(sql: str, limit: int | None = None, target: PostgresTargetDef | None = None) -> dict[str, object]:
    patterns = _get_patterns()
    if target is not None:
        policy = _sql_policy_from_target(target)
        _ensure_sql_table_access(target, sql)
        guarded = guard_sql_query(sql, [] if target.allow_all_tables else target.allowed_tables, policy, limit, target.max_rows)
        executed_sql = guarded.sql
        use_json_wrap = False
        if guarded.category == "read":
            if SELECT_LIKE_RE.match(guarded.sql):
                use_json_wrap = True
                executed_sql = f"SELECT row_to_json(t) FROM ({guarded.sql}) t"
        result = _run_target_sql(target, executed_sql)
        if not use_json_wrap:
            text = mask_text((result.stdout or result.stderr).strip(), patterns)
            return {"category": guarded.category, "limit": guarded.limit, "output": text}
        rows = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append(mask_text(line, patterns))
        return {
            "category": guarded.category,
            "limit": guarded.limit,
            "rows": mask_data(rows, patterns),
        }
    try:
        config = get_config()
    except ConfigError:
        return {"error": "config not available and no vault target specified. Use the web panel to set up targets first."}
    runtime = build_runtime(config)
    return runtime.postgres.query_readonly_sql(sql)


def _get_patterns() -> list[str]:
    try:
        from app.core.vault_manager import get_vault_data, vault_is_unlocked
        if vault_is_unlocked():
            return get_vault_data().masking_patterns
    except Exception:
        pass
    try:
        return get_config().masking.patterns
    except ConfigError:
        return []


def _adapter_for_target(target: PostgresTargetDef) -> ConnectionAdapter:
    return ConnectionAdapter(server=_server_for_target(target), pg_target=target)


def _run_target_sql(target: PostgresTargetDef, sql: str):
    if target.connection_mode in DIRECT_POSTGRES_MODES:
        timeout = _command_timeout()
        return DirectPostgresClient(target, server=_server_for_target(target), timeout=timeout).run_json_sql(sql)
    adapter = _adapter_for_target(target)
    return adapter.run_psql(
        container=target.container_name,
        host=target.host or "localhost",
        port=target.port or 5432,
        user=target.readonly_username,
        db=target.database_name,
        sql=sql,
        password=target.readonly_password,
    )


def _server_for_target(target: PostgresTargetDef) -> ServerDef | None:
    if not target.server_id:
        return None
    try:
        from app.core.vault_manager import get_vault_data, vault_is_unlocked
        if vault_is_unlocked():
            return get_vault_data().get_server(target.server_id)
    except Exception:
        return None
    return None


def _command_timeout() -> int:
    try:
        from app.core.vault_manager import get_vault_data, vault_is_unlocked
        if vault_is_unlocked():
            return get_vault_data().settings.command_timeout_seconds
    except Exception:
        pass
    try:
        return get_config().security.command_timeout_seconds
    except ConfigError:
        return 20


def _sql_policy_from_target(target: PostgresTargetDef) -> SQLPolicy:
    try:
        from app.core.vault_manager import get_vault_data, vault_is_unlocked
        if vault_is_unlocked():
            s = get_vault_data().settings
            return SQLPolicy(
                mode=s.sql_policy_mode,
                allow_insert=s.sql_allow_insert,
                allow_update=s.sql_allow_update,
                allow_delete=s.sql_allow_delete,
                allow_create=s.sql_allow_create,
                allow_alter=s.sql_allow_alter,
                allow_drop=s.sql_allow_drop,
                allow_truncate=s.sql_allow_truncate,
                allow_maintenance=s.sql_allow_maintenance,
                allow_privilege=s.sql_allow_privilege,
                allow_transaction=s.sql_allow_transaction,
                hard_max_query_rows=s.sql_hard_max_query_rows,
            )
    except Exception:
        pass
    return SQLPolicy(mode="readonly_default", hard_max_query_rows=max(1000, target.max_rows))


def _table_allowed(target: PostgresTargetDef, table: str) -> bool:
    return target.allow_all_tables or table in target.allowed_tables


def _ensure_sql_table_access(target: PostgresTargetDef, sql: str) -> None:
    refs = tables_referenced_by_sql(sql)
    if not refs:
        return
    if target.allow_all_tables:
        return
    if not target.allowed_tables:
        raise PermissionError("no tables are allowlisted for this PostgreSQL target")
    denied = sorted(ref for ref in refs if ref not in target.allowed_tables)
    if denied:
        raise PermissionError(f"SQL references non-allowlisted table(s): {', '.join(denied)}")
