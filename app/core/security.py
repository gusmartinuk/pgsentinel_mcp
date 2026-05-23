from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from app.core.config import PgSentinelConfig
from app.core.errors import SecurityError

IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
FORBIDDEN_SQL_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|create|grant|revoke|merge|call|copy|vacuum|analyze|refresh|listen|notify)\b",
    re.IGNORECASE,
)
TABLE_REF_RE = re.compile(r"\b(?:from|join)\s+([A-Za-z_][A-Za-z0-9_]*)(?:\.([A-Za-z_][A-Za-z0-9_]*))?", re.IGNORECASE)
LIMIT_RE = re.compile(r"\blimit\s+\d+\b", re.IGNORECASE)
STATEMENT_HEAD_RE = re.compile(r"^\s*([a-z_]+)", re.IGNORECASE)
WITH_DML_RE = re.compile(r"\)\s*(insert|update|delete|merge)\b", re.IGNORECASE)

SQL_CATEGORY_READ = "read"
SQL_CATEGORY_INSERT = "insert"
SQL_CATEGORY_UPDATE = "update"
SQL_CATEGORY_DELETE = "delete"
SQL_CATEGORY_CREATE = "create"
SQL_CATEGORY_ALTER = "alter"
SQL_CATEGORY_DROP = "drop"
SQL_CATEGORY_TRUNCATE = "truncate"
SQL_CATEGORY_MAINTENANCE = "maintenance"
SQL_CATEGORY_PRIVILEGE = "privilege"
SQL_CATEGORY_TX = "transaction"
SQL_CATEGORY_UNKNOWN = "unknown"


@dataclass
class SQLPolicy:
    mode: str = "readonly_default"
    allow_insert: bool = False
    allow_update: bool = False
    allow_delete: bool = False
    allow_create: bool = False
    allow_alter: bool = False
    allow_drop: bool = False
    allow_truncate: bool = False
    allow_maintenance: bool = False
    allow_privilege: bool = False
    allow_transaction: bool = False
    hard_max_query_rows: int = 1000


@dataclass
class SQLGuardDecision:
    sql: str
    category: str
    limit: int


def validate_identifier(value: str, label: str = "identifier") -> str:
    if not IDENTIFIER_RE.fullmatch(value):
        raise SecurityError(f"invalid {label}: {value}")
    return value


def quote_identifier(value: str) -> str:
    validate_identifier(value)
    return f'"{value}"'


def clamp_limit(requested: int | None, maximum: int, default: int) -> int:
    if requested is None:
        return min(default, maximum)
    if requested < 1:
        raise SecurityError("limit must be greater than zero")
    return min(requested, maximum)


def ensure_allowed_container(config: PgSentinelConfig, container: str) -> str:
    if container not in config.docker.allowed_containers:
        raise SecurityError(f"container is not allowlisted: {container}")
    return validate_identifier(container.replace("-", "_"), "container alias") and container


def ensure_allowed_log(config: PgSentinelConfig, log_name: str):
    if log_name not in config.logs.allowed_logs:
        raise SecurityError(f"log is not allowlisted: {log_name}")
    return config.logs.allowed_logs[log_name]


def ensure_allowed_table(config: PgSentinelConfig, table: str) -> str:
    validate_identifier(table, "table")
    if config.postgres.allowed_tables and table not in config.postgres.allowed_tables:
        raise SecurityError(f"table is not allowlisted: {table}")
    return table


def first_allowed_schema(config: PgSentinelConfig) -> str:
    if not config.postgres.allowed_schemas:
        raise SecurityError("no PostgreSQL schema is allowlisted")
    schema = config.postgres.allowed_schemas[0]
    validate_identifier(schema, "schema")
    return schema


def reject_multiple_statements(sql: str) -> str:
    stripped = sql.strip()
    without_trailing = stripped[:-1] if stripped.endswith(";") else stripped
    if ";" in without_trailing:
        raise SecurityError("multiple SQL statements are not allowed")
    return without_trailing.strip()


def tables_referenced_by_sql(sql: str) -> set[str]:
    tables: set[str] = set()
    for match in TABLE_REF_RE.finditer(sql):
        first, second = match.groups()
        tables.add(second or first)
    return tables


def validate_readonly_sql(sql: str, allowed_tables: Iterable[str], max_rows: int) -> str:
    decision = guard_sql_query(sql, allowed_tables, SQLPolicy(mode="readonly_default", hard_max_query_rows=max_rows), None, max_rows)
    return decision.sql


def guard_sql_query(
    sql: str,
    allowed_tables: Iterable[str],
    policy: SQLPolicy,
    requested_limit: int | None,
    default_limit: int,
) -> SQLGuardDecision:
    sanitized = reject_multiple_statements(sql)
    if not sanitized:
        raise SecurityError("SQL must not be empty")
    if "--" in sanitized or "/*" in sanitized or "*/" in sanitized:
        raise SecurityError("SQL comments are not allowed")
    category = classify_sql_statement(sanitized)
    if category == SQL_CATEGORY_UNKNOWN:
        raise SecurityError("SQL statement type is not allowed")
    _enforce_sql_policy(category, policy)
    allowed = set(allowed_tables)
    if allowed:
        for table in tables_referenced_by_sql(sanitized):
            if table not in allowed:
                raise SecurityError(f"SQL references non-allowlisted table: {table}")
    hard_max = max(1, min(policy.hard_max_query_rows, 5000))
    limit = clamp_limit(requested_limit, hard_max, min(default_limit, hard_max))
    if category == SQL_CATEGORY_READ:
        if LIMIT_RE.search(sanitized):
            return SQLGuardDecision(sql=sanitized, category=category, limit=limit)
        if _read_statement_supports_limit(sanitized):
            return SQLGuardDecision(sql=f"{sanitized} LIMIT {limit}", category=category, limit=limit)
        return SQLGuardDecision(sql=sanitized, category=category, limit=limit)
    return SQLGuardDecision(sql=sanitized, category=category, limit=limit)


def classify_sql_statement(sql: str) -> str:
    head_match = STATEMENT_HEAD_RE.match(sql)
    if not head_match:
        return SQL_CATEGORY_UNKNOWN
    head = head_match.group(1).lower()
    if head in {"select", "show", "explain", "values"}:
        return SQL_CATEGORY_READ
    if head == "with":
        return SQL_CATEGORY_READ if not WITH_DML_RE.search(sql) else SQL_CATEGORY_UNKNOWN
    if head == "insert":
        return SQL_CATEGORY_INSERT
    if head == "update":
        return SQL_CATEGORY_UPDATE
    if head == "delete":
        return SQL_CATEGORY_DELETE
    if head == "create":
        return SQL_CATEGORY_CREATE
    if head == "alter":
        return SQL_CATEGORY_ALTER
    if head == "drop":
        return SQL_CATEGORY_DROP
    if head == "truncate":
        return SQL_CATEGORY_TRUNCATE
    if head in {"vacuum", "analyze", "reindex", "refresh"}:
        return SQL_CATEGORY_MAINTENANCE
    if head in {"grant", "revoke"}:
        return SQL_CATEGORY_PRIVILEGE
    if head in {"begin", "start", "commit", "rollback", "savepoint", "release"}:
        return SQL_CATEGORY_TX
    return SQL_CATEGORY_UNKNOWN


def _enforce_sql_policy(category: str, policy: SQLPolicy) -> None:
    if policy.mode == "readonly_default":
        if category != SQL_CATEGORY_READ:
            raise SecurityError("SQL policy blocks non-read statements")
        return
    if policy.mode != "guarded_write":
        raise SecurityError(f"unsupported SQL policy mode: {policy.mode}")
    if category == SQL_CATEGORY_READ:
        return
    if category == SQL_CATEGORY_INSERT and policy.allow_insert:
        return
    if category == SQL_CATEGORY_UPDATE and policy.allow_update:
        return
    if category == SQL_CATEGORY_DELETE and policy.allow_delete:
        return
    if category == SQL_CATEGORY_CREATE and policy.allow_create:
        return
    if category == SQL_CATEGORY_ALTER and policy.allow_alter:
        return
    if category == SQL_CATEGORY_DROP and policy.allow_drop:
        return
    if category == SQL_CATEGORY_TRUNCATE and policy.allow_truncate:
        return
    if category == SQL_CATEGORY_MAINTENANCE and policy.allow_maintenance:
        return
    if category == SQL_CATEGORY_PRIVILEGE and policy.allow_privilege:
        return
    if category == SQL_CATEGORY_TX and policy.allow_transaction:
        return
    raise SecurityError(f"SQL policy blocks '{category}' statements")


def _read_statement_supports_limit(sql: str) -> bool:
    head_match = STATEMENT_HEAD_RE.match(sql)
    if not head_match:
        return False
    return head_match.group(1).lower() in {"select", "with"}
