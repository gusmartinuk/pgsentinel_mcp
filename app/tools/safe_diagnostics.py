from __future__ import annotations

import ast
import os
from collections import Counter
from pathlib import Path

from app.core.masking import mask_text
from app.core.security import clamp_limit, quote_identifier, validate_identifier
from app.core.vault import PostgresTargetDef, ServerDef
from app.remote.connection import ConnectionAdapter
from app.tools.diagnostics import diagnose_recent_failure
from app.tools.logs import get_recent_errors, search_logs
from app.tools.postgres import query_readonly_sql


ALLOWED_SOURCE_FILES = {
    "README.md",
    "docs/specs.md",
    "docs/deployment.md",
    "docs/testing.md",
    "app/main.py",
    "app/mcp/tools.py",
}

ALLOWED_PY_MODULES = {
    "app.main",
    "app.mcp.tools",
    "app.tools.diagnostics",
    "app.tools.logs",
    "app.tools.postgres",
}


def get_deployment_info(target: ServerDef) -> dict[str, object]:
    adapter = ConnectionAdapter(server=target)
    containers = adapter.get_docker_containers()
    return {
        "server": target.name,
        "connection_mode": target.connection_mode,
        "container_count": len(containers),
        "containers": containers,
        "uptime": (adapter.get_uptime() or "").strip(),
        "disk_usage": (adapter.get_disk_usage() or "").strip(),
        "memory_usage": (adapter.get_memory_usage() or "").strip(),
    }


def get_container_image_info(container: str, target: ServerDef) -> dict[str, object]:
    _ensure_allowed_container(target, container)
    adapter = ConnectionAdapter(server=target)
    result = adapter.run(
        ["docker", "inspect", "--format", "{{.Name}}|{{.Config.Image}}|{{.Image}}", container],
        command_label="docker_inspect_image",
        check=False,
    )
    parts = result.stdout.strip().split("|", 2)
    return {
        "container": container,
        "configured_image": parts[1] if len(parts) > 1 else "",
        "image_id": parts[2] if len(parts) > 2 else "",
        "ok": result.ok,
    }


def get_container_status(container: str, target: ServerDef) -> dict[str, object]:
    _ensure_allowed_container(target, container)
    adapter = ConnectionAdapter(server=target)
    return adapter.get_container_status(container)


def get_container_restart_count(container: str, target: ServerDef) -> dict[str, object]:
    _ensure_allowed_container(target, container)
    adapter = ConnectionAdapter(server=target)
    result = adapter.run(
        ["docker", "inspect", "--format", "{{.Name}}|{{.RestartCount}}", container],
        command_label="docker_inspect_restart_count",
        check=False,
    )
    parts = result.stdout.strip().split("|", 1)
    count = 0
    if len(parts) > 1:
        try:
            count = int(parts[1])
        except ValueError:
            count = 0
    return {"container": container, "restart_count": count, "ok": result.ok}


def get_errors_grouped(log_name: str, minutes: int = 60, limit: int = 100, target: ServerDef | None = None) -> dict[str, object]:
    result = get_recent_errors(log_name=log_name, minutes=minutes, limit=limit, target=target)
    lines = _extract_lines(result)
    grouped = Counter(_normalize_error(line) for line in lines if line.strip())
    top = [{"signature": k, "count": v} for k, v in grouped.most_common(20)]
    return {"log_name": log_name, "minutes": minutes, "total": len(lines), "groups": top}


def get_logs_since_deploy(container: str, limit: int = 200, target: ServerDef | None = None) -> dict[str, object]:
    if target is None:
        return {"error": "server target is required"}
    _ensure_allowed_container(target, container)
    adapter = ConnectionAdapter(server=target)
    status = adapter.get_container_status(container)
    started_at = str(status.get("started_at", "")).strip()
    capped = clamp_limit(limit, 1000, 200)
    args = ["docker", "logs", "--tail", str(capped), container]
    if started_at:
        args = ["docker", "logs", "--since", started_at, "--tail", str(capped), container]
    result = adapter.run(args, command_label="docker_logs_since_deploy", check=False)
    return {
        "container": container,
        "started_at": started_at,
        "limit": capped,
        "lines": _mask_and_split(result.stdout),
        "ok": result.ok,
    }


def get_recent_migrations(postgres_target: PostgresTargetDef, limit: int = 10) -> dict[str, object]:
    _ensure_allowed_table(postgres_target, "alembic_version")
    capped = clamp_limit(limit, 100, 10)
    sql = f"select version_num from public.alembic_version limit {capped}"
    result = query_readonly_sql(sql=sql, limit=capped, target=postgres_target)
    return {"target": postgres_target.name, "limit": capped, "result": result}


def get_failed_jobs(postgres_target: PostgresTargetDef, limit: int = 20) -> dict[str, object]:
    _ensure_allowed_table(postgres_target, "failed_jobs")
    capped = clamp_limit(limit, 200, 20)
    sql = f"select * from public.failed_jobs order by 1 desc limit {capped}"
    result = query_readonly_sql(sql=sql, limit=capped, target=postgres_target)
    return {"target": postgres_target.name, "limit": capped, "result": result}


def get_table_row_count(table: str, postgres_target: PostgresTargetDef) -> dict[str, object]:
    validate_identifier(table, "table")
    _ensure_allowed_table(postgres_target, table)
    sql = f"select count(*) as row_count from {quote_identifier('public')}.{quote_identifier(table)}"
    result = query_readonly_sql(sql=sql, limit=1, target=postgres_target)
    return {"target": postgres_target.name, "table": table, "result": result}


def check_source_contains(path: str, needle: str) -> dict[str, object]:
    _ensure_allowed_source_file(path)
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    found = needle in text
    around = ""
    if found:
        idx = text.index(needle)
        around = text[max(0, idx - 120): idx + min(len(needle) + 120, len(text) - idx)]
    return {"path": path, "found": found, "snippet": mask_text(around, ["password=", "token=", "Bearer "])}


def check_python_symbols_in_module(module: str, symbols: list[str] | None = None) -> dict[str, object]:
    _ensure_allowed_module(module)
    mod_path = Path(module.replace(".", "/") + ".py")
    source = mod_path.read_text(encoding="utf-8", errors="replace")
    tree = ast.parse(source, filename=str(mod_path))
    funcs = sorted({n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))})
    classes = sorted({n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)})
    if symbols:
        present = {name: (name in funcs or name in classes) for name in symbols}
        return {"module": module, "present": present, "functions": funcs[:200], "classes": classes[:200]}
    return {"module": module, "functions": funcs[:200], "classes": classes[:200]}


def diagnose_deployment_issue(target: ServerDef, postgres_target: PostgresTargetDef | None = None, minutes: int = 60) -> dict[str, object]:
    base = diagnose_recent_failure(minutes=minutes, target=target, pg_target=postgres_target)
    return {"diagnosis": "deployment_issue", **base}


def diagnose_worker_issue(target: ServerDef, log_name: str = "worker", minutes: int = 60, limit: int = 50) -> dict[str, object]:
    errors = get_recent_errors(log_name=log_name, minutes=minutes, limit=limit, target=target)
    groups = get_errors_grouped(log_name=log_name, minutes=minutes, limit=limit, target=target)
    return {"diagnosis": "worker_issue", "errors": errors, "groups": groups}


def diagnose_database_issue(postgres_target: PostgresTargetDef) -> dict[str, object]:
    health = query_readonly_sql(sql="select now() as db_now", limit=1, target=postgres_target)
    migrations = get_recent_migrations(postgres_target=postgres_target, limit=5)
    failed_jobs = get_failed_jobs(postgres_target=postgres_target, limit=5) if _table_allowed(postgres_target, "failed_jobs") else {"skipped": True}
    return {"diagnosis": "database_issue", "health_probe": health, "migrations": migrations, "failed_jobs": failed_jobs}


def diagnose_http_5xx_issue(target: ServerDef, log_name: str, lines: int = 500) -> dict[str, object]:
    _ensure_allowed_log_name(target, log_name)
    matches = search_logs(log_name=log_name, keyword=" 5", lines=lines, target=target)
    return {"diagnosis": "http_5xx_issue", "log_name": log_name, "matches": matches}


def _normalize_error(line: str) -> str:
    compact = " ".join(line.strip().split())
    compact = compact[:240]
    for marker in (" at line ", " traceback", "Traceback"):
        pos = compact.lower().find(marker.strip().lower())
        if pos > 0:
            return compact[:pos]
    return compact


def _extract_lines(result: dict[str, object]) -> list[str]:
    if isinstance(result.get("errors"), list):
        return [str(x) for x in result.get("errors", [])]
    raw = str(result.get("lines", ""))
    return [line for line in raw.splitlines() if line.strip()]


def _mask_and_split(raw: str) -> list[str]:
    masked = mask_text(raw, ["password=", "token=", "Bearer ", "Authorization:", "DB_PASSWORD="])
    return [line for line in masked.splitlines() if line.strip()]


def _ensure_allowed_container(target: ServerDef, container: str) -> None:
    if target.allow_all_containers:
        return
    if target.allowed_containers and container not in target.allowed_containers:
        raise ValueError(f"container is not allowlisted: {container}")
    if not target.allowed_containers:
        raise ValueError(f"container is not allowlisted: {container}")


def _ensure_allowed_log_name(target: ServerDef, log_name: str) -> None:
    if target.allowed_log_sources and log_name not in target.allowed_log_sources:
        raise ValueError(f"log source is not allowlisted: {log_name}")
    _ensure_allowed_container(target, log_name)


def _table_allowed(target: PostgresTargetDef, table: str) -> bool:
    return target.allow_all_tables or table in target.allowed_tables


def _ensure_allowed_table(target: PostgresTargetDef, table: str) -> None:
    if not _table_allowed(target, table):
        raise ValueError(f"table is not allowlisted: {table}")


def _ensure_allowed_source_file(path: str) -> None:
    norm = os.path.normpath(path).replace("\\", "/")
    if norm not in ALLOWED_SOURCE_FILES:
        raise ValueError(f"source file is not allowlisted: {path}")
    if not Path(norm).exists():
        raise ValueError(f"source file not found: {path}")


def _ensure_allowed_module(module: str) -> None:
    if module not in ALLOWED_PY_MODULES:
        raise ValueError(f"module is not allowlisted: {module}")
