from __future__ import annotations

from app.tools.docker import get_docker_containers as docker_impl
from app.tools.health import health_overview as health_impl
from app.tools.logs import get_recent_errors as errors_impl
from app.tools.postgres import get_postgres_health as pg_health_impl, get_table_sample as sample_impl
from app.core.vault import ServerDef, PostgresTargetDef


def diagnose_recent_failure(minutes: int = 60, target: ServerDef | None = None,
                            pg_target: PostgresTargetDef | None = None) -> dict[str, object]:
    findings = []
    docker_findings = []
    health_status = "ok"

    if target is not None:
        health = health_impl(target=target)
        docker = docker_impl(target=target)
        health_status = str(health.get("status", "ok"))
        if health_status != "ok":
            findings.append({"severity": "warning", "message": f"Server {target.name}: connectivity issue"})
        container_data = docker.get("containers", {})
        for name, status in container_data.items():
            if isinstance(status, str) and "up" not in status.lower():
                docker_findings.append({"severity": "warning", "message": f"Container {name}: {status}"})
    else:
        try:
            health = health_impl()
            docker = docker_impl()
            health_status = str(health.get("status", "ok"))
        except Exception:
            health_status = "error"
            docker = {}
        container_data = docker.get("containers", {})
        for name, status in container_data.items():
            if isinstance(status, str) and "up" not in status.lower():
                docker_findings.append({"severity": "warning", "message": f"Container {name}: {status}"})

    findings = docker_findings + findings

    if target is not None and target.allowed_log_sources:
        for log_name in target.allowed_log_sources[:3]:
            try:
                errors = errors_impl(log_name=log_name, minutes=minutes, limit=10, target=target)
                entries = errors.get("lines", "")
                if entries:
                    findings.append({"severity": "warning", "message": f"Log {log_name}: errors found"})
            except Exception:
                pass
    else:
        try:
            for log_name in ["app", "postgres"]:
                try:
                    errors = errors_impl(log_name=log_name, minutes=minutes, limit=10)
                    if errors.get("error_count", 0) > 0:
                        findings.append({"severity": "warning", "message": f"Log {log_name}: {errors.get('error_count')} errors"})
                except Exception:
                    pass
        except Exception:
            pass

    if pg_target is not None:
        try:
            pg_health_result = pg_health_impl(target=pg_target)
            if pg_health_result.get("status") != "ok":
                findings.append({"severity": "warning", "message": f"PostgreSQL {pg_target.name}: {pg_health_result.get('connection_test', '?')}"})
            if pg_target.allow_all_tables or "failed_jobs" in pg_target.allowed_tables:
                sample = sample_impl(table="failed_jobs", limit=5, target=pg_target)
                rows = sample.get("rows", [])
                if isinstance(rows, list) and len(rows) > 0:
                    findings.append({"severity": "warning", "message": f"Table failed_jobs has recent entries", "count": len(rows)})
        except Exception:
            pass
    else:
        try:
            pg_health_result = pg_health_impl()
            if pg_health_result.get("status") != "ok":
                findings.append({"severity": "warning", "message": "PostgreSQL health issue"})
            try:
                sample = sample_impl(table="failed_jobs", limit=5)
                if isinstance(sample.get("rows", []), list) and len(sample.get("rows") or []) > 0:
                    findings.append({"severity": "warning", "message": "failed_jobs table has recent entries"})
            except Exception:
                pass
        except Exception:
            pass

    status = "warning" if findings else health_status
    return {
        "status": status,
        "summary": f"{len(findings)} findings, server connectivity {health_status}",
        "findings": findings,
        "server": target.name if target else "default",
    }
