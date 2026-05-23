from __future__ import annotations

from app.core.config import get_config
from app.core.errors import ConfigError
from app.core.masking import mask_text
from app.core.vault import ServerDef
from app.remote.connection import ConnectionAdapter
from app.remote.context import build_runtime
from app.remote.log_reader import RemoteLogReader


def _get_mask_patterns() -> list[str]:
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


def get_container_logs(container: str, lines: int = 100, level_filter: str | None = None,
                       target: ServerDef | None = None) -> dict[str, object]:
    patterns = _get_mask_patterns()
    if target is not None:
        error = _log_access_error(target, container)
        if error:
            return {"error": error}
        adapter = ConnectionAdapter(server=target)
        raw = adapter.get_container_logs(container, lines=lines)
        masked = mask_text(raw, patterns)
        return {"container": container, "lines": lines, "output": masked}
    try:
        config = get_config()
    except ConfigError:
        return {"error": "config not available and no vault target specified"}
    runtime = build_runtime(config)
    reader = RemoteLogReader(runtime.docker, config)
    return reader.get_container_logs(container=container, lines=lines, level_filter=level_filter)


def search_logs(log_name: str, keyword: str, lines: int = 200,
                target: ServerDef | None = None) -> dict[str, object]:
    patterns = _get_mask_patterns()
    if target is not None:
        error = _log_access_error(target, log_name)
        if error:
            return {"error": error}
        adapter = ConnectionAdapter(server=target)
        raw = adapter.get_container_logs(log_name, lines=lines)
        matched = [line for line in raw.split("\n") if keyword.lower() in line.lower()]
        masked = mask_text("\n".join(matched), patterns)
        return {"log_name": log_name, "keyword": keyword, "matches": len(matched), "lines": masked}
    try:
        config = get_config()
    except ConfigError:
        return {"error": "config not available and no vault target specified"}
    runtime = build_runtime(config)
    reader = RemoteLogReader(runtime.docker, config)
    return reader.search_logs(log_name=log_name, keyword=keyword, lines=lines)


def get_recent_errors(log_name: str, minutes: int = 60, limit: int = 100,
                      target: ServerDef | None = None) -> dict[str, object]:
    patterns = _get_mask_patterns()
    if target is not None:
        error = _log_access_error(target, log_name)
        if error:
            return {"error": error}
        adapter = ConnectionAdapter(server=target)
        raw = adapter.get_container_logs(log_name, lines=500)
        from app.remote.log_reader import ERROR_RE
        errors = [line for line in raw.split("\n") if ERROR_RE.search(line)]
        masked = mask_text("\n".join(errors[-limit:]), patterns)
        return {"log_name": log_name, "error_count": len(errors), "lines": masked}
    try:
        config = get_config()
    except ConfigError:
        return {"error": "config not available and no vault target specified"}
    runtime = build_runtime(config)
    reader = RemoteLogReader(runtime.docker, config)
    return reader.get_recent_errors(log_name=log_name, minutes=minutes, limit=limit)


def _log_access_error(target: ServerDef, log_name: str) -> str:
    if target.allowed_log_sources and log_name not in target.allowed_log_sources:
        return f"log source is not allowlisted: {log_name}"
    if target.allow_all_containers:
        return ""
    if target.allowed_containers and log_name not in target.allowed_containers:
        return f"container is not allowlisted: {log_name}"
    if not target.allowed_containers:
        return f"container is not allowlisted: {log_name}"
    return ""
