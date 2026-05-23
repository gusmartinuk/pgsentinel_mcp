from __future__ import annotations

from app.core.config import get_config
from app.core.errors import ConfigError
from app.core.vault import ServerDef, PostgresTargetDef
from app.remote.connection import ConnectionAdapter
from app.remote.context import build_runtime


def health_overview(target: ServerDef | None = None) -> dict[str, object]:
    if target is not None:
        adapter = ConnectionAdapter(server=target)
        ok = adapter.test_connection()
        containers = adapter.get_docker_containers()
        return {
            "status": "ok" if ok else "warning",
            "server": target.name,
            "connection_mode": target.connection_mode,
            "connectivity": "ok" if ok else "failed",
            "container_count": len(containers),
            "containers": list(containers.keys())[:20],
        }
    try:
        config = get_config()
    except ConfigError:
        return {"status": "error", "error": "config not available and no vault target specified"}
    runtime = build_runtime(config)
    ok = runtime.ssh.test_connection()
    containers = runtime.docker.allowed_container_status()
    return {
        "status": "ok" if ok else "warning",
        "server_mode": config.server.mode,
        "connectivity": "ok" if ok else "failed",
        "containers": containers,
    }
