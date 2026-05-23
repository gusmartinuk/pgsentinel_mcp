from __future__ import annotations

from app.core.config import get_config
from app.core.errors import ConfigError
from app.core.vault import ServerDef
from app.remote.connection import ConnectionAdapter
from app.remote.context import build_runtime


def get_docker_containers(target: ServerDef | None = None) -> dict[str, object]:
    if target is not None:
        adapter = ConnectionAdapter(server=target)
        all_containers = adapter.get_docker_containers()
        if target.allow_all_containers:
            result = all_containers
        elif target.allowed_containers:
            allowed = target.allowed_containers
            result = {c: s for c, s in all_containers.items() if c in allowed}
        else:
            result = {}
        return {"server": target.name, "containers": result}
    try:
        config = get_config()
    except ConfigError:
        return {"error": "config not available and no vault target specified"}
    runtime = build_runtime(config)
    return runtime.docker.allowed_container_status()
