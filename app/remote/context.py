from __future__ import annotations

from dataclasses import dataclass

from app.core.config import PgSentinelConfig, get_config
from app.remote.docker_client import RemoteDockerClient
from app.remote.log_reader import RemoteLogReader
from app.remote.postgres_client import RemotePostgresClient
from app.remote.ssh_client import RemoteSSHClient


@dataclass(frozen=True)
class RuntimeContext:
    config: PgSentinelConfig
    ssh: RemoteSSHClient
    docker: RemoteDockerClient
    logs: RemoteLogReader
    postgres: RemotePostgresClient


def build_runtime(config: PgSentinelConfig | None = None) -> RuntimeContext:
    resolved = config or get_config()
    ssh = RemoteSSHClient(resolved)
    docker = RemoteDockerClient(ssh, resolved)
    logs = RemoteLogReader(docker, resolved)
    postgres = RemotePostgresClient(ssh, docker, resolved)
    return RuntimeContext(config=resolved, ssh=ssh, docker=docker, logs=logs, postgres=postgres)
