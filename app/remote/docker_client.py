from __future__ import annotations

from app.core.config import PgSentinelConfig
from app.core.masking import mask_text
from app.core.security import clamp_limit, ensure_allowed_container
from app.remote.ssh_client import RemoteSSHClient


class RemoteDockerClient:
    def __init__(self, ssh: RemoteSSHClient, config: PgSentinelConfig):
        self.ssh = ssh
        self.config = config

    def docker_available(self) -> bool:
        result = self.ssh.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            command_label="docker_version",
            check=False,
        )
        return result.ok

    def allowed_container_status(self) -> list[dict[str, str]]:
        containers: list[dict[str, str]] = []
        for container in self.config.docker.allowed_containers:
            containers.append(self.container_status(container))
        return containers

    def container_status(self, container: str) -> dict[str, str]:
        ensure_allowed_container(self.config, container)
        result = self.ssh.run(
            [
                "docker",
                "inspect",
                "--format",
                "{{.Name}}|{{.Config.Image}}|{{.State.Status}}|{{.State.StartedAt}}",
                container,
            ],
            command_label="docker_inspect",
            check=False,
        )
        if not result.ok:
            return {"name": container, "status": "missing", "image": "", "started_at": ""}
        line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
        name, image, status, started_at = (line.split("|", 3) + ["", "", "", ""])[:4]
        return {
            "name": name.lstrip("/") or container,
            "status": status or "unknown",
            "image": image,
            "started_at": started_at,
        }

    def logs(self, container: str, lines: int | None = None) -> str:
        ensure_allowed_container(self.config, container)
        limit = clamp_limit(lines, self.config.security.max_log_lines, self.config.security.max_log_lines)
        result = self.ssh.run(
            ["docker", "logs", "--tail", limit, container],
            command_label="docker_logs",
        )
        return mask_text(result.stdout + result.stderr, self.config.masking.patterns)

    def disk_usage(self) -> str:
        result = self.ssh.run(["df", "-P", "-h", "/"], command_label="disk_usage", check=False)
        if not result.ok:
            return "unknown"
        lines = result.stdout.strip().splitlines()
        if len(lines) < 2:
            return "unknown"
        parts = lines[1].split()
        return parts[4] if len(parts) >= 5 else "unknown"

    def memory_usage(self) -> str:
        result = self.ssh.run(["free", "-m"], command_label="memory_usage", check=False)
        if not result.ok:
            return "unknown"
        for line in result.stdout.splitlines():
            if line.lower().startswith("mem:"):
                parts = line.split()
                if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
                    total = int(parts[1])
                    used = int(parts[2])
                    if total > 0:
                        return f"{round((used / total) * 100)}%"
        return "unknown"

    def uptime(self) -> str:
        result = self.ssh.run(["uptime", "-p"], command_label="uptime", check=False)
        return result.stdout.strip() if result.ok and result.stdout.strip() else "unknown"
