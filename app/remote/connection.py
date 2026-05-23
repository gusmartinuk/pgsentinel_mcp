from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from app.core.vault import ServerDef, PostgresTargetDef, MonitoringTargetDef
from app.remote.hostkeys import load_host_keys, PersistentTOFUPolicy


@dataclass(frozen=True)
class CommandResult:
    command_label: str
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class ConnectionAdapter:
    """Unified interface for running commands on different connection modes."""

    def __init__(self, server: ServerDef | None = None, pg_target: PostgresTargetDef | None = None,
                 monitoring_target: MonitoringTargetDef | None = None):
        self.server = server
        self.pg_target = pg_target
        self.monitoring_target = monitoring_target

    def run(self, args: Sequence[str | int], *, command_label: str,
            env: Mapping[str, str] | None = None, timeout: int = 20,
            check: bool = True) -> CommandResult:
        if self.server is None:
            return self._run_local(args, command_label=command_label, env=env, timeout=timeout, check=check)
        mode = self.server.connection_mode
        if mode == "local":
            return self._run_local(args, command_label=command_label, env=env, timeout=timeout, check=check)
        elif mode == "ssh" or mode == "docker_exec_psql_over_ssh" or mode == "ssh_tunnel_direct_postgres":
            return self._run_ssh(args, command_label=command_label, env=env, timeout=timeout, check=check)
        else:
            return self._run_local(args, command_label=command_label, env=env, timeout=timeout, check=check)

    def test_connection(self) -> bool:
        if self.server is None or self.server.connection_mode == "local":
            result = self.run(["docker", "version", "--format", "{{.Server.Version}}"],
                              command_label="local_docker_connectivity", check=False)
            return result.ok
        result = self.run(["true"], command_label="ssh_connectivity", check=False)
        return result.ok

    def get_docker_containers(self) -> dict[str, object]:
        result = self.run(["docker", "ps", "--format", "{{.Names}}|{{.Status}}|{{.Image}}", "--no-trunc"],
                          command_label="docker_ps", check=False)
        containers: dict[str, str] = {}
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split("|", 2)
            if len(parts) >= 2:
                containers[parts[0]] = parts[1]
        return containers

    def get_container_status(self, container: str) -> dict[str, str]:
        result = self.run(
            ["docker", "inspect", "--format", "{{.Name}}|{{.Config.Image}}|{{.State.Status}}|{{.State.StartedAt}}", container],
            command_label="docker_inspect", check=False,
        )
        if result.ok:
            parts = result.stdout.strip().split("|", 3)
            if len(parts) >= 3:
                return {"name": container, "image": parts[1], "status": parts[2], "started_at": parts[3] if len(parts) > 3 else ""}
        return {"name": container, "status": "unknown"}

    def get_container_logs(self, container: str, lines: int = 100) -> str:
        result = self.run(
            ["docker", "logs", "--tail", str(lines), container],
            command_label="docker_logs", check=False,
        )
        return result.stdout

    def run_psql(self, container: str, host: str, port: int, user: str, db: str,
                 sql: str, password: str, timeout: int = 20) -> CommandResult:
        return self.run(
            ["docker", "exec", "-e", "PGPASSWORD", container, "psql",
             "-h", host, "-p", str(port), "-U", user, "-d", db,
             "-X", "-A", "-t", "-c", sql],
            env={"PGPASSWORD": password},
            command_label="postgres_psql_json",
            timeout=timeout,
            check=False,
        )

    def get_disk_usage(self) -> str:
        result = self.run(["df", "-P", "-h", "/"], command_label="disk_usage", check=False)
        return result.stdout

    def get_memory_usage(self) -> str:
        result = self.run(["free", "-m"], command_label="memory_usage", check=False)
        return result.stdout

    def get_uptime(self) -> str:
        result = self.run(["uptime", "-p"], command_label="uptime", check=False)
        return result.stdout

    def _run_local(self, args: Sequence[str | int], *, command_label: str,
                   env: Mapping[str, str] | None, timeout: int, check: bool) -> CommandResult:
        import os
        merged_env = None
        if env:
            merged_env = os.environ.copy()
            merged_env.update(env)
        completed = subprocess.run(
            [str(arg) for arg in args],
            capture_output=True, text=True,
            timeout=timeout, check=False,
            env=merged_env,
        )
        return CommandResult(
            command_label=command_label,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    def _run_ssh(self, args: Sequence[str | int], *, command_label: str,
                 env: Mapping[str, str] | None, timeout: int, check: bool) -> CommandResult:
        import shlex
        import paramiko
        import time

        srv = self.server
        if srv is None:
            raise RuntimeError("no server configured for SSH connection")
        client = paramiko.SSHClient()
        hosts_path = load_host_keys(client)
        client.set_missing_host_key_policy(PersistentTOFUPolicy(hosts_path))
        try:
            key_path = None
            if srv.ssh_private_key:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False, prefix="pgsentinel_key_") as f:
                    f.write(srv.ssh_private_key)
                    f.flush()
                    key_path = f.name
                import os as _os
                _os.chmod(key_path, 0o600)
            try:
                client.connect(
                    hostname=srv.host,
                    port=srv.ssh_port,
                    username=srv.ssh_username,
                    key_filename=key_path,
                    passphrase=srv.ssh_private_key_passphrase or None,
                    timeout=timeout,
                    banner_timeout=timeout,
                    auth_timeout=timeout,
                    look_for_keys=False,
                    allow_agent=False,
                )
            finally:
                if key_path:
                    import os as _os
                    try:
                        _os.unlink(key_path)
                    except OSError:
                        pass
            cmd = " ".join(shlex.quote(str(a)) for a in args)
            if env:
                prefix = " ".join(f"{shlex.quote(k)}={shlex.quote(v)}" for k, v in env.items())
                cmd = f"{prefix} {cmd}"
            stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout, get_pty=False)
            stdin.close()
            # Drain stdout/stderr concurrently to avoid channel backpressure and read timeouts.
            chan = stdout.channel
            out_chunks: list[bytes] = []
            err_chunks: list[bytes] = []
            deadline = time.monotonic() + timeout
            while True:
                if chan.recv_ready():
                    out_chunks.append(chan.recv(65535))
                if chan.recv_stderr_ready():
                    err_chunks.append(chan.recv_stderr(65535))
                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break
                if time.monotonic() >= deadline:
                    chan.close()
                    raise TimeoutError(f"{command_label} timed out after {timeout}s")
                time.sleep(0.02)
            exit_code = chan.recv_exit_status()
            out_text = b"".join(out_chunks).decode("utf-8", errors="replace")
            err_text = b"".join(err_chunks).decode("utf-8", errors="replace")
            result = CommandResult(
                command_label=command_label,
                exit_code=exit_code,
                stdout=out_text,
                stderr=err_text,
            )
        finally:
            client.close()
        if check and not result.ok:
            raise RuntimeError(f"{command_label} failed with exit code {result.exit_code}: {result.stderr or result.stdout}")
        return result
