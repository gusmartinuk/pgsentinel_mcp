from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from app.core.config import PgSentinelConfig
from app.core.errors import RemoteCommandError
from app.core.masking import mask_text
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


class RemoteSSHClient:
    def __init__(self, config: PgSentinelConfig):
        self.config = config

    def test_connection(self) -> bool:
        if self.config.server.mode == "local":
            result = self.run(["docker", "version", "--format", "{{.Server.Version}}"], command_label="local_docker_connectivity", check=False)
            return result.ok
        result = self.run(["true"], command_label="ssh_connectivity", check=False)
        return result.ok

    def run(
        self,
        args: Sequence[str | int],
        *,
        command_label: str,
        env: Mapping[str, str] | None = None,
        timeout: int | None = None,
        check: bool = True,
    ) -> CommandResult:
        import time
        if self.config.server.mode == "local":
            return self._run_local(args, command_label=command_label, env=env, timeout=timeout, check=check)
        command = self._build_command(args, env)
        client = self._connect()
        try:
            stdin, stdout, stderr = client.exec_command(
                command,
                timeout=timeout or self.config.security.command_timeout_seconds,
                get_pty=False,
            )
            stdin.close()
            # Drain stdout/stderr concurrently to avoid channel backpressure and read timeouts.
            chan = stdout.channel
            out_chunks: list[bytes] = []
            err_chunks: list[bytes] = []
            limit = timeout or self.config.security.command_timeout_seconds
            deadline = time.monotonic() + limit
            while True:
                if chan.recv_ready():
                    out_chunks.append(chan.recv(65535))
                if chan.recv_stderr_ready():
                    err_chunks.append(chan.recv_stderr(65535))
                if chan.exit_status_ready() and not chan.recv_ready() and not chan.recv_stderr_ready():
                    break
                if time.monotonic() >= deadline:
                    chan.close()
                    raise TimeoutError(f"{command_label} timed out after {limit}s")
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
            patterns = self.config.masking.patterns
            raise RemoteCommandError(
                f"{command_label} failed with exit code {result.exit_code}: "
                f"{mask_text(result.stderr or result.stdout, patterns).strip()}"
            )
        return result

    def _connect(self) -> Any:
        import paramiko

        server = self.config.server
        client = paramiko.SSHClient()
        hosts_path = load_host_keys(client)
        client.set_missing_host_key_policy(PersistentTOFUPolicy(hosts_path))
        try:
            client.connect(
                hostname=server.host or "",
                port=server.port,
                username=server.username or "",
                key_filename=server.ssh_private_key_path,
                passphrase=server.ssh_private_key_passphrase,
                timeout=self.config.security.command_timeout_seconds,
                banner_timeout=self.config.security.command_timeout_seconds,
                auth_timeout=self.config.security.command_timeout_seconds,
                look_for_keys=False,
                allow_agent=False,
            )
        except Exception:
            client.close()
            raise
        return client

    def _run_local(
        self,
        args: Sequence[str | int],
        *,
        command_label: str,
        env: Mapping[str, str] | None,
        timeout: int | None,
        check: bool,
    ) -> CommandResult:
        merged_env = None
        if env:
            import os

            merged_env = os.environ.copy()
            merged_env.update(env)
        completed = subprocess.run(
            [str(arg) for arg in args],
            capture_output=True,
            text=True,
            timeout=timeout or self.config.security.command_timeout_seconds,
            check=False,
            env=merged_env,
        )
        result = CommandResult(
            command_label=command_label,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        if check and not result.ok:
            patterns = self.config.masking.patterns
            raise RemoteCommandError(
                f"{command_label} failed with exit code {result.exit_code}: "
                f"{mask_text(result.stderr or result.stdout, patterns).strip()}"
            )
        return result

    @staticmethod
    def _build_command(args: Sequence[str | int], env: Mapping[str, str] | None = None) -> str:
        command = " ".join(shlex.quote(str(arg)) for arg in args)
        if not env:
            return command
        prefix = " ".join(f"{shlex.quote(key)}={shlex.quote(value)}" for key, value in env.items())
        return f"{prefix} {command}"
