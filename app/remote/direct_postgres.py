from __future__ import annotations

import json
import os
import select
import socket
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from app.core.vault import PostgresTargetDef, ServerDef
from app.remote.connection import CommandResult
from app.remote.hostkeys import load_host_keys, PersistentTOFUPolicy


DIRECT_POSTGRES_MODES = {"postgres_direct_tcp", "postgres_direct_tls", "ssh_tunnel_direct_postgres"}


class DirectPostgresClient:
    def __init__(self, target: PostgresTargetDef, server: ServerDef | None = None, timeout: int = 20):
        self.target = target
        self.server = server
        self.timeout = timeout

    def run_json_sql(self, sql: str) -> CommandResult:
        try:
            if self.target.connection_mode == "ssh_tunnel_direct_postgres":
                return self._run_via_ssh_tunnel(sql)
            return self._run_direct(sql)
        except Exception as exc:
            return CommandResult(
                command_label="postgres_psycopg_json",
                exit_code=1,
                stdout="",
                stderr=str(exc),
            )

    def _run_direct(self, sql: str) -> CommandResult:
        with self._ssl_files() as ssl_kwargs:
            rows = self._fetch_json_lines(
                sql,
                host=self.target.host or "127.0.0.1",
                port=self.target.port,
                ssl_kwargs=ssl_kwargs,
            )
        return CommandResult("postgres_psycopg_json", 0, "\n".join(rows), "")

    def _run_via_ssh_tunnel(self, sql: str) -> CommandResult:
        if self.server is None:
            raise RuntimeError("ssh_tunnel_direct_postgres requires a linked server")
        remote_host = self.target.host or "127.0.0.1"
        remote_port = self.target.port
        with self._ssh_client() as ssh_client:
            transport = ssh_client.get_transport()
            if transport is None or not transport.is_active():
                raise RuntimeError("SSH transport is not active")
            with _LocalForwarder(transport, remote_host, remote_port, self.timeout) as forwarder:
                with self._ssl_files() as ssl_kwargs:
                    rows = self._fetch_json_lines(
                        sql,
                        host=forwarder.host,
                        port=forwarder.port,
                        ssl_kwargs=ssl_kwargs,
                    )
        return CommandResult("postgres_psycopg_json", 0, "\n".join(rows), "")

    def _fetch_json_lines(self, sql: str, *, host: str, port: int, ssl_kwargs: dict[str, str]) -> list[str]:
        import psycopg

        kwargs = {
            "host": host,
            "port": port,
            "dbname": self.target.database_name or "postgres",
            "user": self.target.readonly_username,
            "password": self.target.readonly_password,
            "connect_timeout": self.timeout,
            "options": f"-c statement_timeout={max(1, self.timeout) * 1000}",
            "sslmode": self._ssl_mode(),
            **ssl_kwargs,
        }
        with psycopg.connect(**kwargs) as conn:
            with conn.cursor() as cur:
                cur.execute(sql)
                return [_json_line(row[0] if len(row) == 1 else row) for row in cur.fetchall()]

    def _ssl_mode(self) -> str:
        mode = (self.target.ssl_mode or "").strip()
        if self.target.connection_mode == "postgres_direct_tls":
            return mode if mode in {"require", "verify-ca", "verify-full"} else "require"
        return mode or "prefer"

    @contextmanager
    def _ssl_files(self) -> Iterator[dict[str, str]]:
        paths: list[Path] = []
        kwargs: dict[str, str] = {}
        try:
            if self.target.ca_cert.strip():
                kwargs["sslrootcert"] = _write_temp_secret(self.target.ca_cert, "ca", paths)
            if self.target.client_cert.strip():
                kwargs["sslcert"] = _write_temp_secret(self.target.client_cert, "cert", paths)
            if self.target.client_key.strip():
                kwargs["sslkey"] = _write_temp_secret(self.target.client_key, "key", paths, mode=0o600)
            yield kwargs
        finally:
            for path in paths:
                try:
                    path.unlink()
                except OSError:
                    pass

    @contextmanager
    def _ssh_client(self):
        import paramiko

        if self.server is None:
            raise RuntimeError("linked server is required for SSH tunnel")
        key_path: str | None = None
        client = paramiko.SSHClient()
        hosts_path = load_host_keys(client)
        client.set_missing_host_key_policy(PersistentTOFUPolicy(hosts_path))
        try:
            if self.server.ssh_private_key:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False, prefix="pgsentinel_key_") as handle:
                    handle.write(self.server.ssh_private_key)
                    key_path = handle.name
                os.chmod(key_path, 0o600)
            client.connect(
                hostname=self.server.host,
                port=self.server.ssh_port,
                username=self.server.ssh_username,
                key_filename=key_path,
                passphrase=self.server.ssh_private_key_passphrase or None,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            yield client
        finally:
            client.close()
            if key_path:
                try:
                    os.unlink(key_path)
                except OSError:
                    pass


class _LocalForwarder:
    def __init__(self, transport, remote_host: str, remote_port: int, timeout: int):
        self.transport = transport
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.timeout = timeout
        self.host = "127.0.0.1"
        self.port = 0
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._workers: list[threading.Thread] = []

    def __enter__(self) -> _LocalForwarder:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, 0))
        sock.listen(8)
        sock.settimeout(0.5)
        self._sock = sock
        self.port = sock.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1)
        for worker in self._workers:
            worker.join(timeout=1)

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                client, client_addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=self._handle_client, args=(client, client_addr), daemon=True)
            self._workers.append(worker)
            worker.start()

    def _handle_client(self, client: socket.socket, client_addr) -> None:
        channel = None
        try:
            channel = self.transport.open_channel(
                "direct-tcpip",
                (self.remote_host, self.remote_port),
                client_addr,
                timeout=self.timeout,
            )
            _bridge(client, channel, self._stop)
        finally:
            try:
                client.close()
            except OSError:
                pass
            if channel is not None:
                channel.close()


def _bridge(client: socket.socket, channel, stop: threading.Event) -> None:
    sockets = [client, channel]
    while not stop.is_set():
        readable, _, _ = select.select(sockets, [], [], 0.5)
        if not readable:
            continue
        for stream in readable:
            data = stream.recv(32768)
            if not data:
                return
            if stream is client:
                channel.sendall(data)
            else:
                client.sendall(data)


def _write_temp_secret(value: str, label: str, paths: list[Path], mode: int = 0o600) -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=f".{label}.pem", delete=False, prefix="pgsentinel_pg_") as handle:
        handle.write(value)
        path = Path(handle.name)
    os.chmod(path, mode)
    paths.append(path)
    return str(path)


def _json_line(value) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, default=str)
