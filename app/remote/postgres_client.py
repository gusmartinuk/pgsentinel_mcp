from __future__ import annotations

import json

from app.core.config import PgSentinelConfig
from app.core.masking import mask_data, mask_text
from app.core.security import (
    clamp_limit,
    ensure_allowed_container,
    ensure_allowed_table,
    first_allowed_schema,
    quote_identifier,
    validate_readonly_sql,
)
from app.remote.docker_client import RemoteDockerClient
from app.remote.ssh_client import RemoteSSHClient


class RemotePostgresClient:
    def __init__(self, ssh: RemoteSSHClient, docker: RemoteDockerClient, config: PgSentinelConfig):
        self.ssh = ssh
        self.docker = docker
        self.config = config

    def health(self) -> dict[str, str]:
        pg = self.config.postgres
        ensure_allowed_container(self.config, pg.container_name)
        container = self.docker.container_status(pg.container_name)
        ready = self.ssh.run(
            ["docker", "exec", pg.container_name, "pg_isready", "-U", pg.username, "-d", pg.database],
            command_label="postgres_pg_isready",
            check=False,
        )
        connection = self._psql_json_rows("SELECT json_build_object('ok', true)", check=False)
        ok = container.get("status") == "running" and ready.ok and bool(connection)
        return {
            "status": "ok" if ok else "warning",
            "database": pg.database,
            "postgres_container": container.get("status", "unknown"),
            "pg_isready": mask_text((ready.stdout or ready.stderr).strip(), self.config.masking.patterns),
            "connection_test": "ok" if connection else "failed",
        }

    def list_allowed_tables(self) -> dict[str, object]:
        return {
            "schemas": self.config.postgres.allowed_schemas,
            "tables": self.config.postgres.allowed_tables,
        }

    def describe_table(self, table: str) -> dict[str, object]:
        table = ensure_allowed_table(self.config, table)
        schema = first_allowed_schema(self.config)
        sql = """
            SELECT json_build_object(
                'name', column_name,
                'type', data_type,
                'nullable', is_nullable = 'YES'
            )
            FROM information_schema.columns
            WHERE table_schema = %s AND table_name = %s
            ORDER BY ordinal_position
        """
        rows = self._psql_json_rows(sql, variables=[schema, table])
        sensitive = set(self.config.postgres.sensitive_columns)
        columns = [
            column for column in rows
            if isinstance(column, dict) and column.get("name") not in sensitive
        ]
        return {"schema": schema, "table": table, "columns": columns}

    def sample_table(self, table: str, limit: int | None = None) -> dict[str, object]:
        table = ensure_allowed_table(self.config, table)
        schema = first_allowed_schema(self.config)
        row_limit = clamp_limit(limit, self.config.security.max_query_rows, min(20, self.config.security.max_query_rows))
        sql = (
            "SELECT row_to_json(t) "
            f"FROM (SELECT * FROM {quote_identifier(schema)}.{quote_identifier(table)} LIMIT {row_limit}) t"
        )
        rows = self._psql_json_rows(sql)
        return {
            "schema": schema,
            "table": table,
            "limit": row_limit,
            "rows": mask_data(rows, self.config.masking.patterns),
        }

    def query_readonly_sql(self, sql: str) -> dict[str, object]:
        if not self.config.security.allow_raw_sql:
            raise PermissionError("raw SQL tool is disabled by configuration")
        guarded = validate_readonly_sql(sql, self.config.postgres.allowed_tables, self.config.security.max_query_rows)
        rows = self._psql_json_rows(f"SELECT row_to_json(t) FROM ({guarded}) t")
        return {"rows": mask_data(rows, self.config.masking.patterns)}

    def _psql_json_rows(
        self,
        sql: str,
        *,
        variables: list[str] | None = None,
        check: bool = True,
    ) -> list[object]:
        pg = self.config.postgres
        ensure_allowed_container(self.config, pg.container_name)
        rendered = self._render_sql(sql, variables or [])
        result = self.ssh.run(
            [
                "docker",
                "exec",
                "-e",
                "PGPASSWORD",
                pg.container_name,
                "psql",
                "-h",
                pg.host_inside_container,
                "-p",
                pg.port_inside_container,
                "-U",
                pg.username,
                "-d",
                pg.database,
                "-X",
                "-A",
                "-t",
                "-c",
                rendered,
            ],
            env={"PGPASSWORD": pg.password},
            command_label="postgres_psql_json",
            check=check,
        )
        if not result.ok:
            return []
        rows: list[object] = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append(mask_text(line, self.config.masking.patterns))
        return rows

    @staticmethod
    def _render_sql(sql: str, variables: list[str]) -> str:
        rendered = sql
        for value in variables:
            escaped = value.replace("'", "''")
            rendered = rendered.replace("%s", f"'{escaped}'", 1)
        return " ".join(rendered.split())
