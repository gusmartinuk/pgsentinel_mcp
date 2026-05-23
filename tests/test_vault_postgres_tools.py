from app.core.vault import PostgresTargetDef, ServerDef
from app.remote.connection import CommandResult
from app.tools.postgres import get_postgres_health


def test_vault_postgres_target_uses_linked_server(monkeypatch):
    calls = []
    server = ServerDef(id="srv-1", name="VPS", connection_mode="ssh")

    class FakeAdapter:
        def __init__(self, server=None, pg_target=None):
            calls.append((server, pg_target))

        def run_psql(self, **kwargs):
            return CommandResult(
                command_label="postgres_psql_json",
                exit_code=0,
                stdout='{"ok": true}\n',
                stderr="",
            )

    monkeypatch.setattr("app.tools.postgres._server_for_target", lambda target: server)
    monkeypatch.setattr("app.tools.postgres.ConnectionAdapter", FakeAdapter)

    target = PostgresTargetDef(
        id="pg-1",
        name="Main DB",
        server_id="srv-1",
        connection_mode="docker_exec_psql_over_ssh",
        container_name="postgres",
        database_name="appdb",
        readonly_username="reader",
        readonly_password="secret",
    )

    result = get_postgres_health(target=target)

    assert result["status"] == "ok"
    assert calls == [(server, target)]


def test_vault_postgres_direct_mode_uses_psycopg_client(monkeypatch):
    calls = []

    class FakeDirectClient:
        def __init__(self, target, server=None, timeout=20):
            calls.append((target, server, timeout))

        def run_json_sql(self, sql):
            return CommandResult(
                command_label="postgres_psycopg_json",
                exit_code=0,
                stdout='{"ok": true}\n',
                stderr="",
            )

    monkeypatch.setattr("app.tools.postgres.DirectPostgresClient", FakeDirectClient)
    monkeypatch.setattr("app.tools.postgres._command_timeout", lambda: 7)

    target = PostgresTargetDef(
        id="pg-1",
        name="Direct DB",
        connection_mode="postgres_direct_tcp",
        host="db.internal",
        database_name="appdb",
        readonly_username="reader",
        readonly_password="secret",
    )

    result = get_postgres_health(target=target)

    assert result["status"] == "ok"
    assert calls == [(target, None, 7)]
