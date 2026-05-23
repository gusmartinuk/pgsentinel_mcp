import types

from app.core.vault import PostgresTargetDef
from app.remote.direct_postgres import DirectPostgresClient


class FakeCursor:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def execute(self, sql):
        self.calls.append(("execute", sql))

    def fetchall(self):
        return [({"ok": True},), ("plain",)]


class FakeConnection:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def cursor(self):
        return FakeCursor(self.calls)


def test_direct_postgres_client_uses_psycopg(monkeypatch):
    calls = []

    def connect(**kwargs):
        calls.append(("connect", kwargs))
        return FakeConnection(calls)

    monkeypatch.setitem(__import__("sys").modules, "psycopg", types.SimpleNamespace(connect=connect))

    target = PostgresTargetDef(
        id="pg",
        name="Direct",
        connection_mode="postgres_direct_tcp",
        host="db.internal",
        port=15432,
        database_name="appdb",
        readonly_username="reader",
        readonly_password="secret",
    )

    result = DirectPostgresClient(target, timeout=9).run_json_sql("SELECT json_build_object('ok', true)")

    assert result.ok
    assert result.stdout.splitlines() == ['{"ok": true}', "plain"]
    assert calls[0] == (
        "connect",
        {
            "host": "db.internal",
            "port": 15432,
            "dbname": "appdb",
            "user": "reader",
            "password": "secret",
            "connect_timeout": 9,
            "options": "-c statement_timeout=9000",
            "sslmode": "prefer",
        },
    )


def test_direct_postgres_tls_requires_ssl(monkeypatch):
    calls = []

    def connect(**kwargs):
        calls.append(kwargs)
        return FakeConnection([])

    monkeypatch.setitem(__import__("sys").modules, "psycopg", types.SimpleNamespace(connect=connect))

    target = PostgresTargetDef(
        id="pg",
        name="TLS",
        connection_mode="postgres_direct_tls",
        host="db.internal",
        database_name="appdb",
        readonly_username="reader",
        readonly_password="secret",
        ssl_mode="prefer",
    )

    result = DirectPostgresClient(target).run_json_sql("SELECT json_build_object('ok', true)")

    assert result.ok
    assert calls[0]["sslmode"] == "require"
