from app.remote.log_reader import RemoteLogReader
from app.core.vault import ServerDef
from app.tools.logs import get_container_logs


class FakeDocker:
    def __init__(self):
        self.calls = []

    def logs(self, container, lines=None):
        self.calls.append((container, lines))
        return "\n".join(["ok", "ERROR password=secret", "Traceback TOKEN=abc"])


def test_recent_errors_clamps_to_configured_log_limit(config):
    docker = FakeDocker()
    reader = RemoteLogReader(docker, config)

    result = reader.get_recent_errors("app", limit=500)

    assert docker.calls == [("app", 80)]
    assert result["count"] == 2
    assert "secret" not in str(result)
    assert "abc" not in str(result)


def test_search_logs_rejects_unconfigured_log(config):
    docker = FakeDocker()
    reader = RemoteLogReader(docker, config)

    try:
        reader.search_logs("missing", "ERROR")
    except Exception as exc:
        assert "allowlisted" in str(exc)
    else:
        raise AssertionError("expected allowlist rejection")


def test_vault_log_access_respects_allowlists(monkeypatch):
    calls = []

    class FakeAdapter:
        def __init__(self, server):
            self.server = server

        def get_container_logs(self, container, lines=100):
            calls.append((self.server.id, container, lines))
            return "ok"

    monkeypatch.setattr("app.tools.logs.ConnectionAdapter", FakeAdapter)
    server = ServerDef(
        id="srv",
        name="Server",
        allowed_containers=["app"],
        allowed_log_sources=["app"],
    )

    assert get_container_logs("postgres", target=server)["error"] == "log source is not allowlisted: postgres"
    assert get_container_logs("app", target=server)["output"] == "ok"
    assert calls == [("srv", "app", 100)]
