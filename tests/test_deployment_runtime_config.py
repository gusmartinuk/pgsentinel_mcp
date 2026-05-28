from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_entrypoint_repairs_bind_mount_permissions_before_dropping_privileges():
    entrypoint = (ROOT / "docker" / "app" / "entrypoint.sh").read_text(encoding="utf-8")

    assert 'chown -R "$RUN_AS_USER:$RUN_AS_USER" "$VAULT_DIR" /var/log/pgsentinel' in entrypoint
    assert 'touch "$AUDIT_LOG" "$SERVER_LOG"' in entrypoint
    assert 'exec gosu "$RUN_AS_USER" uvicorn' in entrypoint


def test_compose_does_not_force_non_root_entrypoint_user():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert "PGSENTINEL_CONTAINER_USER" not in compose
    assert "user:" not in compose


def test_dockerfile_keeps_entrypoint_root_and_uses_gosu_drop():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "gosu" in dockerfile
    assert "\nUSER app\n" not in dockerfile
