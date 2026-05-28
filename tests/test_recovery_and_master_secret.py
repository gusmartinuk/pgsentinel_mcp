from __future__ import annotations

from app.core.vault_manager import (
    consume_pending_recovery_key,
    create_vault,
    lock_vault,
    reset_vault,
    reset_master_password_with_recovery,
    try_auto_unlock,
    unlock_vault,
    vault_is_locked,
    vault_is_unlocked,
)


def test_recovery_key_can_reset_master_password(monkeypatch, tmp_path):
    monkeypatch.setenv("PGSENTINEL_VAULT", str(tmp_path / "vault.enc"))
    create_vault("old-password-123", agent_enabled=True)
    recovery = consume_pending_recovery_key()
    assert recovery.startswith("pgs_rec_")

    lock_vault()
    new_recovery = reset_master_password_with_recovery(recovery, "new-password-123")
    assert new_recovery.startswith("pgs_rec_")

    lock_vault()
    unlock_vault("new-password-123")
    assert vault_is_unlocked()


def test_master_password_file_unlocks_after_lock(monkeypatch, tmp_path):
    vault_dir = tmp_path / "vaults"
    vault_dir.mkdir(parents=True, exist_ok=True)
    active_file = vault_dir / ".active_vault"
    active_file.write_text("a1b2c3d4\n", encoding="utf-8")
    secret_file = tmp_path / "master.txt"
    secret_file.write_text("file-master-123\n", encoding="utf-8")
    monkeypatch.setenv("PGSENTINEL_VAULT_DIR", str(vault_dir))
    monkeypatch.setenv("PGSENTINEL_ACTIVE_VAULT_FILE", str(active_file))
    monkeypatch.setenv("PGSENTINEL_MASTER_PASSWORD_FILE", str(secret_file))
    create_vault("file-master-123", agent_enabled=True)
    lock_vault()
    from app.core.vault_manager import ensure_profile_active_and_unlocked
    ensure_profile_active_and_unlocked("a1b2c3d4")
    assert vault_is_unlocked()


def test_reset_vault_clears_runtime_master_password(monkeypatch, tmp_path):
    monkeypatch.setenv("PGSENTINEL_VAULT", str(tmp_path / "vault.enc"))
    create_vault("memory-only-master", agent_enabled=True)

    reset_vault()

    assert vault_is_locked()
    assert try_auto_unlock() is False
