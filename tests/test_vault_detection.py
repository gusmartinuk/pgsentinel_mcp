from __future__ import annotations

from app.core.vault_manager import any_vault_files_exist, reset_vault


def test_any_vault_files_exist_detects_multi_vault_files(monkeypatch, tmp_path):
    vault_dir = tmp_path / "vaults"
    vault_dir.mkdir()
    (vault_dir / "default1.vault.enc").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("PGSENTINEL_VAULT_DIR", str(vault_dir))
    reset_vault()

    assert any_vault_files_exist() is True


def test_any_vault_files_exist_detects_marker_without_active_vault(monkeypatch, tmp_path):
    vault_dir = tmp_path / "vaults"
    vault_dir.mkdir()
    (vault_dir / ".vault_initialized").write_text("1\n", encoding="utf-8")
    monkeypatch.setenv("PGSENTINEL_VAULT_DIR", str(vault_dir))
    reset_vault()

    assert any_vault_files_exist() is True
