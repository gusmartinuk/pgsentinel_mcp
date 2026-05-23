from __future__ import annotations

import os
import secrets
import threading
import time
from typing import Any
from pathlib import Path

from app.core.vault import Vault, VaultData, VaultError


DEFAULT_VAULT_PATH = os.environ.get("PGSENTINEL_VAULT", "/secure/pgsentinel/vault.enc")
DEFAULT_VAULT_DIR = os.environ.get("PGSENTINEL_VAULT_DIR", "")

_lock = threading.Lock()
_vault: Vault | None = None
_sessions: dict[str, dict[str, Any]] = {}
_auto_lock_thread: threading.Thread | None = None
_auto_lock_stop: threading.Event | None = None


def get_vault() -> Vault:
    global _vault
    current_path = _resolve_current_vault_path()
    if _vault is not None:
        existing_path = getattr(_vault, '_vault_path', None)
        if existing_path != current_path:
            _vault = None
    if _vault is None:
        with _lock:
            if _vault is None:
                _vault = Vault(current_path)
                if _vault.exists():
                    _vault.load_encrypted()
    return _vault


def reset_vault() -> None:
    global _vault, _sessions
    _stop_auto_lock_timer()
    with _lock:
        _vault = None
        _sessions.clear()


def vault_exists() -> bool:
    return get_vault().exists()


def vault_is_locked() -> bool:
    return get_vault().is_locked


def vault_is_unlocked() -> bool:
    return get_vault().is_unlocked


def unlock_vault(master_password: str) -> None:
    v = get_vault()
    v.unlock(master_password)
    v.touch()
    _start_auto_lock_timer()


def lock_vault() -> None:
    v = get_vault()
    v.lock()
    _clear_all_sessions()
    _stop_auto_lock_timer()


def create_vault(master_password: str, agent_enabled: bool = True) -> str:
    v = get_vault()
    if v.exists():
        raise VaultError("vault already exists")
    agent_key = v.create(master_password, agent_enabled=agent_enabled)
    _write_vault_marker(v.path)
    v.unlock(master_password)
    _start_auto_lock_timer()
    return agent_key


def create_named_vault(name: str, master_password: str, agent_enabled: bool = True) -> str:
    _ensure_multi_vault_enabled()
    normalized = _normalize_vault_name(name)
    path = _vault_path_for_name(normalized)
    if path.exists():
        raise VaultError(f"vault '{normalized}' already exists")
    _set_active_vault_name(normalized)
    reset_vault()
    return create_vault(master_password, agent_enabled=agent_enabled)


def get_vault_data() -> VaultData:
    v = get_vault()
    if v.is_locked:
        raise VaultError("vault is locked")
    v.touch()
    return v.data


def save_vault(master_password: str | None = None) -> None:
    v = get_vault()
    if v.is_locked:
        raise VaultError("vault is locked, cannot save")
    v.save(master_password)


def get_active_vault_name() -> str:
    if _get_vault_dir() is None:
        p = Path(_resolve_current_vault_path())
        return p.stem.replace(".vault", "")
    return _read_active_vault_name() or "default"


def switch_active_vault(name: str) -> str:
    _ensure_multi_vault_enabled()
    normalized = _normalize_vault_name(name)
    path = _vault_path_for_name(normalized)
    if not path.exists():
        raise VaultError(f"vault '{normalized}' not found")
    _set_active_vault_name(normalized)
    reset_vault()
    return normalized


def list_vaults() -> list[dict[str, object]]:
    vault_dir = _get_vault_dir()
    if vault_dir is None:
        path = Path(_resolve_current_vault_path())
        item = _vault_stat_item("default", path, True)
        return [item]
    vault_dir.mkdir(parents=True, exist_ok=True)
    active = get_active_vault_name()
    items: list[dict[str, object]] = []
    for path in sorted(vault_dir.glob("*.vault.enc")):
        name = path.name[:-len(".vault.enc")]
        items.append(_vault_stat_item(name, path, name == active))
    if not items:
        items.append(_vault_stat_item(active, _vault_path_for_name(active), True))
    return items


def import_vault_bytes(name: str, content: bytes, *, activate: bool = True, overwrite: bool = False) -> str:
    _ensure_multi_vault_enabled()
    normalized = _normalize_vault_name(name)
    path = _vault_path_for_name(normalized)
    if path.exists() and not overwrite:
        raise VaultError(f"vault '{normalized}' already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with open(tmp_path, "wb") as f:
        f.write(content)
    os.replace(tmp_path, path)
    if activate:
        _set_active_vault_name(normalized)
        reset_vault()
    return normalized


def export_vault_bytes(name: str | None = None) -> tuple[str, bytes]:
    if name:
        normalized = _normalize_vault_name(name)
    else:
        normalized = get_active_vault_name()
    path = _vault_path_for_name(normalized) if _get_vault_dir() is not None else Path(_resolve_current_vault_path())
    if not path.exists():
        raise VaultError(f"vault '{normalized}' not found")
    return normalized, path.read_bytes()


def create_session() -> str:
    session_id = secrets.token_urlsafe(48)
    with _lock:
        _sessions[session_id] = {"created_at": time.monotonic()}
    return session_id


def get_session(session_id: str) -> dict[str, Any] | None:
    with _lock:
        return _sessions.get(session_id)


def destroy_session(session_id: str) -> None:
    with _lock:
        _sessions.pop(session_id, None)


def _clear_all_sessions() -> None:
    with _lock:
        _sessions.clear()


def _start_auto_lock_timer() -> None:
    global _auto_lock_thread, _auto_lock_stop
    _stop_auto_lock_timer()
    _auto_lock_stop = threading.Event()
    _auto_lock_thread = threading.Thread(target=_auto_lock_loop, daemon=True)
    _auto_lock_thread.start()


def _stop_auto_lock_timer() -> None:
    global _auto_lock_thread, _auto_lock_stop
    if _auto_lock_stop is not None:
        _auto_lock_stop.set()
    _auto_lock_thread = None
    _auto_lock_stop = None


def _auto_lock_loop() -> None:
    while True:
        stop = _auto_lock_stop
        if stop is None:
            break
        if stop.wait(30):
            break
        v = get_vault()
        if v.is_locked:
            continue
        try:
            timeout_minutes = v.data.settings.auto_lock_minutes
        except VaultError:
            continue
        elapsed = (time.monotonic() - v.last_activity) / 60
        if elapsed >= timeout_minutes:
            v.lock()
            _clear_all_sessions()
        if _auto_lock_stop is None:
            break


def _write_vault_marker(vault_path: str) -> None:
    marker_path = os.environ.get("PGSENTINEL_VAULT_MARKER")
    if not marker_path:
        marker_path = os.path.join(os.path.dirname(vault_path), ".vault_initialized")
    try:
        os.makedirs(os.path.dirname(marker_path), exist_ok=True)
        with open(marker_path, "w", encoding="utf-8") as f:
            f.write(f"{time.time():.0f}\n")
    except OSError:
        # Marker hardening should not block setup if filesystem policy disallows write.
        pass


def _resolve_current_vault_path() -> str:
    vault_dir = _get_vault_dir()
    if vault_dir is None:
        return os.environ.get("PGSENTINEL_VAULT", DEFAULT_VAULT_PATH)
    vault_dir.mkdir(parents=True, exist_ok=True)
    active = _read_active_vault_name() or "default"
    return str(_vault_path_for_name(active))


def _get_vault_dir() -> Path | None:
    value = os.environ.get("PGSENTINEL_VAULT_DIR", DEFAULT_VAULT_DIR).strip()
    if not value:
        return None
    return Path(value)


def _active_vault_file() -> Path:
    vault_dir = _get_vault_dir()
    if vault_dir is None:
        raise VaultError("multi-vault mode is not enabled")
    configured = os.environ.get("PGSENTINEL_ACTIVE_VAULT_FILE", "").strip()
    if configured:
        return Path(configured)
    return vault_dir / ".active_vault"


def _read_active_vault_name() -> str | None:
    path = _active_vault_file()
    if not path.exists():
        return None
    value = path.read_text(encoding="utf-8").strip()
    return _normalize_vault_name(value) if value else None


def _set_active_vault_name(name: str) -> None:
    normalized = _normalize_vault_name(name)
    path = _active_vault_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(normalized + "\n", encoding="utf-8")


def _vault_path_for_name(name: str) -> Path:
    vault_dir = _get_vault_dir()
    if vault_dir is None:
        return Path(os.environ.get("PGSENTINEL_VAULT", DEFAULT_VAULT_PATH))
    normalized = _normalize_vault_name(name)
    return vault_dir / f"{normalized}.vault.enc"


def _normalize_vault_name(name: str) -> str:
    clean = name.strip().lower().replace(" ", "-")
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789-_"
    clean = "".join(ch for ch in clean if ch in allowed)
    if not clean:
        raise VaultError("vault name is invalid")
    return clean


def _ensure_multi_vault_enabled() -> None:
    if _get_vault_dir() is None:
        raise VaultError("multi-vault mode is disabled; set PGSENTINEL_VAULT_DIR")


def _vault_stat_item(name: str, path: Path, active: bool) -> dict[str, object]:
    exists = path.exists()
    size = path.stat().st_size if exists else 0
    mtime = path.stat().st_mtime if exists else 0.0
    return {
        "name": name,
        "path": str(path),
        "active": active,
        "exists": exists,
        "size": size,
        "mtime": mtime,
    }
