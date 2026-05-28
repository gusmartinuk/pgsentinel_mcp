from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
from typing import Any
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.vault import Vault, VaultData, VaultError


DEFAULT_VAULT_PATH = os.environ.get("PGSENTINEL_VAULT", "/secure/pgsentinel/vault.enc")
DEFAULT_VAULT_DIR = os.environ.get("PGSENTINEL_VAULT_DIR", "")
DEFAULT_VAULT_CODE = "default1"

_lock = threading.Lock()
_vault: Vault | None = None
_sessions: dict[str, dict[str, Any]] = {}
_auto_lock_thread: threading.Thread | None = None
_auto_lock_stop: threading.Event | None = None
_runtime_master_password: str | None = None
_pending_recovery_key: str | None = None


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
    global _vault, _sessions, _runtime_master_password, _pending_recovery_key
    _stop_auto_lock_timer()
    with _lock:
        _vault = None
        _sessions.clear()
        _runtime_master_password = None
        _pending_recovery_key = None


def _reset_active_vault_only() -> None:
    # Drop the cached vault object so the newly-selected active path loads, but
    # keep admin sessions and the in-memory master password — switching which
    # definition is active must not log the operator out or force a re-unlock.
    global _vault
    _stop_auto_lock_timer()
    with _lock:
        _vault = None


def vault_exists() -> bool:
    return get_vault().exists()


def any_vault_files_exist() -> bool:
    for vault_dir in _vault_search_dirs():
        try:
            if any(vault_dir.glob("*.vault.enc")):
                return True
            if (vault_dir / ".vault_initialized").exists():
                return True
        except OSError:
            pass
    for path in _vault_search_files():
        try:
            if path.exists():
                return True
        except OSError:
            pass
    return False


def vault_is_locked() -> bool:
    return get_vault().is_locked


def vault_is_unlocked() -> bool:
    return get_vault().is_unlocked


def unlock_vault(master_password: str) -> None:
    global _runtime_master_password
    v = get_vault()
    v.unlock(master_password)
    v.touch()
    _runtime_master_password = master_password
    _start_auto_lock_timer()


def lock_vault() -> None:
    global _runtime_master_password
    v = get_vault()
    v.lock()
    _clear_all_sessions()
    _stop_auto_lock_timer()
    _runtime_master_password = None


def try_auto_unlock() -> bool:
    v = get_vault()
    if v.is_unlocked:
        return True
    master = _runtime_master_password or _master_password_from_env_or_file()
    if not master:
        return False
    try:
        unlock_vault(master)
        return True
    except VaultError:
        return False


def create_vault(master_password: str, agent_enabled: bool = True,
                 shared_agent: tuple[str, str] | None = None) -> str:
    global _runtime_master_password, _pending_recovery_key
    v = get_vault()
    if v.exists():
        raise VaultError("vault already exists")
    agent_key = v.create(master_password, agent_enabled=agent_enabled)
    if shared_agent is not None:
        # Adopt the existing shared agent key instead of the freshly minted one,
        # so a single key + profile_code reaches every definition.
        key_hash, expires_at = shared_agent
        v.data.agent.key_hash = key_hash
        v.data.agent.enabled = True
        v.data.agent.expires_at = expires_at
        v.save()
        agent_key = ""
    _write_vault_marker(v.path)
    v.unlock(master_password)
    _runtime_master_password = master_password
    try:
        _pending_recovery_key = _write_recovery_bundle(v.path, master_password)
    except OSError as exc:
        raise VaultError(f"failed to persist recovery bundle: {exc}") from exc
    _start_auto_lock_timer()
    return agent_key


def ensure_profile_active_and_unlocked(name: str) -> str:
    normalized = _normalize_vault_name(name)
    current = get_active_vault_name()
    if current != normalized:
        switch_active_vault(normalized)
    v = get_vault()
    if v.is_locked:
        master = _runtime_master_password or _master_password_from_env_or_file()
        if not master:
            raise VaultError("vault is locked")
        v.unlock(master)
        globals()["_runtime_master_password"] = master
        v.touch()
        _start_auto_lock_timer()
    return normalized


def create_named_vault(name: str, master_password: str | None, agent_enabled: bool = True) -> str:
    if not master_password:
        if not _runtime_master_password:
            raise VaultError("master password required")
        master_password = _runtime_master_password
    _ensure_multi_vault_enabled()
    normalized = _normalize_vault_name(name)
    path = _vault_path_for_name(normalized)
    if path.exists():
        raise VaultError(f"vault '{normalized}' already exists")
    shared_agent = _current_shared_agent()
    _set_active_vault_name(normalized)
    _reset_active_vault_only()
    return create_vault(master_password, agent_enabled=agent_enabled, shared_agent=shared_agent)


def _current_shared_agent() -> tuple[str, str] | None:
    try:
        v = get_vault()
        if v.is_unlocked and v.data.agent.key_hash:
            return (v.data.agent.key_hash, v.data.agent.expires_at)
    except VaultError:
        pass
    return None


def _apply_to_all_definitions(mutate) -> int:
    # Apply a mutation to every definition's AgentConfig (shared key model).
    if _get_vault_dir() is None:
        # Single-vault (legacy) mode: only the one active vault exists.
        v = get_vault()
        if v.is_locked:
            raise VaultError("vault is locked, cannot save")
        mutate(v.data.agent)
        v.save()
        return 1
    master = _runtime_master_password or _master_password_from_env_or_file()
    if not master:
        raise VaultError("master password required to update definitions")
    original = get_active_vault_name()
    names = [str(item["name"]) for item in list_vaults() if item["exists"]]
    count = 0
    for name in names:
        switch_active_vault(name)
        v = get_vault()
        if v.is_locked:
            try:
                v.unlock(master)
            except VaultError:
                continue
        mutate(v.data.agent)
        v.save()
        count += 1
    if original:
        switch_active_vault(original)
        try:
            get_vault().unlock(master)
        except VaultError:
            pass
        globals()["_runtime_master_password"] = master
        _start_auto_lock_timer()
    return count


def set_shared_agent_key(key_hash: str, last_rotated: str, expires_at: str) -> int:
    def mutate(agent: Any) -> None:
        agent.key_hash = key_hash
        agent.enabled = True
        agent.last_rotated = last_rotated
        agent.expires_at = expires_at
    return _apply_to_all_definitions(mutate)


def set_shared_agent_enabled(enabled: bool) -> int:
    def mutate(agent: Any) -> None:
        agent.enabled = enabled
    return _apply_to_all_definitions(mutate)


def consume_pending_recovery_key() -> str:
    global _pending_recovery_key
    key = _pending_recovery_key or ""
    _pending_recovery_key = None
    return key


def reset_master_password_with_recovery(recovery_key: str, new_master_password: str) -> str:
    global _runtime_master_password, _pending_recovery_key
    v = get_vault()
    if not v.exists():
        raise VaultError("vault file not found")
    recovered_master = _recover_master_password(v.path, recovery_key)
    if v.is_locked:
        v.unlock(recovered_master)
    v.save(master_password=new_master_password)
    _runtime_master_password = new_master_password
    try:
        _pending_recovery_key = _write_recovery_bundle(v.path, new_master_password)
    except OSError as exc:
        raise VaultError(f"failed to rotate recovery bundle: {exc}") from exc
    _start_auto_lock_timer()
    return _pending_recovery_key


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
    return _read_active_vault_name() or DEFAULT_VAULT_CODE


def switch_active_vault(name: str) -> str:
    _ensure_multi_vault_enabled()
    normalized = _normalize_vault_name(name)
    path = _vault_path_for_name(normalized)
    if not path.exists():
        raise VaultError(f"vault '{normalized}' not found")
    _set_active_vault_name(normalized)
    _reset_active_vault_only()
    return normalized


def list_vaults() -> list[dict[str, object]]:
    vault_dir = _get_vault_dir()
    if vault_dir is None:
        discovered = _discover_existing_vault_dir()
        if discovered is None:
            path = Path(_resolve_current_vault_path())
            item = _vault_stat_item("default", path, True)
            return [item]
        vault_dir = discovered
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
    active = _read_active_vault_name() or DEFAULT_VAULT_CODE
    return str(_vault_path_for_name(active))


def _master_password_from_env_or_file() -> str:
    direct = os.environ.get("PGSENTINEL_MASTER_PASSWORD", "").strip()
    if direct:
        return direct
    file_path = os.environ.get("PGSENTINEL_MASTER_PASSWORD_FILE", "").strip()
    if file_path and os.path.exists(file_path):
        try:
            return Path(file_path).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return ""


def _vault_search_dirs() -> list[Path]:
    candidates: list[Path] = []
    configured = _get_vault_dir()
    if configured is not None:
        candidates.append(configured)
    legacy_parent = Path(os.environ.get("PGSENTINEL_VAULT", DEFAULT_VAULT_PATH)).parent
    candidates.append(legacy_parent / "vaults")
    candidates.append(Path("/secure/pgsentinel/vaults"))
    seen: set[str] = set()
    unique: list[Path] = []
    for path in candidates:
        key = str(path)
        if key not in seen:
            unique.append(path)
            seen.add(key)
    return unique


def _vault_search_files() -> list[Path]:
    legacy_path = Path(os.environ.get("PGSENTINEL_VAULT", DEFAULT_VAULT_PATH))
    files = [
        legacy_path,
        legacy_path.parent / ".vault_initialized",
        legacy_path.parent / "vaults" / ".vault_initialized",
        Path("/secure/pgsentinel/.vault_initialized"),
        Path("/secure/pgsentinel/vaults/.vault_initialized"),
    ]
    seen: set[str] = set()
    unique: list[Path] = []
    for path in files:
        key = str(path)
        if key not in seen:
            unique.append(path)
            seen.add(key)
    return unique


def _discover_existing_vault_dir() -> Path | None:
    for vault_dir in _vault_search_dirs():
        try:
            if any(vault_dir.glob("*.vault.enc")):
                return vault_dir
        except OSError:
            continue
    return None


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
    if not value:
        return None
    # Backward-compatible read path: legacy names should not crash routing.
    normalized = _normalize_vault_name(value, strict=False)
    return normalized or None


def _set_active_vault_name(name: str) -> None:
    normalized = _normalize_vault_name(name)
    path = _active_vault_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(normalized + "\n", encoding="utf-8")


def _vault_path_for_name(name: str) -> Path:
    vault_dir = _get_vault_dir()
    if vault_dir is None:
        return Path(os.environ.get("PGSENTINEL_VAULT", DEFAULT_VAULT_PATH))
    normalized = _normalize_vault_name(name, strict=False)
    if not normalized:
        normalized = DEFAULT_VAULT_CODE
    return vault_dir / f"{normalized}.vault.enc"


def _normalize_vault_name(name: str, strict: bool = True) -> str:
    clean = "".join(ch for ch in name.strip().lower() if ch.isalnum())
    if not strict:
        return clean
    if len(clean) != 8:
        raise VaultError("vault code must be exactly 8 alphanumeric characters")
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


def _recovery_path_for_vault(vault_path: str) -> str:
    return vault_path + ".recovery"


def _write_recovery_bundle(vault_path: str, master_password: str) -> str:
    recovery_key = "pgs_rec_" + secrets.token_urlsafe(36)
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = hashlib.scrypt(recovery_key.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    ciphertext = AESGCM(key).encrypt(nonce, master_password.encode("utf-8"), None)
    bundle = {
        "kdf": "scrypt",
        "cipher": "aes-256-gcm",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    out_path = _recovery_path_for_vault(vault_path)
    tmp = out_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    os.replace(tmp, out_path)
    return recovery_key


def _recover_master_password(vault_path: str, recovery_key: str) -> str:
    path = _recovery_path_for_vault(vault_path)
    if not os.path.exists(path):
        raise VaultError("recovery bundle not found")
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    salt = base64.b64decode(bundle["salt"])
    nonce = base64.b64decode(bundle["nonce"])
    ciphertext = base64.b64decode(bundle["ciphertext"])
    key = hashlib.scrypt(recovery_key.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise VaultError("invalid recovery key") from exc
    return plaintext.decode("utf-8")
