from __future__ import annotations

import base64
import shutil
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field, asdict
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.masking import mask_text


VAULT_DATA_VERSION = 1
VAULT_ENVELOPE_VERSION = 2
KDF = "argon2id"
CIPHER = "aes-256-gcm"
SALT_BYTES = 32
NONCE_BYTES = 12


class VaultError(Exception):
    pass


@dataclass
class ServerDef:
    id: str
    name: str
    environment: str = "staging"
    connection_mode: str = "ssh"
    host: str = ""
    ssh_port: int = 22
    ssh_username: str = ""
    ssh_private_key: str = ""
    ssh_private_key_passphrase: str = ""
    allowed_containers: list[str] = field(default_factory=list)
    allowed_log_sources: list[str] = field(default_factory=list)
    allow_all_containers: bool = False
    enabled: bool = True
    notes: str = ""


@dataclass
class PostgresTargetDef:
    id: str
    name: str
    server_id: str = ""
    connection_mode: str = "docker_exec_psql_over_ssh"
    host: str = ""
    port: int = 5432
    container_name: str = ""
    database_name: str = ""
    readonly_username: str = ""
    readonly_password: str = ""
    ssl_mode: str = "prefer"
    ca_cert: str = ""
    client_cert: str = ""
    client_key: str = ""
    allowed_schemas: list[str] = field(default_factory=lambda: ["public"])
    allowed_tables: list[str] = field(default_factory=list)
    allow_all_tables: bool = False
    sql_query_enabled: bool = False
    sensitive_columns: list[str] = field(default_factory=lambda: [
        "password", "password_hash", "token", "secret",
        "api_key", "private_key", "access_token", "refresh_token",
    ])
    max_rows: int = 100
    enabled: bool = True
    notes: str = ""


@dataclass
class MonitoringTargetDef:
    id: str
    name: str
    environment: str = "staging"
    connection_mode: str = "https_api"
    base_url: str = ""
    api_token: str = ""
    tls_verify: bool = True
    ca_cert: str = ""
    allowed_operations: list[str] = field(default_factory=list)
    enabled: bool = True
    notes: str = ""


@dataclass
class AgentConfig:
    enabled: bool = False
    key_hash: str = ""
    last_rotated: str = ""
    expires_at: str = ""


@dataclass
class SecuritySettings:
    auto_lock_minutes: int = 30
    max_log_lines: int = 300
    max_query_rows: int = 100
    command_timeout_seconds: int = 20
    sql_policy_mode: str = "readonly_default"
    sql_allow_insert: bool = False
    sql_allow_update: bool = False
    sql_allow_delete: bool = False
    sql_allow_create: bool = False
    sql_allow_alter: bool = False
    sql_allow_drop: bool = False
    sql_allow_truncate: bool = False
    sql_allow_maintenance: bool = False
    sql_allow_privilege: bool = False
    sql_allow_transaction: bool = False
    sql_hard_max_query_rows: int = 1000


@dataclass
class VaultData:
    version: int = VAULT_DATA_VERSION
    servers: list[ServerDef] = field(default_factory=list)
    postgres_targets: list[PostgresTargetDef] = field(default_factory=list)
    monitoring_targets: list[MonitoringTargetDef] = field(default_factory=list)
    agent: AgentConfig = field(default_factory=AgentConfig)
    settings: SecuritySettings = field(default_factory=SecuritySettings)
    masking_patterns: list[str] = field(default_factory=lambda: [
        "password=", "PASSWORD=", "token=", "TOKEN=",
        "Authorization:", "Bearer ", "DB_PASSWORD=",
        "APP_KEY=", "SECRET=", "PRIVATE_KEY",
        "AWS_SECRET_ACCESS_KEY=", "DATABASE_URL=",
        "SECRET_KEY=", "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
    ])

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"version": self.version}
        data["servers"] = [asdict(s) for s in self.servers]
        data["postgres_targets"] = [asdict(p) for p in self.postgres_targets]
        data["monitoring_targets"] = [asdict(m) for m in self.monitoring_targets]
        data["agent"] = asdict(self.agent)
        data["settings"] = asdict(self.settings)
        data["masking_patterns"] = self.masking_patterns
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VaultData:
        version = data.get("version", VAULT_DATA_VERSION)
        servers = [ServerDef(**s) for s in data.get("servers", [])]
        postgres_targets = [PostgresTargetDef(**p) for p in data.get("postgres_targets", [])]
        monitoring_targets = [MonitoringTargetDef(**m) for m in data.get("monitoring_targets", [])]
        agent = AgentConfig(**data.get("agent", {}))
        settings = SecuritySettings(**data.get("settings", {}))
        masking_patterns = data.get("masking_patterns", [])
        return cls(
            version=version, servers=servers, postgres_targets=postgres_targets,
            monitoring_targets=monitoring_targets, agent=agent, settings=settings,
            masking_patterns=masking_patterns,
        )

    def get_default_server(self) -> ServerDef | None:
        enabled = [s for s in self.servers if s.enabled]
        if len(enabled) == 1:
            return enabled[0]
        return None

    def get_default_postgres_target(self) -> PostgresTargetDef | None:
        enabled = [p for p in self.postgres_targets if p.enabled]
        return enabled[0] if len(enabled) == 1 else None

    def get_server(self, server_id: str) -> ServerDef | None:
        for s in self.servers:
            if s.id == server_id:
                return s
        return None

    def get_postgres_target(self, target_id: str) -> PostgresTargetDef | None:
        for p in self.postgres_targets:
            if p.id == target_id:
                return p
        return None

    def get_monitoring_target(self, target_id: str) -> MonitoringTargetDef | None:
        for m in self.monitoring_targets:
            if m.id == target_id:
                return m
        return None

    def is_agent_key_expired(self) -> bool:
        if not self.agent.expires_at:
            return False
        try:
            from datetime import datetime, timezone
            expires = datetime.fromisoformat(self.agent.expires_at.replace("Z", "+00:00"))
            return expires <= datetime.now(timezone.utc)
        except Exception:
            return True


class Vault:
    def __init__(self, vault_path: str):
        self._vault_path = vault_path
        self._data: VaultData | None = None
        self._cipher_text: bytes | None = None
        self._salt: bytes | None = None
        self._nonce: bytes | None = None
        self._derived_key: bytes | None = None
        self._last_activity: float = 0.0

    @property
    def path(self) -> str:
        return self._vault_path

    @property
    def is_locked(self) -> bool:
        return self._data is None

    @property
    def is_unlocked(self) -> bool:
        return self._data is not None

    @property
    def data(self) -> VaultData:
        if self._data is None:
            raise VaultError("vault is locked")
        return self._data

    @property
    def last_activity(self) -> float:
        return self._last_activity

    def touch(self) -> None:
        self._last_activity = time.monotonic()

    def exists(self) -> bool:
        return os.path.exists(self._vault_path)

    def load_encrypted(self) -> None:
        if not self.exists():
            return
        raw = open(self._vault_path, "rb").read()
        envelope = json.loads(raw.decode("utf-8", errors="replace"))
        env_version = int(envelope.get("version", 1))
        if env_version < 1 or env_version > VAULT_ENVELOPE_VERSION:
            raise VaultError(f"unsupported vault envelope version: {env_version}")
        self._cipher_text = base64.b64decode(envelope["ciphertext"])
        self._salt = base64.b64decode(envelope["salt"])
        self._nonce = base64.b64decode(envelope["nonce"])

    def create(self, master_password: str, agent_enabled: bool = False) -> str:
        if self.exists():
            raise VaultError("vault already exists")
        vault_data = VaultData()
        if agent_enabled:
            vault_data.agent.enabled = True
        from app.core.agent_key import generate_agent_token, hash_agent_token
        token = generate_agent_token()
        vault_data.agent.key_hash = hash_agent_token(token)
        self._data = vault_data
        self._salt = secrets.token_bytes(SALT_BYTES)
        key = self._derive_key(master_password)
        self._derived_key = key
        self.save(master_password)
        return token

    def unlock(self, master_password: str) -> None:
        if self._data is not None:
            return
        if not self.exists():
            raise VaultError("vault file not found")
        self.load_encrypted()
        key = self._derive_key(master_password)
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(self._nonce, self._cipher_text, None)
        except Exception:
            raise VaultError("invalid master password or corrupted vault")
        payload = json.loads(plaintext.decode("utf-8"))
        self._data = VaultData.from_dict(payload)
        self._derived_key = key
        self.touch()

    def lock(self) -> None:
        self._data = None
        self._cipher_text = None
        self._salt = None
        self._nonce = None
        self._derived_key = None

    def save(self, master_password: str | None = None) -> None:
        if self._data is None:
            raise VaultError("vault is locked, cannot save")
        nonce = secrets.token_bytes(NONCE_BYTES)
        if master_password is not None:
            self._salt = secrets.token_bytes(SALT_BYTES)
            self._derived_key = self._derive_key(master_password)
        key = self._derived_key
        if key is None:
            raise VaultError("no derived key or master password available to save")
        salt = self._salt
        aesgcm = AESGCM(key)
        plaintext = json.dumps(self._data.to_dict(), indent=2, ensure_ascii=False).encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        salt_b64 = base64.b64encode(salt).decode("ascii")
        nonce_b64 = base64.b64encode(nonce).decode("ascii")
        ct_b64 = base64.b64encode(ciphertext).decode("ascii")
        now_iso = _now_iso()
        app_version = "unknown"
        try:
            from app import __version__ as app_version  # type: ignore
        except Exception:
            pass
        envelope = {
            "version": VAULT_ENVELOPE_VERSION,
            "kdf": KDF,
            "cipher": CIPHER,
            "data_version": self._data.version,
            "app_version": app_version,
            "salt": salt_b64,
            "nonce": nonce_b64,
            "ciphertext": ct_b64,
            "created_at": now_iso,
            "updated_at": now_iso,
        }
        tmp_path = self._vault_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2, ensure_ascii=False)
        if os.path.exists(self._vault_path):
            try:
                shutil.copy2(self._vault_path, self._vault_path + ".bak")
            except OSError:
                pass
        os.replace(tmp_path, self._vault_path)
        self._salt = salt
        self._nonce = nonce
        self._cipher_text = ciphertext
        self.touch()

    def _derive_key(self, master_password: str) -> bytes:
        if self._salt is None:
            self._salt = secrets.token_bytes(SALT_BYTES)
        _check_argon2()
        return _argon2id_derive(master_password.encode("utf-8"), self._salt)


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_ARGON2_AVAILABLE = False


def _check_argon2() -> None:
    global _ARGON2_AVAILABLE
    if _ARGON2_AVAILABLE:
        return
    try:
        from argon2.low_level import hash_secret_raw, Type
        _ARGON2_AVAILABLE = True
    except ImportError:
        raise VaultError("argon2-cffi is required for vault encryption")


def _argon2id_derive(password: bytes, salt: bytes) -> bytes:
    from argon2.low_level import hash_secret_raw, Type
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=4,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )
