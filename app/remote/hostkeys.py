from __future__ import annotations

import os
import threading
from pathlib import Path


_LOCK = threading.Lock()


def known_hosts_path() -> Path:
    configured = os.environ.get("PGSENTINEL_SSH_KNOWN_HOSTS", "").strip()
    if configured:
        return Path(configured)
    vault_dir = os.environ.get("PGSENTINEL_VAULT_DIR", "").strip()
    if vault_dir:
        return Path(vault_dir) / "known_hosts"
    vault_path = os.environ.get("PGSENTINEL_VAULT", "/secure/pgsentinel/vault.enc")
    return Path(vault_path).parent / "known_hosts"


def load_host_keys(client) -> Path:
    path = known_hosts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    client.load_system_host_keys()
    client.load_host_keys(str(path))
    return path


class PersistentTOFUPolicy:
    """Trust-on-first-use and persist host keys into project known_hosts."""

    def __init__(self, path: Path):
        self.path = path

    def missing_host_key(self, client, hostname, key):
        with _LOCK:
            keys = client.get_host_keys()
            keys.add(hostname, key.get_name(), key)
            keys.save(str(self.path))
