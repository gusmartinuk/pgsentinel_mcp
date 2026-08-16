#!/bin/sh
set -eu

RUN_AS_USER="${PGSENTINEL_RUN_AS_USER:-app}"

VAULT_DIR_ENV="${PGSENTINEL_VAULT_DIR:-}"
if [ -n "$VAULT_DIR_ENV" ]; then
  ACTIVE_FILE="${PGSENTINEL_ACTIVE_VAULT_FILE:-$VAULT_DIR_ENV/.active_vault}"
  ACTIVE_NAME="default1"
  if [ -f "$ACTIVE_FILE" ]; then
    ACTIVE_NAME="$(tr -d '\r\n' < "$ACTIVE_FILE")"
  fi
  VAULT_PATH="$VAULT_DIR_ENV/${ACTIVE_NAME}.vault.enc"
  VAULT_DIR="$VAULT_DIR_ENV"
else
  VAULT_PATH="${PGSENTINEL_VAULT:-/secure/pgsentinel/vault.enc}"
  VAULT_DIR="$(dirname "$VAULT_PATH")"
fi
VAULT_MARKER="${PGSENTINEL_VAULT_MARKER:-$VAULT_DIR/.vault_initialized}"
REQUIRE_EXISTING="${PGSENTINEL_REQUIRE_EXISTING_VAULT:-false}"

# If this instance was initialized before, never allow silent first-run reset.
if [ -f "$VAULT_MARKER" ] && [ ! -f "$VAULT_PATH" ]; then
  echo "FATAL: vault marker exists but vault file is missing."
  echo "FATAL: expected vault at: $VAULT_PATH"
  echo "FATAL: refusing startup to prevent accidental re-initialization."
  exit 78
fi

# Optional hard requirement for production-like environments.
if [ "$REQUIRE_EXISTING" = "true" ] && [ ! -f "$VAULT_PATH" ]; then
  echo "FATAL: PGSENTINEL_REQUIRE_EXISTING_VAULT=true but vault file not found at $VAULT_PATH"
  exit 78
fi

if [ "$(id -u)" = "0" ]; then
  mkdir -p "$VAULT_DIR" /var/log/pgsentinel
  chown -R "$RUN_AS_USER:$RUN_AS_USER" "$VAULT_DIR" /var/log/pgsentinel

  AUDIT_LOG="${PGSENTINEL_AUDIT_LOG:-/app/audit/pgsentinel-audit.jsonl}"
  SERVER_LOG="${PGSENTINEL_SERVER_LOG:-/var/log/pgsentinel/server.log}"
  mkdir -p "$(dirname "$AUDIT_LOG")" "$(dirname "$SERVER_LOG")"
  touch "$AUDIT_LOG" "$SERVER_LOG"
  chown "$RUN_AS_USER:$RUN_AS_USER" "$AUDIT_LOG" "$SERVER_LOG"

  # The SSH known_hosts cache lives outside the chowned vault dir; make sure the
  # app user can read/append it (TOFU writes new host keys here on first SSH).
  KNOWN_HOSTS="${PGSENTINEL_SSH_KNOWN_HOSTS:-$VAULT_DIR/known_hosts}"
  mkdir -p "$(dirname "$KNOWN_HOSTS")"
  [ -e "$KNOWN_HOSTS" ] || : > "$KNOWN_HOSTS"
  chown "$RUN_AS_USER:$RUN_AS_USER" "$KNOWN_HOSTS"
  chmod 0600 "$KNOWN_HOSTS"

  # Auto-unlock file lives on the data volume, outside the vaults/ chown.
  MASTER_FILE="${PGSENTINEL_MASTER_PASSWORD_FILE:-}"
  if [ -n "$MASTER_FILE" ] && [ -e "$MASTER_FILE" ]; then
    chown "$RUN_AS_USER:$RUN_AS_USER" "$MASTER_FILE"
    chmod 0600 "$MASTER_FILE"
  fi

  if [ -S /var/run/docker.sock ]; then
    SOCKET_GID="$(stat -c '%g' /var/run/docker.sock 2>/dev/null || true)"
    if [ -n "$SOCKET_GID" ]; then
      GROUP_NAME="$(getent group "$SOCKET_GID" | cut -d: -f1 || true)"
      if [ -z "$GROUP_NAME" ]; then
        GROUP_NAME="dockerhost"
        addgroup --gid "$SOCKET_GID" "$GROUP_NAME" >/dev/null 2>&1 || true
      fi
      adduser "$RUN_AS_USER" "$GROUP_NAME" >/dev/null 2>&1 || true
    fi
  fi
fi

if [ "$#" -gt 0 ]; then
  if [ "$(id -u)" = "0" ]; then
    exec gosu "$RUN_AS_USER" "$@"
  fi
  exec "$@"
fi

if [ "$(id -u)" = "0" ]; then
  exec gosu "$RUN_AS_USER" uvicorn app.main:app --host 0.0.0.0 --port "${APP_PORT:-8088}"
fi

exec uvicorn app.main:app --host 0.0.0.0 --port "${APP_PORT:-8088}"
