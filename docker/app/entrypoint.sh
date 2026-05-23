#!/bin/sh
set -eu

VAULT_DIR_ENV="${PGSENTINEL_VAULT_DIR:-}"
if [ -n "$VAULT_DIR_ENV" ]; then
  ACTIVE_FILE="${PGSENTINEL_ACTIVE_VAULT_FILE:-$VAULT_DIR_ENV/.active_vault}"
  ACTIVE_NAME="default"
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

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

exec uvicorn app.main:app --host 0.0.0.0 --port "${APP_PORT:-8088}"
