from __future__ import annotations

import secrets

import bcrypt


AGENT_KEY_PREFIX = "pgs_ai_"


def generate_agent_token() -> str:
    entropy = secrets.token_urlsafe(48)
    return f"{AGENT_KEY_PREFIX}{entropy}"


def hash_agent_token(token: str) -> str:
    try:
        salt = bcrypt.gensalt(rounds=12, prefix=b"2b")
    except TypeError:
        salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(token.encode("utf-8"), salt).decode("ascii")


def verify_agent_token(token: str, token_hash: str) -> bool:
    try:
        return bcrypt.checkpw(token.encode("utf-8"), token_hash.encode("ascii"))
    except (ValueError, UnicodeDecodeError):
        return False


def is_valid_agent_token_format(token: str) -> bool:
    if not token or not token.startswith(AGENT_KEY_PREFIX):
        return False
    suffix = token[len(AGENT_KEY_PREFIX):]
    return len(suffix) >= 32
