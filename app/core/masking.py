from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

MASK = "***MASKED***"

SENSITIVE_KEYWORDS = (
    "password",
    "passwd",
    "token",
    "secret",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
    "access_key",
    "refresh_token",
)


def _pattern_regex(pattern: str) -> re.Pattern[str]:
    escaped = re.escape(pattern)
    if pattern.endswith(":"):
        return re.compile(rf"({escaped}\s*)[^\r\n]+", re.IGNORECASE)
    if pattern.endswith("="):
        return re.compile(rf"({escaped})[^\s&;,\r\n]+", re.IGNORECASE)
    if pattern.strip().lower() == "bearer":
        return re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
    return re.compile(rf"({escaped})([^\s\r\n]*)", re.IGNORECASE)


def mask_text(value: str, patterns: list[str] | None = None) -> str:
    masked = value
    for pattern in patterns or []:
        masked = _pattern_regex(pattern).sub(rf"\1{MASK}", masked)
    masked = re.sub(
        r"((?:password|passwd|token|secret|api[_-]?key|private[_-]?key)\s*[:=]\s*)[^\s&;,\r\n]+",
        rf"\1{MASK}",
        masked,
        flags=re.IGNORECASE,
    )
    masked = re.sub(r"(Authorization:\s*)[^\r\n]+", rf"\1{MASK}", masked, flags=re.IGNORECASE)
    masked = re.sub(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", rf"\1{MASK}", masked, flags=re.IGNORECASE)
    return masked


def is_sensitive_key(key: str) -> bool:
    normalized = key.lower().replace("-", "_")
    return any(keyword in normalized for keyword in SENSITIVE_KEYWORDS)


def mask_data(value: Any, patterns: list[str] | None = None) -> Any:
    if isinstance(value, str):
        return mask_text(value, patterns)
    if isinstance(value, Mapping):
        return {
            key: MASK if is_sensitive_key(str(key)) else mask_data(item, patterns)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [mask_data(item, patterns) for item in value]
    if isinstance(value, tuple):
        return tuple(mask_data(item, patterns) for item in value)
    return value
