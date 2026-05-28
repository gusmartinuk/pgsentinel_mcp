from __future__ import annotations

import inspect
import json
import os
import sys
import time
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar

from app.core.masking import mask_data

F = TypeVar("F", bound=Callable[..., Any])
DEFAULT_AUDIT_LOG = "audit/pgsentinel-audit.jsonl"


def audit_log_path() -> Path:
    return Path(os.environ.get("PGSENTINEL_AUDIT_LOG", DEFAULT_AUDIT_LOG))


def write_audit_event(event: dict[str, Any]) -> None:
    # Audit logging must never crash the request it is recording. A read-only
    # filesystem or a bind-mounted log owned by another user previously turned
    # routine actions (e.g. admin login) into HTTP 500s.
    if "timestamp" not in event:
        event["timestamp"] = datetime.now(UTC).isoformat()
    try:
        path = audit_log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(mask_data(event), sort_keys=True) + "\n")
    except OSError as exc:
        print(f"pgsentinel: audit write failed ({exc})", file=sys.stderr)


def _summarize_call(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    summary = dict(kwargs)
    if args:
        summary["_positional_count"] = len(args)
    return mask_data(summary)


def audit_tool_call(tool_name: str) -> Callable[[F], F]:
    def decorator(func: F) -> F:
        if inspect.iscoroutinefunction(func):

            @wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                started = time.perf_counter()
                status = "success"
                try:
                    return await func(*args, **kwargs)
                except Exception:
                    status = "error"
                    raise
                finally:
                    write_audit_event(
                        {
                            "timestamp": datetime.now(UTC).isoformat(),
                            "tool": tool_name,
                            "arguments_summary": _summarize_call(args, kwargs),
                            "status": status,
                            "duration_ms": round((time.perf_counter() - started) * 1000),
                            "readonly": True,
                        }
                    )

            return async_wrapper  # type: ignore[return-value]

        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            started = time.perf_counter()
            status = "success"
            try:
                return func(*args, **kwargs)
            except Exception:
                status = "error"
                raise
            finally:
                write_audit_event(
                    {
                        "timestamp": datetime.now(UTC).isoformat(),
                        "tool": tool_name,
                        "arguments_summary": _summarize_call(args, kwargs),
                        "status": status,
                        "duration_ms": round((time.perf_counter() - started) * 1000),
                        "readonly": True,
                    }
                )
        return wrapper  # type: ignore[return-value]

    return decorator
