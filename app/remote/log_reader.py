from __future__ import annotations

import re

from app.core.config import PgSentinelConfig
from app.core.masking import mask_text
from app.core.security import clamp_limit, ensure_allowed_log
from app.remote.docker_client import RemoteDockerClient

ERROR_RE = re.compile(
    r"(ERROR|Exception|Traceback|SQLSTATE|FATAL|\b500\b|timeout|connection refused|permission denied)",
    re.IGNORECASE,
)


class RemoteLogReader:
    def __init__(self, docker: RemoteDockerClient, config: PgSentinelConfig):
        self.docker = docker
        self.config = config

    def get_container_logs(self, container: str, lines: int | None = None, level_filter: str | None = None) -> dict[str, object]:
        output = self.docker.logs(container, lines)
        entries = output.splitlines()
        if level_filter:
            needle = level_filter.lower()
            entries = [line for line in entries if needle in line.lower()]
        return {"container": container, "lines": entries, "count": len(entries)}

    def search_logs(self, log_name: str, keyword: str, lines: int | None = None) -> dict[str, object]:
        log_config = ensure_allowed_log(self.config, log_name)
        max_lines = min(log_config.max_lines or self.config.security.max_log_lines, self.config.security.max_log_lines)
        limit = clamp_limit(lines, max_lines, max_lines)
        output = self.docker.logs(log_config.container, limit)
        needle = keyword.lower()
        matches = [line for line in output.splitlines() if needle in line.lower()]
        deduped = list(dict.fromkeys(matches))
        return {
            "log_name": log_name,
            "keyword": keyword,
            "matches": [mask_text(line, self.config.masking.patterns) for line in deduped],
            "count": len(deduped),
        }

    def get_recent_errors(self, log_name: str, minutes: int = 60, limit: int | None = None) -> dict[str, object]:
        log_config = ensure_allowed_log(self.config, log_name)
        max_lines = min(log_config.max_lines or self.config.security.max_log_lines, self.config.security.max_log_lines)
        search_limit = clamp_limit(limit, max_lines, min(100, max_lines))
        output = self.docker.logs(log_config.container, max_lines)
        matches = [line for line in output.splitlines() if ERROR_RE.search(line)]
        matches = matches[-search_limit:]
        return {
            "log_name": log_name,
            "minutes": minutes,
            "errors": [mask_text(line, self.config.masking.patterns) for line in matches],
            "count": len(matches),
        }

    def has_recent_errors(self, log_name: str) -> bool:
        try:
            return bool(self.get_recent_errors(log_name, limit=20)["count"])
        except Exception:
            return False
