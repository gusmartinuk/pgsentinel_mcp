from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from app.core.errors import ConfigError


DEFAULT_CONFIG_PATH = "/secrets/pgsentinel.secrets.yml"


def runtime_env() -> str:
    return os.environ.get("PGSENTINEL_ENV", "development").strip().lower()


def is_production() -> bool:
    return runtime_env() == "production"


def legacy_config_allowed() -> bool:
    value = os.environ.get("PGSENTINEL_ALLOW_LEGACY_CONFIG", "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    return not is_production()


class ProjectConfig(BaseModel):
    name: str = "PgSentinel MCP"
    environment: str = "staging"


class ServerConfig(BaseModel):
    mode: Literal["ssh", "local"] = "ssh"
    host: str | None = None
    port: int = Field(default=22, ge=1, le=65535)
    username: str | None = None
    ssh_private_key_path: str | None = None
    ssh_private_key_passphrase: str | None = None

    @model_validator(mode="after")
    def require_ssh_fields_for_ssh_mode(self) -> "ServerConfig":
        if self.mode == "ssh":
            missing = [
                field
                for field in ("host", "username", "ssh_private_key_path")
                if not getattr(self, field)
            ]
            if missing:
                raise ValueError(f"server.{', server.'.join(missing)} required when server.mode is ssh")
        return self


class SecurityConfig(BaseModel):
    default_readonly: bool = True
    allow_write_tools: bool = False
    allow_raw_sql: bool = False
    allow_raw_shell: bool = False
    max_log_lines: int = Field(default=300, ge=1, le=5000)
    max_query_rows: int = Field(default=100, ge=1, le=1000)
    command_timeout_seconds: int = Field(default=20, ge=1, le=300)

    @model_validator(mode="after")
    def enforce_mvp_security(self) -> "SecurityConfig":
        if not self.default_readonly:
            raise ValueError("security.default_readonly must remain true in the MVP")
        if self.allow_write_tools:
            raise ValueError("security.allow_write_tools is not supported in the MVP")
        if self.allow_raw_shell:
            raise ValueError("security.allow_raw_shell must remain false")
        return self


class DockerConfig(BaseModel):
    allowed_containers: list[str] = Field(default_factory=list)

    @field_validator("allowed_containers")
    @classmethod
    def require_containers(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("docker.allowed_containers must not be empty")
        return value


class PostgresConfig(BaseModel):
    container_name: str
    database: str
    username: str
    password: str
    host_inside_container: str = "localhost"
    port_inside_container: int = Field(default=5432, ge=1, le=65535)
    allowed_schemas: list[str] = Field(default_factory=lambda: ["public"])
    allowed_tables: list[str] = Field(default_factory=list)
    sensitive_columns: list[str] = Field(
        default_factory=lambda: [
            "password",
            "password_hash",
            "token",
            "secret",
            "api_key",
            "private_key",
            "access_token",
            "refresh_token",
        ]
    )

    @field_validator("allowed_tables")
    @classmethod
    def require_tables(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("postgres.allowed_tables must not be empty")
        return value


class LogConfig(BaseModel):
    type: Literal["docker"]
    container: str
    max_lines: int | None = Field(default=None, ge=1, le=5000)


class LogsConfig(BaseModel):
    allowed_logs: dict[str, LogConfig] = Field(default_factory=dict)

    @field_validator("allowed_logs")
    @classmethod
    def require_logs(cls, value: dict[str, LogConfig]) -> dict[str, LogConfig]:
        if not value:
            raise ValueError("logs.allowed_logs must not be empty")
        return value


class MaskingConfig(BaseModel):
    patterns: list[str] = Field(
        default_factory=lambda: [
            "password=",
            "PASSWORD=",
            "token=",
            "TOKEN=",
            "Authorization:",
            "Bearer ",
            "DB_PASSWORD=",
            "APP_KEY=",
            "SECRET=",
            "PRIVATE_KEY",
            "AWS_SECRET_ACCESS_KEY=",
        ]
    )


class PgSentinelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project: ProjectConfig = Field(default_factory=ProjectConfig)
    server: ServerConfig
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    docker: DockerConfig
    postgres: PostgresConfig
    logs: LogsConfig
    masking: MaskingConfig = Field(default_factory=MaskingConfig)

    @model_validator(mode="after")
    def validate_cross_references(self) -> "PgSentinelConfig":
        allowed = set(self.docker.allowed_containers)
        if self.postgres.container_name not in allowed:
            raise ValueError("postgres.container_name must be in docker.allowed_containers")
        for name, log_config in self.logs.allowed_logs.items():
            if log_config.container not in allowed:
                raise ValueError(f"logs.allowed_logs.{name}.container must be allowlisted")
        return self

    def summary(self) -> dict[str, object]:
        return {
            "project": self.project.name,
            "environment": self.project.environment,
            "server_mode": self.server.mode,
            "readonly": self.security.default_readonly,
            "write_tools_enabled": self.security.allow_write_tools,
            "raw_sql_enabled": self.security.allow_raw_sql,
            "allowed_containers": self.docker.allowed_containers,
            "allowed_logs": sorted(self.logs.allowed_logs),
            "allowed_schemas": self.postgres.allowed_schemas,
            "allowed_tables": self.postgres.allowed_tables,
        }


def config_path_from_env() -> str:
    return os.environ.get("PGSENTINEL_CONFIG", DEFAULT_CONFIG_PATH)


def load_config(path: str | Path | None = None) -> PgSentinelConfig:
    if not legacy_config_allowed():
        raise ConfigError("legacy YAML config fallback is disabled in production")
    resolved = Path(path or config_path_from_env())
    if not resolved.exists():
        raise ConfigError(f"config file not found: {resolved}")
    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8")) or {}
        return PgSentinelConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc
    except OSError as exc:
        raise ConfigError(str(exc)) from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML: {exc}") from exc


@lru_cache(maxsize=1)
def get_config() -> PgSentinelConfig:
    return load_config()


def clear_config_cache() -> None:
    get_config.cache_clear()
