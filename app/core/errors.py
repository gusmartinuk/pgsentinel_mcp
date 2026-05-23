class PgSentinelError(Exception):
    """Base application error."""


class ConfigError(PgSentinelError):
    """Raised when protected configuration cannot be loaded or validated."""


class SecurityError(PgSentinelError):
    """Raised when an operation violates the read-only security model."""


class RemoteCommandError(PgSentinelError):
    """Raised when a predefined remote command fails."""
