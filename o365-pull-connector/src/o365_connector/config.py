import os
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, Optional


def env_bool(key: str, default: bool = False) -> bool:
    value = os.getenv(key)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


@dataclass
class AppConfig:
    database_url: str = field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./o365_connector.db")
    )
    log_level: str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    scheduler_enabled: bool = field(default_factory=lambda: env_bool("SCHEDULER_ENABLED", True))
    scheduler_interval: int = field(default_factory=lambda: int(os.getenv("SCHEDULER_INTERVAL", "300")))
    max_retry_attempts: int = field(default_factory=lambda: int(os.getenv("MAX_RETRY_ATTEMPTS", "3")))
    retry_backoff_seconds: float = field(default_factory=lambda: float(os.getenv("RETRY_BACKOFF_SECONDS", "1.0")))
    retry_backoff_jitter: float = field(default_factory=lambda: float(os.getenv("RETRY_BACKOFF_JITTER", "0.5")))
    export_version: int = 1
    default_pull_window: timedelta = field(default=timedelta(hours=24))
    defender_enabled: bool = field(default_factory=lambda: env_bool("DEFENDER_ENABLED", False))

    @classmethod
    def from_env(cls) -> "AppConfig":
        return cls()

    def as_dict(self) -> Dict[str, Any]:
        return {
            "database_url": self.database_url,
            "log_level": self.log_level,
            "scheduler_enabled": self.scheduler_enabled,
            "scheduler_interval": self.scheduler_interval,
            "max_retry_attempts": self.max_retry_attempts,
            "retry_backoff_seconds": self.retry_backoff_seconds,
            "retry_backoff_jitter": self.retry_backoff_jitter,
            "export_version": self.export_version,
            "default_pull_window_seconds": int(self.default_pull_window.total_seconds()),
            "defender_enabled": self.defender_enabled,
        }
