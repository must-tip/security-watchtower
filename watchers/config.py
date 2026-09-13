"""Validated environment configuration for the production Watchtower."""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from . import __version__


def setup_logging(level: str = "INFO") -> logging.Logger:
    normalized = level.strip().upper()
    numeric_level = getattr(logging, normalized, None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"invalid LOG_LEVEL: {level!r}")
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        handlers=[logging.StreamHandler()],
        force=True,
    )
    return logging.getLogger("watchtower")


def _env_int(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _env_float(
    name: str,
    default: float,
    *,
    minimum: float,
    maximum: float,
) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be numeric") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be true or false")


def _env_csv(name: str, default: str) -> list[str]:
    return [
        item.strip()
        for item in os.getenv(name, default).split(",")
        if item.strip()
    ]


def _validate_http_url(
    value: str,
    *,
    name: str,
    require_https: bool,
    allow_loopback: bool,
) -> None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{name} contains an invalid URL") from exc

    allowed_schemes = {"https"} if require_https else {"http", "https"}
    if parsed.scheme.lower() not in allowed_schemes:
        raise ValueError(f"{name} must use {'HTTPS' if require_https else 'HTTP or HTTPS'}")
    if not parsed.hostname:
        raise ValueError(f"{name} must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError(f"{name} must not contain credentials")
    if parsed.fragment or parsed.query:
        raise ValueError(f"{name} must not contain a query string or fragment")
    if not parsed.path or parsed.path == "/":
        raise ValueError(f"{name} must identify an explicit health endpoint path")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"{name} contains an invalid port")

    hostname = parsed.hostname.lower().rstrip(".")
    if hostname == "localhost" and not allow_loopback:
        raise ValueError(f"{name} must not target localhost")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if (
        address.is_private
        or address.is_reserved
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    ):
        raise ValueError(f"{name} targets a prohibited address range")
    if address.is_loopback and not allow_loopback:
        raise ValueError(f"{name} must not target a loopback address")


logger = logging.getLogger("watchtower")


@dataclass
class RedisSettings:
    host: str = field(default_factory=lambda: os.getenv("REDIS_HOST", "localhost").strip())
    port: int = field(
        default_factory=lambda: _env_int(
            "REDIS_PORT", 6379, minimum=1, maximum=65535
        )
    )
    db: int = field(
        default_factory=lambda: _env_int("REDIS_DB", 0, minimum=0, maximum=15)
    )
    password: Optional[str] = field(default_factory=lambda: os.getenv("REDIS_PASSWORD"))
    max_connections: int = field(
        default_factory=lambda: _env_int(
            "REDIS_MAX_CONNECTIONS", 20, minimum=1, maximum=1000
        )
    )
    socket_timeout: float = field(
        default_factory=lambda: _env_float(
            "REDIS_SOCKET_TIMEOUT", 5.0, minimum=0.1, maximum=120.0
        )
    )
    retry_on_timeout: bool = True
    decode_responses: bool = True


@dataclass
class NotifierSettings:
    slack_webhook_url: Optional[str] = field(
        default_factory=lambda: os.getenv("SLACK_WEBHOOK_URL")
    )
    telegram_bot_token: Optional[str] = field(
        default_factory=lambda: os.getenv("TELEGRAM_BOT_TOKEN")
    )
    telegram_chat_id: Optional[str] = field(
        default_factory=lambda: os.getenv("TELEGRAM_CHAT_ID")
    )
    generic_webhook_url: Optional[str] = field(
        default_factory=lambda: os.getenv("GENERIC_WEBHOOK_URL")
    )
    alert_cooldown_secs: int = field(
        default_factory=lambda: _env_int(
            "ALERT_COOLDOWN_SECS", 300, minimum=1, maximum=86400
        )
    )
    min_alert_severity: str = field(
        default_factory=lambda: os.getenv("MIN_ALERT_SEVERITY", "HIGH")
        .strip()
        .upper()
    )
    request_timeout_secs: float = field(
        default_factory=lambda: _env_float(
            "NOTIFIER_TIMEOUT", 10.0, minimum=0.1, maximum=120.0
        )
    )
    max_retries: int = field(
        default_factory=lambda: _env_int(
            "NOTIFIER_MAX_RETRIES", 3, minimum=0, maximum=10
        )
    )


@dataclass
class ApiWatcherSettings:
    # Complete, side-effect-free GET health endpoint URLs.
    target_urls: list[str] = field(
        default_factory=lambda: _env_csv(
            "API_WATCHER_TARGETS",
            "",
        )
    )
    poll_interval_secs: float = field(
        default_factory=lambda: _env_float(
            "API_POLL_INTERVAL", 15.0, minimum=1.0, maximum=3600.0
        )
    )
    request_timeout_secs: float = field(
        default_factory=lambda: _env_float(
            "API_REQUEST_TIMEOUT", 8.0, minimum=0.1, maximum=300.0
        )
    )
    failure_threshold: int = field(
        default_factory=lambda: _env_int(
            "API_FAILURE_THRESHOLD", 3, minimum=1, maximum=100
        )
    )
    latency_warn_ms: float = field(
        default_factory=lambda: _env_float(
            "API_LATENCY_WARN_MS", 2000.0, minimum=1.0, maximum=300000.0
        )
    )
    max_concurrent: int = field(
        default_factory=lambda: _env_int(
            "API_MAX_CONCURRENT", 10, minimum=1, maximum=500
        )
    )
    user_agent: str = f"SecurityWatchtower/{__version__}"


@dataclass
class CodeWatcherSettings:
    watch_paths: list[str] = field(
        default_factory=lambda: _env_csv("CODE_WATCH_PATHS", "./src")
    )
    watch_extensions: list[str] = field(
        default_factory=lambda: _env_csv(
            "CODE_WATCH_EXTENSIONS", ".py,.js,.ts,.go,.java"
        )
    )
    scan_on_start: bool = field(
        default_factory=lambda: _env_bool("CODE_SCAN_ON_START", True)
    )
    secret_patterns_enabled: bool = field(
        default_factory=lambda: _env_bool("CODE_SECRET_SCAN", True)
    )
    ignore_paths: list[str] = field(
        default_factory=lambda: _env_csv(
            "CODE_IGNORE_PATHS",
            "node_modules,.git,__pycache__,.venv,dist,build",
        )
    )


@dataclass
class CorrelatorSettings:
    correlation_window_secs: float = field(
        default_factory=lambda: _env_float(
            "CORRELATOR_WINDOW", 300.0, minimum=1.0, maximum=86400.0
        )
    )
    buffer_max_size: int = field(
        default_factory=lambda: _env_int(
            "CORRELATOR_BUFFER_SIZE", 500, minimum=1, maximum=100000
        )
    )
    min_confidence: float = field(
        default_factory=lambda: _env_float(
            "CORRELATOR_MIN_CONFIDENCE", 0.6, minimum=0.0, maximum=1.0
        )
    )
    poll_timeout_secs: float = field(
        default_factory=lambda: _env_float(
            "CORRELATOR_POLL_TIMEOUT", 5.0, minimum=1.0, maximum=60.0
        )
    )
    publish_channel: str = "watchtower:alerts"
    findings_queue: str = "watchtower:findings"


@dataclass
class Settings:
    redis: RedisSettings = field(default_factory=RedisSettings)
    notifier: NotifierSettings = field(default_factory=NotifierSettings)
    api_watcher: ApiWatcherSettings = field(default_factory=ApiWatcherSettings)
    code_watcher: CodeWatcherSettings = field(default_factory=CodeWatcherSettings)
    correlator: CorrelatorSettings = field(default_factory=CorrelatorSettings)
    env: str = field(
        default_factory=lambda: os.getenv("WATCHTOWER_ENV", "production")
        .strip()
        .lower()
    )
    platform: str = field(
        default_factory=lambda: os.getenv(
            "PLATFORM_NAME", "multi-service-platform"
        ).strip()
    )
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "INFO").strip().upper()
    )

    def validate(self) -> None:
        if self.env != "production":
            raise RuntimeError(
                f"WATCHTOWER_ENV={self.env!r} is not allowed; "
                "this Watchtower build is production-only"
            )
        if not self.platform or len(self.platform) > 100:
            raise ValueError("PLATFORM_NAME must contain 1 to 100 characters")
        if not self.redis.host or any(char.isspace() for char in self.redis.host):
            raise ValueError("REDIS_HOST is invalid")
        if (
            not self.redis.password
            or len(self.redis.password) < 20
            or self.redis.password.startswith("replace-with-")
        ):
            raise ValueError(
                "REDIS_PASSWORD must be a non-placeholder secret of at least "
                "20 characters"
            )
        if not self.api_watcher.target_urls:
            raise ValueError("API_WATCHER_TARGETS must contain at least one endpoint")
        if len(self.api_watcher.target_urls) > 100:
            raise ValueError("API_WATCHER_TARGETS cannot contain more than 100 endpoints")
        for target in self.api_watcher.target_urls:
            _validate_http_url(
                target,
                name="API_WATCHER_TARGETS",
                require_https=True,
                allow_loopback=False,
            )

        severity = self.notifier.min_alert_severity
        if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("MIN_ALERT_SEVERITY is invalid")
        if bool(self.notifier.telegram_bot_token) != bool(
            self.notifier.telegram_chat_id
        ):
            raise ValueError(
                "TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be configured together"
            )
        if self.notifier.telegram_bot_token and not re.fullmatch(
            r"[0-9]{6,15}:[A-Za-z0-9_-]{20,}",
            self.notifier.telegram_bot_token,
        ):
            raise ValueError("TELEGRAM_BOT_TOKEN has an invalid format")
        if self.notifier.telegram_chat_id and not re.fullmatch(
            r"-?[0-9]{1,24}",
            self.notifier.telegram_chat_id,
        ):
            raise ValueError("TELEGRAM_CHAT_ID has an invalid format")
        for name, url in (
            ("SLACK_WEBHOOK_URL", self.notifier.slack_webhook_url),
            ("GENERIC_WEBHOOK_URL", self.notifier.generic_webhook_url),
        ):
            if url:
                _validate_http_url(
                    url,
                    name=name,
                    require_https=True,
                    allow_loopback=False,
                )

        if not self.code_watcher.watch_paths:
            raise ValueError("CODE_WATCH_PATHS must contain at least one path")
        for watch_path in self.code_watcher.watch_paths:
            if (
                len(watch_path) > 4096
                or "\x00" in watch_path
                or os.path.abspath(watch_path) == os.path.sep
            ):
                raise ValueError("CODE_WATCH_PATHS contains an unsafe path")
        if any(
            not extension.startswith(".")
            or "/" in extension
            or "\\" in extension
            for extension in self.code_watcher.watch_extensions
        ):
            raise ValueError("CODE_WATCH_EXTENSIONS contains an invalid extension")

        if (
            not self.notifier.slack_webhook_url
            and not self.notifier.telegram_bot_token
            and not self.notifier.generic_webhook_url
        ):
            logger.warning("No external notification channel is configured")
        logger.info(
            "Config validated | env=%s | platform=%s | redis=%s:%s",
            self.env,
            self.platform,
            self.redis.host,
            self.redis.port,
        )


settings = Settings()
