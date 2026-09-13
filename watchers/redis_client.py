"""Thread-safe Redis access with bounded retry and atomic alert claims."""

from __future__ import annotations

import logging
import math
import threading
import time
import uuid
from typing import Callable, Optional, TypeVar

from .config import settings

try:
    import redis as _redis
    from redis.exceptions import ConnectionError as RedisConnectionError
    from redis.exceptions import RedisError
    from redis.exceptions import TimeoutError as RedisTimeoutError
except ModuleNotFoundError:  # Allows isolated schema/unit tests without runtime deps.
    _redis = None

    class RedisError(Exception):
        """Fallback base used only until the runtime dependency is accessed."""

    class RedisConnectionError(RedisError):
        pass

    class RedisTimeoutError(RedisError):
        pass

logger = logging.getLogger("watchtower.redis")
T = TypeVar("T")

_pool: Optional[object] = None
_pool_lock = threading.Lock()


def _require_redis():
    if _redis is None:
        raise RuntimeError("redis runtime dependency is not installed")
    return _redis


def _get_pool() -> object:
    global _pool
    if _pool is not None:
        return _pool
    with _pool_lock:
        if _pool is None:
            cfg = settings.redis
            redis_module = _require_redis()
            _pool = redis_module.ConnectionPool(
                host=cfg.host,
                port=cfg.port,
                db=cfg.db,
                password=cfg.password,
                max_connections=cfg.max_connections,
                socket_timeout=cfg.socket_timeout,
                socket_connect_timeout=cfg.socket_timeout,
                retry_on_timeout=cfg.retry_on_timeout,
                decode_responses=cfg.decode_responses,
                health_check_interval=30,
                client_name="security-watchtower",
            )
            logger.info(
                "Redis pool created | host=%s port=%s db=%s",
                cfg.host,
                cfg.port,
                cfg.db,
            )
    return _pool


def get_client():
    redis_module = _require_redis()
    return redis_module.Redis(connection_pool=_get_pool())


def _with_retry(
    operation: Callable[[], T],
    *,
    max_attempts: int = 3,
    base_delay: float = 0.5,
) -> T:
    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    last_error: Optional[Exception] = None
    for attempt in range(1, max_attempts + 1):
        try:
            return operation()
        except (RedisConnectionError, RedisTimeoutError) as exc:
            last_error = exc
            if attempt == max_attempts:
                break
            delay = base_delay * (2 ** (attempt - 1))
            logger.warning(
                "Redis operation retry | attempt=%d max_attempts=%d delay=%.1f "
                "error_type=%s",
                attempt,
                max_attempts,
                delay,
                type(exc).__name__,
            )
            time.sleep(delay)
        except RedisError:
            logger.exception("Non-retryable Redis operation failed")
            raise
    if last_error is None:
        raise RuntimeError("Redis operation failed without an exception")
    raise last_error


def ping() -> bool:
    try:
        return bool(get_client().ping())
    except RedisError:
        return False


def wait_for_redis(
    timeout_secs: float = 30.0,
    check_interval: float = 1.0,
) -> None:
    if timeout_secs <= 0 or check_interval <= 0:
        raise ValueError("Redis wait timeouts must be positive")
    deadline = time.monotonic() + timeout_secs
    logger.info("Waiting for Redis")
    while time.monotonic() < deadline:
        if ping():
            logger.info("Redis is ready")
            return
        time.sleep(min(check_interval, max(0.0, deadline - time.monotonic())))
    raise RuntimeError(
        f"Redis at {settings.redis.host}:{settings.redis.port} "
        f"was unavailable after {timeout_secs:.1f} seconds"
    )


def push_finding(finding_json: str, queue: Optional[str] = None) -> None:
    target = queue or settings.correlator.findings_queue
    _with_retry(lambda: get_client().lpush(target, finding_json))
    logger.debug("Finding pushed | queue=%s", target)


def pop_finding(
    timeout_secs: float = 5.0,
    queue: Optional[str] = None,
) -> Optional[str]:
    if timeout_secs <= 0:
        raise ValueError("timeout_secs must be positive")
    target = queue or settings.correlator.findings_queue

    def pop() -> Optional[str]:
        result = get_client().brpop(
            target,
            timeout=max(1, math.ceil(timeout_secs)),
        )
        return result[1] if result else None

    return _with_retry(pop)


def publish_alert(alert_json: str, channel: Optional[str] = None) -> None:
    target = channel or settings.correlator.publish_channel
    _with_retry(lambda: get_client().publish(target, alert_json))
    logger.debug("Alert published | channel=%s", target)


def set_with_ttl(key: str, value: str, ttl_secs: int) -> None:
    if ttl_secs < 1:
        raise ValueError("ttl_secs must be positive")
    _with_retry(lambda: get_client().setex(key, ttl_secs, value))


def key_exists(key: str) -> bool:
    return bool(_with_retry(lambda: get_client().exists(key)))


def store_finding_record(
    finding_id: str,
    finding_json: str,
    ttl_secs: int = 86400,
) -> None:
    set_with_ttl(
        f"watchtower:findings:record:{finding_id}",
        finding_json,
        ttl_secs,
    )


def store_alert_record(
    alert_fingerprint: str,
    alert_json: str,
    ttl_secs: int = 86400,
) -> None:
    set_with_ttl(
        f"watchtower:alerts:record:{alert_fingerprint}",
        alert_json,
        ttl_secs,
    )


def claim_alert(fingerprint: str, cooldown_secs: int) -> Optional[str]:
    """Atomically claim an alert and return an ownership token."""
    if cooldown_secs < 1:
        raise ValueError("cooldown_secs must be positive")
    key = f"watchtower:alert_cooldown:{fingerprint}"
    token = uuid.uuid4().hex
    claimed = _with_retry(
        lambda: get_client().set(
            key,
            token,
            nx=True,
            ex=cooldown_secs,
        )
    )
    return token if claimed else None


def release_alert_claim(fingerprint: str, token: str) -> bool:
    """Release only the caller's claim, even if the cooldown has rolled over."""
    if not token:
        raise ValueError("claim token is required")
    key = f"watchtower:alert_cooldown:{fingerprint}"
    script = """
    if redis.call('get', KEYS[1]) == ARGV[1] then
      return redis.call('del', KEYS[1])
    end
    return 0
    """
    return bool(
        _with_retry(
            lambda: get_client().eval(script, 1, key, token)
        )
    )


def is_alert_suppressed(fingerprint: str) -> bool:
    return key_exists(f"watchtower:alert_cooldown:{fingerprint}")


def suppress_alert(fingerprint: str, cooldown_secs: int) -> None:
    set_with_ttl(
        f"watchtower:alert_cooldown:{fingerprint}",
        "1",
        cooldown_secs,
    )
