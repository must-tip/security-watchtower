"""Asynchronous, side-effect-free health endpoint watcher."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from collections import defaultdict
from typing import Optional
from urllib.parse import urlsplit

import aiohttp
from aiohttp import (
    ClientSession,
    ClientTimeout,
    DefaultResolver,
    TCPConnector,
)
from aiohttp.abc import AbstractResolver

from .config import settings
from .redis_client import push_finding, store_finding_record
from .schema import Finding, FindingSource, FindingType, Severity, new_finding

logger = logging.getLogger("watchtower.api_watcher")

_failure_counts: dict[str, int] = defaultdict(int)
_endpoint_states: dict[str, str] = defaultdict(lambda: "UP")


class SafeResolver(AbstractResolver):
    def __init__(self, *, allow_loopback: bool) -> None:
        self._resolver = DefaultResolver()
        self._allow_loopback = allow_loopback

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[dict[str, object]]:
        results = await self._resolver.resolve(host, port, family)
        if not results:
            raise OSError("hostname did not resolve")
        for result in results:
            address = ipaddress.ip_address(str(result["host"]).split("%", 1)[0])
            if address.is_loopback:
                if not self._allow_loopback:
                    raise OSError("hostname resolved to a prohibited address")
                continue
            if (
                address.is_private
                or address.is_link_local
                or address.is_multicast
                or address.is_unspecified
                or address.is_reserved
            ):
                raise OSError("hostname resolved to a prohibited address")
        return results

    async def close(self) -> None:
        await self._resolver.close()


def _target_metadata(url: str) -> tuple[str, str]:
    parsed = urlsplit(url)
    hostname = parsed.hostname or "unknown-service"
    service = hostname.split(".", 1)[0]
    endpoint = parsed.path
    return service, endpoint


def _classify_status(status: int) -> str:
    if status in {401, 403}:
        return FindingType.AUTH_FAILURE.value
    if status == 429:
        return FindingType.RATE_LIMIT_HIT.value
    if 500 <= status <= 599:
        return FindingType.HTTP_5XX.value
    if 400 <= status <= 499:
        return FindingType.HTTP_4XX.value
    return FindingType.ANOMALOUS_RESPONSE.value


def _record_failure(key: str) -> int:
    _failure_counts[key] += 1
    return _failure_counts[key]


def _record_success(key: str) -> None:
    _failure_counts[key] = 0
    _endpoint_states[key] = "UP"


def _down_finding(
    *,
    url: str,
    service: str,
    endpoint: str,
    failures: int,
    title: str,
    error_kind: str,
) -> Finding:
    return new_finding(
        source=FindingSource.API.value,
        type=FindingType.ENDPOINT_DOWN.value,
        severity=Severity.CRITICAL.value,
        service=service,
        system=settings.platform,
        title=title,
        description=(
            f"GET health probe failed for {service}{endpoint}; "
            f"consecutive failures: {failures}"
        ),
        endpoint=endpoint,
        confidence=min(0.8 + failures * 0.05, 0.99),
        context={
            "failures": failures,
            "error_kind": error_kind,
            "target_scheme": urlsplit(url).scheme,
        },
    )


async def _probe_endpoint(
    session: ClientSession,
    url: str,
) -> Optional[Finding]:
    cfg = settings.api_watcher
    service, endpoint = _target_metadata(url)
    key = url
    started = time.monotonic()

    try:
        async with session.get(
            url,
            timeout=ClientTimeout(total=cfg.request_timeout_secs),
            headers={
                "User-Agent": cfg.user_agent,
                "Accept": "application/json, text/plain;q=0.9, */*;q=0.1",
            },
            allow_redirects=False,
        ) as response:
            latency_ms = (time.monotonic() - started) * 1000
            status = response.status

            if 200 <= status <= 299:
                _record_success(key)
                if latency_ms <= cfg.latency_warn_ms:
                    logger.debug(
                        "Probe healthy | service=%s endpoint=%s status=%d latency_ms=%.0f",
                        service,
                        endpoint,
                        status,
                        latency_ms,
                    )
                    return None
                logger.warning(
                    "Probe slow | service=%s endpoint=%s latency_ms=%.0f",
                    service,
                    endpoint,
                    latency_ms,
                )
                return new_finding(
                    source=FindingSource.API.value,
                    type=FindingType.HIGH_LATENCY.value,
                    severity=Severity.MEDIUM.value,
                    service=service,
                    system=settings.platform,
                    title=f"High latency on {service}{endpoint}",
                    description=(
                        f"Health endpoint responded in {latency_ms:.0f} ms; "
                        f"threshold is {cfg.latency_warn_ms:.0f} ms"
                    ),
                    endpoint=endpoint,
                    confidence=0.9,
                    context={
                        "latency_ms": round(latency_ms, 2),
                        "http_status": status,
                        "threshold_ms": cfg.latency_warn_ms,
                    },
                )

            failures = _record_failure(key)
            if failures < cfg.failure_threshold:
                logger.info(
                    "Transient endpoint failure | service=%s endpoint=%s "
                    "status=%d failures=%d threshold=%d",
                    service,
                    endpoint,
                    status,
                    failures,
                    cfg.failure_threshold,
                )
                return None

            _endpoint_states[key] = "DOWN" if status >= 500 else "DEGRADED"
            severity = Severity.CRITICAL if status >= 500 else Severity.HIGH
            return new_finding(
                source=FindingSource.API.value,
                type=_classify_status(status),
                severity=severity.value,
                service=service,
                system=settings.platform,
                title=f"Persistent HTTP {status} on {service}{endpoint}",
                description=(
                    f"GET health probe returned HTTP {status}; "
                    f"consecutive failures: {failures}"
                ),
                endpoint=endpoint,
                confidence=min(0.7 + failures * 0.05, 0.99),
                context={
                    "http_status": status,
                    "latency_ms": round(latency_ms, 2),
                    "method": "GET",
                    "failures": failures,
                    "endpoint_state": _endpoint_states[key],
                },
            )

    except asyncio.CancelledError:
        raise
    except asyncio.TimeoutError:
        failures = _record_failure(key)
        logger.warning(
            "Probe timeout | service=%s endpoint=%s failures=%d",
            service,
            endpoint,
            failures,
        )
        if failures < cfg.failure_threshold:
            return None
        _endpoint_states[key] = "DOWN"
        return _down_finding(
            url=url,
            service=service,
            endpoint=endpoint,
            failures=failures,
            title=f"Endpoint timeout: {service}{endpoint}",
            error_kind="timeout",
        )
    except aiohttp.ClientSSLError:
        _endpoint_states[key] = "DOWN"
        logger.error(
            "TLS validation failed | service=%s endpoint=%s",
            service,
            endpoint,
        )
        return new_finding(
            source=FindingSource.API.value,
            type=FindingType.SSL_ERROR.value,
            severity=Severity.HIGH.value,
            service=service,
            system=settings.platform,
            title=f"TLS validation failed: {service}{endpoint}",
            description="The health probe could not validate the endpoint certificate",
            endpoint=endpoint,
            confidence=0.99,
            context={"error_kind": "tls_validation"},
        )
    except aiohttp.ClientError as exc:
        failures = _record_failure(key)
        logger.warning(
            "Probe client error | service=%s endpoint=%s failures=%d error_type=%s",
            service,
            endpoint,
            failures,
            type(exc).__name__,
        )
        if failures < cfg.failure_threshold:
            return None
        _endpoint_states[key] = "DOWN"
        return _down_finding(
            url=url,
            service=service,
            endpoint=endpoint,
            failures=failures,
            title=f"Service unreachable: {service}{endpoint}",
            error_kind=type(exc).__name__,
        )


def _persist_finding(finding: Finding) -> None:
    payload = finding.to_json()
    push_finding(payload)
    store_finding_record(finding.id, payload)


async def _emit(finding: Finding) -> None:
    await asyncio.to_thread(_persist_finding, finding)
    logger.info(
        "API finding emitted | id=%s severity=%s type=%s service=%s endpoint=%s",
        finding.id[:8],
        finding.severity,
        finding.type,
        finding.service,
        finding.endpoint,
    )


async def _wait_for_next_poll(
    stop_event: Optional[asyncio.Event],
    timeout: float,
) -> None:
    if stop_event is None:
        await asyncio.sleep(timeout)
        return
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        return


async def watch(stop_event: Optional[asyncio.Event] = None) -> None:
    cfg = settings.api_watcher
    connector = TCPConnector(
        limit=cfg.max_concurrent,
        resolver=SafeResolver(allow_loopback=False),
    )
    logger.info(
        "API watcher starting | targets=%d poll_interval=%.0fs",
        len(cfg.target_urls),
        cfg.poll_interval_secs,
    )

    async with ClientSession(connector=connector) as session:
        while not (stop_event and stop_event.is_set()):
            results = await asyncio.gather(
                *(_probe_endpoint(session, url) for url in cfg.target_urls),
                return_exceptions=True,
            )
            for result in results:
                if isinstance(result, Finding):
                    await _emit(result)
                elif isinstance(result, asyncio.CancelledError):
                    raise result
                elif isinstance(result, BaseException):
                    raise RuntimeError(
                        f"probe task failed with {type(result).__name__}"
                    ) from result
            await _wait_for_next_poll(stop_event, cfg.poll_interval_secs)


if __name__ == "__main__":
    settings.validate()
    asyncio.run(watch())
