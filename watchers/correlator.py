"""
Security Watchtower — Correlation Engine
Consumes findings from Redis, correlates API ↔ Code findings by
service+endpoint within a time window, scores confidence, and
emits enriched CorrelatedAlerts.

Deduplicates alerts by fingerprint to prevent notification spam.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import deque
from typing import Deque, Dict, List, Optional, Tuple

from .config import settings
from .notifier import send_alert
from .redis_client import (
    claim_alert,
    pop_finding,
    publish_alert,
    release_alert_claim,
    store_alert_record,
)
from .schema import (
    Finding,
    FindingSource,
    FindingType,
    new_correlated_alert,
)

logger = logging.getLogger("watchtower.correlator")

# ─── Root Cause + Fix Knowledge Base ─────────────────────────────────────────

# Maps (api_type, code_type) → (root_cause, recommended_fix)
_CORRELATION_KB: Dict[Tuple[str, str], Tuple[str, str]] = {
    (FindingType.HTTP_5XX.value, FindingType.NULL_DEREFERENCE.value): (
        "A NullPointerException in the handler is causing unhandled 500 responses.",
        "Add None-guards before chained attribute access. Use Optional[T] typing."
    ),
    (FindingType.HTTP_5XX.value, FindingType.SQL_INJECTION_RISK.value): (
        "Unsanitized user input in the SQL query is likely causing DB errors and 500s.",
        "Replace f-string / concatenated SQL with parameterized queries (ORM or cursor.execute with params tuple)."  # noqa: E501
    ),
    (FindingType.HTTP_5XX.value, FindingType.REENTRANCY_RISK.value): (
        "Smart contract reentrancy is likely causing transaction reversions which surface as 500 errors.",
        "Implement CEI pattern (Checks-Effects-Interactions) + add OpenZeppelin ReentrancyGuard."
    ),
    (FindingType.AUTH_FAILURE.value, FindingType.MISSING_AUTH_CHECK.value): (
        "The endpoint is returning 401/403 because the auth decorator or middleware guard is absent in the handler.",  # noqa: E501
        "Add @login_required / @require_auth / JWT middleware to the route handler."
    ),
    (FindingType.AUTH_FAILURE.value, FindingType.HARDCODED_SECRET.value): (
        "Hardcoded credentials in source may have been rotated/revoked, causing authentication failures.",
        "Remove hardcoded secrets immediately. Load from environment variables or a secrets manager (Vault/AWS SSM)."  # noqa: E501
    ),
    (FindingType.HTTP_5XX.value, FindingType.EVAL_USAGE.value): (
        "eval()/exec() with untrusted input is likely raising exceptions that become 500 responses.",
        "Remove eval()/exec(). Use safe deserialization (json.loads) or a whitelist-based dispatcher."
    ),
    (FindingType.HTTP_5XX.value, FindingType.HARDCODED_SECRET.value): (
        "Hardcoded secret may have been rotated, causing authentication with downstream services to fail.",
        "Externalize all secrets to environment variables or a secrets manager. Rotate immediately."
    ),
    (FindingType.ENDPOINT_DOWN.value, FindingType.NULL_DEREFERENCE.value): (
        "Startup crash due to null dereference is preventing the service from starting.",
        "Add defensive None checks at initialization. Add startup health assertions."
    ),
    (FindingType.HIGH_LATENCY.value, FindingType.SQL_INJECTION_RISK.value): (
        "Non-parameterized query is likely causing full table scans (missing index path), producing high latency.",  # noqa: E501
        "Parameterize queries. Add EXPLAIN ANALYZE and add appropriate indexes."
    ),
    (FindingType.HTTP_5XX.value, FindingType.SSRF_RISK.value): (
        "SSRF attempt on the endpoint may be causing timeout or connection errors that return 500.",
        "Validate and whitelist all outbound URLs. Use a URL allow-list + DNS rebinding protection."
    ),
    (FindingType.RATE_LIMIT_HIT.value, FindingType.MISSING_AUTH_CHECK.value): (
        "Unauthenticated endpoint is being hammered — no auth gate to filter bots/scrapers.",
        "Add authentication to this endpoint. Enforce per-IP rate limiting independently."
    ),
}

_DEFAULT_ROOT_CAUSE = (
    "An API-layer anomaly correlates with a code-level security issue on the same service/endpoint.",
    "Review the linked code finding for security hardening. Add defensive error handling."
)


def _lookup_root_cause(api_type: str, code_type: str) -> Tuple[str, str]:
    return _CORRELATION_KB.get(
        (api_type, code_type),
        _DEFAULT_ROOT_CAUSE
    )


def _findings_share_scope(api: Finding, code: Finding) -> bool:
    """Match exact routes, or known issue pairs at service scope."""
    if (
        api.source != FindingSource.API.value
        or code.source != FindingSource.CODE.value
        or api.service != code.service
        or abs(api.timestamp - code.timestamp)
        > settings.correlator.correlation_window_secs
    ):
        return False
    if api.endpoint and code.endpoint:
        return api.endpoint == code.endpoint
    return (api.type, code.type) in _CORRELATION_KB


# ─── Confidence Scoring ───────────────────────────────────────────────────────

def _compute_confidence(api: Finding, code: Finding) -> float:
    """
    Heuristic confidence score for a correlation.
    Higher when:
      - same trace_id (very strong signal)
      - same endpoint exact match
      - high individual confidence scores
      - findings close in time
    """
    score = 0.5  # base

    # Trace ID match — strongest signal
    if api.trace_id and code.trace_id and api.trace_id == code.trace_id:
        score += 0.35

    # Same endpoint (already required for match, but reward exact match)
    if api.endpoint and code.endpoint and api.endpoint == code.endpoint:
        score += 0.10

    # Time proximity (within 60s → +0.10, within 300s → +0.05)
    dt = abs(api.timestamp - code.timestamp)
    if dt <= 60:
        score += 0.10
    elif dt <= 300:
        score += 0.05

    # Both high-severity → stronger signal
    if api.severity_numeric >= 3 and code.severity_numeric >= 3:
        score += 0.08

    # Known KB pairing
    if (api.type, code.type) in _CORRELATION_KB:
        score += 0.12

    # Weighted by individual confidence
    score *= (api.confidence * 0.5 + code.confidence * 0.5)

    return min(round(score, 3), 0.99)


# ─── Correlation Buffer ───────────────────────────────────────────────────────

class _CorrelationBuffer:
    """
    Thread-safe time-windowed buffer for unmatched findings.
    Automatically evicts entries older than `window_secs`.
    """

    def __init__(self, window_secs: float, max_size: int):
        self._window = window_secs
        self._maxsize = max_size
        self._api: Deque[Finding] = deque(maxlen=max_size)
        self._code: Deque[Finding] = deque(maxlen=max_size)
        self._lock = threading.Lock()

    def add(self, finding: Finding) -> None:
        with self._lock:
            if finding.source == FindingSource.API.value:
                self._api.append(finding)
            elif finding.source == FindingSource.CODE.value:
                self._code.append(finding)

    def find_matches(self) -> List[Tuple[Finding, Finding]]:
        """
        Return all (api, code) pairs that match by service+endpoint
        and are within the time window. Thread-safe.
        """
        now = time.time()
        matches: List[Tuple[Finding, Finding]] = []
        with self._lock:
            # Evict expired
            fresh_api = [f for f in self._api if now - f.timestamp < self._window]
            fresh_code = [f for f in self._code if now - f.timestamp < self._window]

            used_api: set[str] = set()
            used_code: set[str] = set()
            for api in fresh_api:
                for code in fresh_code:
                    if (
                        api.id not in used_api
                        and code.id not in used_code
                        and _findings_share_scope(api, code)
                    ):
                        matches.append((api, code))
                        used_api.add(api.id)
                        used_code.add(code.id)

            # Update deques
            self._api = deque(fresh_api, maxlen=self._maxsize)
            self._code = deque(fresh_code, maxlen=self._maxsize)

        return matches

    def remove_pair(self, api: Finding, code: Finding) -> None:
        with self._lock:
            try:
                self._api.remove(api)
            except ValueError:
                pass
            try:
                self._code.remove(code)
            except ValueError:
                pass

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {"api_buffer": len(self._api), "code_buffer": len(self._code)}


# ─── Correlator Loop ──────────────────────────────────────────────────────────

def correlate(stop_event: Optional[threading.Event] = None) -> None:
    """
    Main correlation loop.
    Consumes findings from Redis, buffers by source,
    finds service+endpoint matches, computes confidence,
    emits CorrelatedAlerts above threshold.
    """
    cfg = settings.correlator
    buffer = _CorrelationBuffer(
        window_secs=cfg.correlation_window_secs,
        max_size=cfg.buffer_max_size,
    )

    logger.info(
        "Correlator starting | window=%.0fs buffer_size=%d min_confidence=%.2f",
        cfg.correlation_window_secs, cfg.buffer_max_size, cfg.min_confidence
    )
    next_stats_at = time.monotonic() + 60

    while not (stop_event and stop_event.is_set()):
        # ── consume one finding from Redis ────────────────────────────────────
        try:
            raw = pop_finding(timeout_secs=cfg.poll_timeout_secs)
        except Exception as exc:
            logger.error(
                "Redis pop failed | error_type=%s",
                type(exc).__name__,
            )
            if stop_event:
                stop_event.wait(2)
            else:
                time.sleep(2)
            continue

        if raw is None:
            continue  # timeout — loop again

        try:
            finding = Finding.from_json(raw)
        except Exception as exc:
            raw_hash = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
            logger.warning(
                "Malformed finding discarded | error_type=%s bytes=%d sha256=%s",
                type(exc).__name__,
                len(raw),
                raw_hash,
            )
            continue

        logger.debug(
            "Received finding | source=%s service=%s endpoint=%s type=%s severity=%s",
            finding.source, finding.service, finding.endpoint, finding.type, finding.severity
        )

        # Skip findings that are already correlated or suppressed
        if finding.source not in {
            FindingSource.API.value,
            FindingSource.CODE.value,
        }:
            continue

        buffer.add(finding)

        # ── match pass ────────────────────────────────────────────────────────
        matches = buffer.find_matches()
        for api_f, code_f in matches:
            confidence = _compute_confidence(api_f, code_f)

            if confidence < cfg.min_confidence:
                logger.debug(
                    "Low-confidence correlation skipped | confidence=%.2f service=%s",
                    confidence, api_f.service
                )
                buffer.remove_pair(api_f, code_f)
                continue

            root_cause, fix = _lookup_root_cause(api_f.type, code_f.type)
            alert = new_correlated_alert(
                api_finding=api_f,
                code_finding=code_f,
                confidence=confidence,
                root_cause=root_cause,
                recommended_fix=fix,
            )

            # ── deduplication ─────────────────────────────────────────────────
            try:
                store_alert_record(alert.fingerprint, alert.to_json())
                claim_token = claim_alert(
                    alert.fingerprint,
                    settings.notifier.alert_cooldown_secs,
                )
            except Exception as exc:
                logger.error(
                    "Failed to persist or claim alert | error_type=%s",
                    type(exc).__name__,
                )
                buffer.remove_pair(api_f, code_f)
                continue

            if not claim_token:
                logger.info(
                    "Alert suppressed (cooldown) | fingerprint=%s service=%s",
                    alert.fingerprint[:12], alert.service
                )
                buffer.remove_pair(api_f, code_f)
                continue

            # ── publish ────────────────────────────────────────────────────────
            try:
                publish_alert(alert.to_json())
            except Exception as exc:
                logger.error(
                    "Failed to publish claimed alert | error_type=%s",
                    type(exc).__name__,
                )
                try:
                    release_alert_claim(alert.fingerprint, claim_token)
                except Exception as release_exc:
                    logger.error(
                        "Failed to release alert claim | error_type=%s",
                        type(release_exc).__name__,
                    )
                buffer.remove_pair(api_f, code_f)
                continue

            # ── send notification ──────────────────────────────────────────────
            delivered = False
            try:
                delivered = send_alert(alert)
            except Exception as exc:
                logger.error(
                    "Notifier failed | error_type=%s",
                    type(exc).__name__,
                )
            if not delivered:
                try:
                    release_alert_claim(alert.fingerprint, claim_token)
                except Exception as release_exc:
                    logger.error(
                        "Failed to release undelivered alert claim | error_type=%s",
                        type(release_exc).__name__,
                    )

            buffer.remove_pair(api_f, code_f)

            logger.info(
                "Correlated alert emitted | id=%s severity=%s confidence=%.2f service=%s endpoint=%s",
                alert.id[:8], alert.severity, alert.confidence, alert.service, alert.endpoint
            )

        # ── periodic stats log ────────────────────────────────────────────────
        if time.monotonic() >= next_stats_at:
            stats = buffer.stats()
            logger.info("Buffer stats | api=%d code=%d", stats["api_buffer"], stats["code_buffer"])
            next_stats_at = time.monotonic() + 60


# ─── Standalone Entry Point ───────────────────────────────────────────────────

if __name__ == "__main__":
    settings.validate()
    correlate()
