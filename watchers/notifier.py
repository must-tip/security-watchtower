"""TLS-verified, redacted delivery for correlated Watchtower alerts."""

from __future__ import annotations

import logging
import re
import threading
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import __version__
from .config import settings
from .schema import CorrelatedAlert, Severity

logger = logging.getLogger("watchtower.notifier")

_SEV_ORDER = {
    Severity.LOW.value: 1,
    Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3,
    Severity.CRITICAL.value: 4,
}
_SEV_EMOJI = {
    Severity.CRITICAL.value: "🔴",
    Severity.HIGH.value: "🟠",
    Severity.MEDIUM.value: "🟡",
    Severity.LOW.value: "🟢",
}
_SEV_COLOR_HEX = {
    Severity.CRITICAL.value: "#FF1744",
    Severity.HIGH.value: "#FF6D00",
    Severity.MEDIUM.value: "#FFAB00",
    Severity.LOW.value: "#00E676",
}
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_PATTERNS = (
    re.compile(
        r"(?i)\b(authorization|api[_-]?key|access[_-]?token|"
        r"auth[_-]?token|password|passwd|secret)\b\s*[:=]\s*"
        r"(?:bearer\s+)?[^\s,;]+"
    ),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b"),
    re.compile(r"\b[A-Za-z0-9+/=_-]{40,}\b"),
)


def _should_notify(alert: CorrelatedAlert) -> bool:
    threshold = _SEV_ORDER[settings.notifier.min_alert_severity]
    return _SEV_ORDER.get(alert.severity, 0) >= threshold


def _sanitize(value: Optional[object], max_len: int = 300) -> str:
    """Normalize controls, redact credential shapes, and bound notification text."""
    if value is None or value == "":
        return "N/A"
    text = _CONTROL_CHARACTERS.sub("", str(value))
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = " ".join(text.split())
    return text[:max_len] + ("…" if len(text) > max_len else "")


def _build_session() -> requests.Session:
    session = requests.Session()
    # Retry only connection establishment failures. Retrying a transmitted POST
    # could duplicate a notification at providers that ignore idempotency keys.
    retry = Retry(
        total=None,
        connect=settings.notifier.max_retries,
        read=0,
        redirect=0,
        status=0,
        other=0,
        backoff_factor=0.8,
        allowed_methods=frozenset({"POST"}),
        raise_on_status=False,
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


_thread_state = threading.local()


def _get_session() -> requests.Session:
    session = getattr(_thread_state, "session", None)
    if session is None:
        session = _build_session()
        _thread_state.session = session
    return session


def _plain(text: str) -> Dict[str, str]:
    return {"type": "plain_text", "text": text}


def _build_slack_payload(alert: CorrelatedAlert) -> Dict[str, Any]:
    emoji = _SEV_EMOJI.get(alert.severity, "⚪")
    color = _SEV_COLOR_HEX.get(alert.severity, "#888888")
    fields = (
        ("System", alert.system),
        ("Service", alert.service),
        ("Endpoint", alert.endpoint),
        ("Confidence", f"{alert.confidence * 100:.0f}%"),
        ("API error", alert.api_error),
        ("Code issue", alert.code_issue),
        ("File", alert.file),
        ("Line", alert.line),
    )
    return {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": _plain(
                            _sanitize(
                                f"{emoji} Security alert: "
                                f"{alert.severity} — {alert.service}",
                                150,
                            )
                        ),
                    },
                    {
                        "type": "section",
                        "fields": [
                            _plain(f"{label}: {_sanitize(value, 250)}")
                            for label, value in fields
                        ],
                    },
                    {
                        "type": "section",
                        "text": _plain(
                            "Root cause: "
                            f"{_sanitize(alert.root_cause, 1000)}\n"
                            "Recommended fix: "
                            f"{_sanitize(alert.recommended_fix, 1000)}"
                        ),
                    },
                    {
                        "type": "context",
                        "elements": [
                            _plain(
                                f"Alert {_sanitize(alert.id[:8], 16)} | "
                                f"Fingerprint {_sanitize(alert.fingerprint[:12], 16)} | "
                                f"Trace {_sanitize(alert.trace_id, 128)}"
                            )
                        ],
                    },
                ],
            }
        ]
    }


def _build_telegram_payload(
    alert: CorrelatedAlert,
    chat_id: str,
) -> Dict[str, Any]:
    emoji = _SEV_EMOJI.get(alert.severity, "⚪")
    text = "\n".join(
        (
            _sanitize(f"{emoji} SECURITY ALERT — {alert.severity}", 100),
            "",
            f"Service: {_sanitize(alert.service)}",
            f"System: {_sanitize(alert.system)}",
            f"Endpoint: {_sanitize(alert.endpoint)}",
            f"Confidence: {alert.confidence * 100:.0f}%",
            f"API error: {_sanitize(alert.api_error)}",
            f"Code issue: {_sanitize(alert.code_issue)}",
            f"File: {_sanitize(alert.file)}:{_sanitize(alert.line, 20)}",
            "",
            f"Root cause: {_sanitize(alert.root_cause, 500)}",
            f"Fix: {_sanitize(alert.recommended_fix, 500)}",
            f"ID: {_sanitize(alert.id[:8], 16)}",
        )
    )
    return {"chat_id": chat_id, "text": text}


def _build_webhook_payload(alert: CorrelatedAlert) -> Dict[str, Any]:
    endpoint = (
        _sanitize(alert.endpoint, 2048)
        if alert.endpoint is not None
        else None
    )
    file_path = _sanitize(alert.file, 4096) if alert.file is not None else None
    trace_id = (
        _sanitize(alert.trace_id, 256)
        if alert.trace_id is not None
        else None
    )
    return {
        "alert_id": alert.id,
        "fingerprint": alert.fingerprint,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "service": _sanitize(alert.service, 200),
        "system": _sanitize(alert.system, 200),
        "endpoint": endpoint,
        "api_error": alert.api_error,
        "code_issue": alert.code_issue,
        "file": file_path,
        "line": alert.line,
        "root_cause": _sanitize(alert.root_cause, 4000),
        "recommended_fix": _sanitize(alert.recommended_fix, 4000),
        "trace_id": trace_id,
        "timestamp": alert.timestamp,
        "source": f"security-watchtower-v{__version__}",
    }


def _post(
    url: str,
    payload: Dict[str, Any],
    label: str,
    idempotency_key: str,
) -> bool:
    response: Optional[requests.Response] = None
    try:
        response = _get_session().post(
            url,
            json=payload,
            timeout=settings.notifier.request_timeout_secs,
            allow_redirects=False,
            stream=True,
            headers={
                "Content-Type": "application/json",
                "Idempotency-Key": idempotency_key,
                "User-Agent": f"SecurityWatchtower/{__version__}",
            },
        )
        if response.ok:
            logger.info(
                "%s notification sent | status=%d",
                label,
                response.status_code,
            )
            return True
        logger.warning(
            "%s notification failed | status=%d",
            label,
            response.status_code,
        )
        return False
    except requests.exceptions.Timeout:
        logger.error("%s notification timed out", label)
        return False
    except requests.exceptions.RequestException as exc:
        logger.error(
            "%s notification failed | error_type=%s",
            label,
            type(exc).__name__,
        )
        return False
    finally:
        if response is not None:
            response.close()


def send_alert(alert: CorrelatedAlert) -> bool:
    """Deliver an alert to every configured channel without leaking payloads."""
    if not _should_notify(alert):
        logger.debug(
            "Alert below notification threshold | severity=%s min=%s",
            alert.severity,
            settings.notifier.min_alert_severity,
        )
        return True

    cfg = settings.notifier
    attempted = 0
    delivered = 0

    if cfg.slack_webhook_url:
        attempted += 1
        delivered += int(
            _post(
                cfg.slack_webhook_url,
                _build_slack_payload(alert),
                "Slack",
                alert.fingerprint,
            )
        )
    if cfg.telegram_bot_token and cfg.telegram_chat_id:
        attempted += 1
        delivered += int(
            _post(
                "https://api.telegram.org/"
                f"bot{cfg.telegram_bot_token}/sendMessage",
                _build_telegram_payload(alert, cfg.telegram_chat_id),
                "Telegram",
                alert.fingerprint,
            )
        )
    if cfg.generic_webhook_url:
        attempted += 1
        delivered += int(
            _post(
                cfg.generic_webhook_url,
                _build_webhook_payload(alert),
                "Webhook",
                alert.fingerprint,
            )
        )

    if attempted == 0:
        logger.warning(
            "No notification channel configured | alert_id=%s",
            alert.id[:8],
        )
        return False
    if delivered == 0:
        logger.error(
            "Alert delivery failed on every channel | alert_id=%s channels=%d",
            alert.id[:8],
            attempted,
        )
        return False
    logger.info(
        "Alert delivered | alert_id=%s delivered=%d attempted=%d",
        alert.id[:8],
        delivered,
        attempted,
    )
    return True
