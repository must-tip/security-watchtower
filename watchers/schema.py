"""
Security Watchtower — Unified Finding Schema
Single source of truth for all events emitted by watchers.
Every field is documented. Never break this contract without versioning.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
import uuid
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict, Optional


# ─── Enumerations ─────────────────────────────────────────────────────────────

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def numeric(self) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]

    @classmethod
    def from_string(cls, s: str) -> "Severity":
        return cls(s.upper())


class FindingSource(str, Enum):
    API = "api"         # Emitted by api_watcher
    CODE = "code"        # Emitted by code_watcher
    CORRELATOR = "correlator"  # Emitted by correlator (correlated pair)
    MANUAL = "manual"      # Human-entered finding
    SCHEDULER = "scheduler"   # Periodic scan finding


class FindingType(str, Enum):
    # API watcher types
    HTTP_5XX = "http_5xx"
    HTTP_4XX = "http_4xx"
    HIGH_LATENCY = "high_latency"
    ENDPOINT_DOWN = "endpoint_down"
    SSL_ERROR = "ssl_error"
    AUTH_FAILURE = "auth_failure"
    RATE_LIMIT_HIT = "rate_limit_hit"
    ANOMALOUS_RESPONSE = "anomalous_response"

    # Code watcher types
    HARDCODED_SECRET = "hardcoded_secret"
    SQL_INJECTION_RISK = "sql_injection_risk"
    NULL_DEREFERENCE = "null_dereference"
    REENTRANCY_RISK = "reentrancy_risk"
    EVAL_USAGE = "eval_usage"
    WEAK_CRYPTO = "weak_crypto"
    SSRF_RISK = "ssrf_risk"
    MISSING_AUTH_CHECK = "missing_auth_check"
    MASS_ASSIGNMENT = "mass_assignment"
    OPEN_REDIRECT = "open_redirect"
    FILE_MODIFIED = "file_modified"
    SUSPICIOUS_PATTERN = "suspicious_pattern"

    # Correlator types
    CORRELATED_FAILURE = "correlated_failure"

    # Generic
    UNKNOWN = "unknown"


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    PATCHED = "PATCHED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUPPRESSED = "SUPPRESSED"


# ─── Core Finding Dataclass ───────────────────────────────────────────────────

@dataclass
class Finding:
    """
    Canonical event object. All watchers emit this schema into Redis.
    Immutable once created — update status via FindingUpdate.
    """

    # Identity
    id: str            # UUID4
    source: str            # FindingSource value
    type: str            # FindingType value
    severity: str            # Severity value

    # Targeting
    service: str            # Which microservice (e.g. "auth-service")
    system: str            # Which platform system (e.g. "banking")

    # Optional targeting details
    endpoint: Optional[str]  # HTTP path, e.g. "/api/login"
    file: Optional[str]  # Source file path, e.g. "auth/login.py"
    line: Optional[int]  # Line number in file
    function: Optional[str]  # Function or method name

    # Correlation
    trace_id: Optional[str]  # Request trace ID for linking API ↔ code
    fingerprint: str            # SHA-256 of (service+endpoint+type+file+line) — dedup key

    # Confidence (0.0–1.0)
    confidence: float

    # Evidence
    title: str
    description: str
    context: Dict[str, Any]  # Arbitrary extra data (status code, snippet, etc.)

    # Lifecycle
    timestamp: float           # Unix epoch (UTC)
    status: str             # FindingStatus value

    # Schema version for forward compatibility
    schema_version: str = "2.0"

    def __post_init__(self) -> None:
        try:
            uuid.UUID(self.id)
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("finding id must be a UUID") from exc
        FindingSource(self.source)
        FindingType(self.type)
        Severity.from_string(self.severity)
        FindingStatus(self.status)
        if self.schema_version != "2.0":
            raise ValueError(f"unsupported finding schema: {self.schema_version!r}")
        for name, value, maximum in (
            ("service", self.service, 200),
            ("system", self.system, 200),
            ("title", self.title, 500),
            ("description", self.description, 4000),
        ):
            if not isinstance(value, str) or not value.strip() or len(value) > maximum:
                raise ValueError(f"{name} must contain 1 to {maximum} characters")
        for name, value, maximum in (
            ("endpoint", self.endpoint, 2048),
            ("file", self.file, 4096),
            ("function", self.function, 500),
            ("trace_id", self.trace_id, 256),
        ):
            if value is not None and (
                not isinstance(value, str) or len(value) > maximum
            ):
                raise ValueError(f"{name} must be null or at most {maximum} characters")
        if self.line is not None and (
            not isinstance(self.line, int) or isinstance(self.line, bool) or self.line < 1
        ):
            raise ValueError("line must be a positive integer or null")
        if (
            not isinstance(self.fingerprint, str)
            or len(self.fingerprint) != 32
            or any(char not in "0123456789abcdef" for char in self.fingerprint)
        ):
            raise ValueError("fingerprint must be 32 lowercase hexadecimal characters")
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, (int, float))
            or not math.isfinite(float(self.confidence))
            or not 0.0 <= float(self.confidence) <= 1.0
        ):
            raise ValueError("confidence must be between 0 and 1")
        if (
            isinstance(self.timestamp, bool)
            or not isinstance(self.timestamp, (int, float))
            or not math.isfinite(float(self.timestamp))
            or self.timestamp <= 0
        ):
            raise ValueError("timestamp must be a positive finite number")
        if not isinstance(self.context, dict):
            raise ValueError("context must be an object")
        try:
            json.dumps(self.context, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("context must be JSON serializable") from exc

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        if not isinstance(d, dict):
            raise ValueError("finding payload must be an object")
        allowed = set(cls.__dataclass_fields__)
        unknown = set(d) - allowed
        if unknown:
            raise ValueError(f"unknown finding fields: {sorted(unknown)}")
        return cls(**d)

    @classmethod
    def from_json(cls, s: str) -> "Finding":
        try:
            payload = json.loads(s)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError("finding payload is not valid JSON") from exc
        return cls.from_dict(payload)

    @property
    def severity_numeric(self) -> int:
        return Severity.from_string(self.severity).numeric

    @property
    def is_critical(self) -> bool:
        return self.severity in (Severity.CRITICAL.value, Severity.HIGH.value)

    def matches(self, other: "Finding") -> bool:
        """Check if two findings refer to the same service+endpoint pair (for correlation)."""
        return (
            self.service == other.service
            and self.endpoint == other.endpoint
            and self.source != other.source   # must be from different watchers
        )


# ─── Correlated Alert ─────────────────────────────────────────────────────────

@dataclass
class CorrelatedAlert:
    """
    Produced by the correlator when an API finding and a Code finding
    are matched to the same service/endpoint. This is the artifact
    that gets sent to the notifier.
    """
    id: str
    service: str
    system: str
    endpoint: Optional[str]
    api_finding_id: str
    code_finding_id: str
    api_error: str            # FindingType of the API event
    code_issue: str            # FindingType of the code event
    file: Optional[str]
    line: Optional[int]
    severity: str            # Max of api + code severity
    confidence: float          # 0.0–1.0
    root_cause: str            # Human-readable root cause summary
    recommended_fix: str
    timestamp: float
    fingerprint: str            # SHA-256 dedup key for this alert
    trace_id: Optional[str]
    context: Dict[str, Any]

    def __post_init__(self) -> None:
        for name in ("id", "api_finding_id", "code_finding_id"):
            try:
                uuid.UUID(getattr(self, name))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError(f"{name} must be a UUID") from exc
        FindingType(self.api_error)
        FindingType(self.code_issue)
        Severity.from_string(self.severity)
        for name, value, maximum in (
            ("service", self.service, 200),
            ("system", self.system, 200),
            ("root_cause", self.root_cause, 4000),
            ("recommended_fix", self.recommended_fix, 4000),
        ):
            if not isinstance(value, str) or not value.strip() or len(value) > maximum:
                raise ValueError(f"{name} must contain 1 to {maximum} characters")
        for name, value, maximum in (
            ("endpoint", self.endpoint, 2048),
            ("file", self.file, 4096),
            ("trace_id", self.trace_id, 256),
        ):
            if value is not None and (
                not isinstance(value, str) or not value or len(value) > maximum
            ):
                raise ValueError(f"{name} must be null or contain 1 to {maximum} characters")
        if self.line is not None and (
            not isinstance(self.line, int) or isinstance(self.line, bool) or self.line < 1
        ):
            raise ValueError("line must be a positive integer or null")
        if (
            isinstance(self.confidence, bool)
            or not isinstance(self.confidence, (int, float))
            or not math.isfinite(float(self.confidence))
            or not 0.0 <= float(self.confidence) <= 1.0
        ):
            raise ValueError("confidence must be between 0 and 1")
        if (
            isinstance(self.timestamp, bool)
            or not isinstance(self.timestamp, (int, float))
            or not math.isfinite(float(self.timestamp))
            or self.timestamp <= 0
        ):
            raise ValueError("timestamp must be a positive finite number")
        if (
            not isinstance(self.fingerprint, str)
            or len(self.fingerprint) != 32
            or any(char not in "0123456789abcdef" for char in self.fingerprint)
        ):
            raise ValueError("fingerprint must be 32 lowercase hexadecimal characters")
        if not isinstance(self.context, dict):
            raise ValueError("context must be an object")
        try:
            json.dumps(self.context, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise ValueError("context must be JSON serializable") from exc

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )


# ─── Factory Functions ────────────────────────────────────────────────────────

def _compute_fingerprint(*parts: Any) -> str:
    """SHA-256 fingerprint from significant fields. Used for deduplication."""
    raw = "|".join(str(p or "").lower() for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def new_finding(
    *,
    source: str,
    type: str,
    severity: str,
    service: str,
    system: str,
    title: str,
    description: str,
    endpoint: Optional[str] = None,
    file: Optional[str] = None,
    line: Optional[int] = None,
    function: Optional[str] = None,
    trace_id: Optional[str] = None,
    confidence: float = 0.8,
    context: Optional[Dict[str, Any]] = None,
    status: str = FindingStatus.OPEN.value,
) -> Finding:
    """
    Primary factory for creating Finding instances.
    Automatically sets id, timestamp, fingerprint.
    """
    source_value = FindingSource(source).value
    type_value = FindingType(type).value
    severity_value = Severity.from_string(severity).value
    status_value = FindingStatus(status).value
    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not math.isfinite(float(confidence))
        or not 0.0 <= float(confidence) <= 1.0
    ):
        raise ValueError("confidence must be between 0 and 1")
    fingerprint = _compute_fingerprint(service, endpoint, type_value, file, line)
    return Finding(
        id=str(uuid.uuid4()),
        source=source_value,
        type=type_value,
        severity=severity_value,
        service=service,
        system=system,
        endpoint=endpoint,
        file=file,
        line=line,
        function=function,
        trace_id=trace_id,
        fingerprint=fingerprint,
        confidence=float(confidence),
        title=title,
        description=description,
        context=context or {},
        timestamp=time.time(),
        status=status_value,
    )


def new_correlated_alert(
    *,
    api_finding: Finding,
    code_finding: Finding,
    confidence: float,
    root_cause: str,
    recommended_fix: str,
) -> CorrelatedAlert:
    """
    Build a CorrelatedAlert from a matched API+Code pair.
    Severity is the maximum of the two findings.
    """
    sev_a = Severity.from_string(api_finding.severity).numeric
    sev_c = Severity.from_string(code_finding.severity).numeric
    max_sev = Severity.CRITICAL if max(sev_a, sev_c) >= 4 \
        else Severity.HIGH if max(sev_a, sev_c) >= 3 \
        else Severity.MEDIUM if max(sev_a, sev_c) >= 2 \
        else Severity.LOW

    fingerprint = _compute_fingerprint(
        api_finding.service,
        api_finding.endpoint,
        api_finding.type,
        code_finding.file,
        code_finding.line,
    )

    return CorrelatedAlert(
        id=str(uuid.uuid4()),
        service=api_finding.service,
        system=api_finding.system,
        endpoint=api_finding.endpoint,
        api_finding_id=api_finding.id,
        code_finding_id=code_finding.id,
        api_error=api_finding.type,
        code_issue=code_finding.type,
        file=code_finding.file,
        line=code_finding.line,
        severity=max_sev.value,
        confidence=confidence,
        root_cause=root_cause,
        recommended_fix=recommended_fix,
        timestamp=time.time(),
        fingerprint=fingerprint,
        trace_id=api_finding.trace_id or code_finding.trace_id,
        context={
            "api_context": api_finding.context,
            "code_context": code_finding.context,
        },
    )
