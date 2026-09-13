"""
Security Watchtower — Test Suite
Tests for schema, correlator logic, notifier filtering, and security patterns.
Run with: pytest tests/ -v
"""

import json
import time
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from watchers.schema import FindingSource, FindingType, Severity, new_finding


# ─── Schema Tests ─────────────────────────────────────────────────────────────

class TestFindingSchema:

    def test_new_finding_has_required_fields(self):

        f = new_finding(
            source=FindingSource.API.value,
            type=FindingType.HTTP_5XX.value,
            severity=Severity.HIGH.value,
            service="auth-service",
            system="banking",
            title="Test finding",
            description="Test description",
            endpoint="/api/login",
        )
        assert f.id
        assert f.fingerprint
        assert f.timestamp > 0
        assert f.severity == "HIGH"
        assert f.confidence == 0.8  # default

    def test_finding_fingerprint_is_deterministic(self):

        kwargs = dict(
            source=FindingSource.API.value,
            type=FindingType.HTTP_5XX.value,
            severity=Severity.HIGH.value,
            service="auth-service",
            system="banking",
            title="Test",
            description="Test",
            endpoint="/api/login",
        )
        f1 = new_finding(**kwargs)
        f2 = new_finding(**kwargs)
        # Same significant fields → same fingerprint
        assert f1.fingerprint == f2.fingerprint
        # But different IDs
        assert f1.id != f2.id

    def test_finding_roundtrip_json(self):
        from watchers.schema import new_finding, Finding, FindingSource, FindingType, Severity

        f = new_finding(
            source=FindingSource.CODE.value,
            type=FindingType.HARDCODED_SECRET.value,
            severity=Severity.CRITICAL.value,
            service="auth-service",
            system="banking",
            title="Secret found",
            description="Found in file",
            file="auth/login.py",
            line=42,
        )
        restored = Finding.from_json(f.to_json())
        assert restored.id == f.id
        assert restored.severity == f.severity
        assert restored.file == f.file
        assert restored.line == f.line
        assert restored.fingerprint == f.fingerprint

    def test_severity_ordering(self):
        from watchers.schema import Severity

        assert Severity.LOW.numeric < Severity.MEDIUM.numeric
        assert Severity.MEDIUM.numeric < Severity.HIGH.numeric
        assert Severity.HIGH.numeric < Severity.CRITICAL.numeric

    def test_confidence_outside_0_1_is_rejected(self):

        with pytest.raises(ValueError, match="between 0 and 1"):
            new_finding(
                source=FindingSource.API.value,
                type=FindingType.HTTP_5XX.value,
                severity=Severity.LOW.value,
                service="s",
                system="s",
                title="t",
                description="d",
                confidence=-5.0,
            )
        with pytest.raises(ValueError, match="between 0 and 1"):
            new_finding(
                source=FindingSource.API.value,
                type=FindingType.HTTP_5XX.value,
                severity=Severity.LOW.value,
                service="s",
                system="s",
                title="t",
                description="d",
                confidence=999.0,
            )

    def test_unknown_schema_fields_are_rejected(self):
        from watchers.schema import Finding

        with pytest.raises(ValueError, match="unknown finding fields"):
            Finding.from_dict({"unexpected": True})


# ─── Correlation Buffer Tests ──────────────────────────────────────────────────

class TestCorrelationBuffer:

    def _make_api_finding(self, service="auth", endpoint="/login"):
        return new_finding(
            source=FindingSource.API.value,
            type=FindingType.HTTP_5XX.value,
            severity=Severity.HIGH.value,
            service=service, system="banking",
            title="500 error", description="test",
            endpoint=endpoint,
        )

    def _make_code_finding(self, service="auth", endpoint="/login", file="auth/login.py", line=42):
        return new_finding(
            source=FindingSource.CODE.value,
            type=FindingType.NULL_DEREFERENCE.value,
            severity=Severity.MEDIUM.value,
            service=service, system="banking",
            title="Null deref", description="test",
            endpoint=endpoint, file=file, line=line,
        )

    def test_api_code_pair_matches(self):

        api = self._make_api_finding()
        code = self._make_code_finding()
        assert api.matches(code)

    def test_different_endpoints_dont_match(self):
        api = self._make_api_finding(endpoint="/login")
        code = self._make_code_finding(endpoint="/register")
        assert not api.matches(code)

    def test_same_source_dont_match(self):
        api1 = self._make_api_finding()
        api2 = self._make_api_finding()
        assert not api1.matches(api2)  # same source — no correlation

    def test_buffer_evicts_expired_findings(self):
        # Use a tiny window so findings expire immediately
        from watchers.correlator import _CorrelationBuffer
        buf = _CorrelationBuffer(window_secs=0.01, max_size=100)
        api = self._make_api_finding()
        code = self._make_code_finding()
        buf.add(api)
        buf.add(code)
        time.sleep(0.05)  # let them expire
        matches = buf.find_matches()
        assert matches == []

    def test_buffer_finds_match_within_window(self):
        from watchers.correlator import _CorrelationBuffer
        buf = _CorrelationBuffer(window_secs=300, max_size=100)
        api = self._make_api_finding()
        code = self._make_code_finding()
        buf.add(api)
        buf.add(code)
        matches = buf.find_matches()
        assert len(matches) == 1
        assert matches[0][0].service == "auth"

    def test_known_pair_matches_at_service_scope_without_code_route(self):
        from watchers.correlator import _findings_share_scope

        api = self._make_api_finding()
        code = self._make_code_finding(endpoint=None)
        assert _findings_share_scope(api, code)

    def test_unknown_pair_does_not_match_without_code_route(self):
        from watchers.schema import FindingSource, FindingType, Severity, new_finding
        from watchers.correlator import _findings_share_scope

        api = self._make_api_finding()
        code = new_finding(
            source=FindingSource.CODE.value,
            type=FindingType.FILE_MODIFIED.value,
            severity=Severity.LOW.value,
            service="auth",
            system="banking",
            title="changed",
            description="changed",
        )
        assert not _findings_share_scope(api, code)

    def test_pair_outside_correlation_window_does_not_match(self):
        from watchers.correlator import _findings_share_scope

        api = self._make_api_finding()
        code = self._make_code_finding()
        code.timestamp = api.timestamp - 301
        with patch("watchers.correlator.settings") as mock_settings:
            mock_settings.correlator.correlation_window_secs = 300
            assert not _findings_share_scope(api, code)


# ─── Confidence Scoring Tests ─────────────────────────────────────────────────

class TestConfidenceScoring:

    def test_trace_id_match_boosts_confidence(self):
        from watchers.correlator import _compute_confidence

        trace = "req-abc-123"
        api = new_finding(
            source=FindingSource.API.value, type=FindingType.HTTP_5XX.value,
            severity=Severity.HIGH.value, service="auth", system="banking",
            title="t", description="d", endpoint="/login", trace_id=trace,
        )
        code = new_finding(
            source=FindingSource.CODE.value, type=FindingType.NULL_DEREFERENCE.value,
            severity=Severity.MEDIUM.value, service="auth", system="banking",
            title="t", description="d", endpoint="/login", trace_id=trace,
        )
        no_trace_code = new_finding(
            source=FindingSource.CODE.value, type=FindingType.NULL_DEREFERENCE.value,
            severity=Severity.MEDIUM.value, service="auth", system="banking",
            title="t", description="d", endpoint="/login", trace_id=None,
        )
        score_with_trace = _compute_confidence(api, code)
        score_without_trace = _compute_confidence(api, no_trace_code)
        assert score_with_trace > score_without_trace

    def test_kb_pairing_boosts_confidence(self):
        from watchers.correlator import _compute_confidence

        api = new_finding(
            source=FindingSource.API.value, type=FindingType.HTTP_5XX.value,
            severity=Severity.HIGH.value, service="auth", system="banking",
            title="t", description="d", endpoint="/login",
        )
        code_kb = new_finding(
            source=FindingSource.CODE.value, type=FindingType.NULL_DEREFERENCE.value,
            severity=Severity.MEDIUM.value, service="auth", system="banking",
            title="t", description="d", endpoint="/login",
        )
        code_unknown = new_finding(
            source=FindingSource.CODE.value, type=FindingType.FILE_MODIFIED.value,
            severity=Severity.LOW.value, service="auth", system="banking",
            title="t", description="d", endpoint="/login",
        )
        score_kb = _compute_confidence(api, code_kb)
        score_unknown = _compute_confidence(api, code_unknown)
        assert score_kb > score_unknown


# ─── Security Pattern Scanning Tests ──────────────────────────────────────────

class TestCodeWatcherPatterns:

    def _write_temp(self, tmp_path, content, name="test_file.py"):
        p = tmp_path / name
        p.write_text(content)
        return str(p)

    def test_hardcoded_api_key_detected(self, tmp_path):
        from watchers.code_watcher import scan_file
        path = self._write_temp(tmp_path, 'api_key = "AKIAIOSFODNN7EXAMPLE12345678"\n')
        findings = scan_file(path)
        types = [f.type for f in findings]
        assert "hardcoded_secret" in types

    def test_hardcoded_password_detected(self, tmp_path):
        from watchers.code_watcher import scan_file
        path = self._write_temp(tmp_path, "password = 'super_secret_password_123'\n")
        findings = scan_file(path)
        assert any(f.type == "hardcoded_secret" for f in findings)

    def test_eval_usage_detected(self, tmp_path):
        from watchers.code_watcher import scan_file
        path = self._write_temp(tmp_path, "result = eval(user_input)\n")
        findings = scan_file(path)
        assert any(f.type == "eval_usage" for f in findings)

    def test_weak_crypto_detected(self, tmp_path):
        from watchers.code_watcher import scan_file
        path = self._write_temp(tmp_path, "import hashlib\nhash = hashlib.md5(data).hexdigest()\n")
        findings = scan_file(path)
        assert any(f.type == "weak_crypto" for f in findings)

    def test_clean_file_has_no_findings(self, tmp_path):
        from watchers.code_watcher import scan_file
        path = self._write_temp(tmp_path, "def add(a, b):\n    return a + b\n")
        findings = scan_file(path)
        assert findings == []

    def test_direct_symlink_scan_is_rejected(self, tmp_path):
        from watchers.code_watcher import scan_file

        source = tmp_path / "source.py"
        source.write_text("result = eval(user_input)\n")
        link = tmp_path / "link.py"
        link.symlink_to(source)
        assert scan_file(str(link)) == []

    def test_repository_service_inference_uses_real_path_boundaries(self):
        from watchers.code_watcher import _infer_service_system
        from watchers.config import settings

        service, system = _infer_service_system(
            "/workspace/components/cloud-services/services/repo-authentication/app.py"
        )
        assert service == "repo-authentication"
        assert system == settings.platform


# ─── Notifier Severity Filtering Tests ────────────────────────────────────────

class TestNotifierFiltering:

    def _make_alert(self, severity: str):
        from watchers.schema import CorrelatedAlert
        import time
        return CorrelatedAlert(
            id=str(uuid.uuid4()),
            service="auth-service", system="banking",
            endpoint="/api/login",
            api_finding_id=str(uuid.uuid4()),
            code_finding_id=str(uuid.uuid4()),
            api_error="http_5xx", code_issue="null_dereference",
            file="auth/login.py", line=42,
            severity=severity, confidence=0.85,
            root_cause="Test root cause.",
            recommended_fix="Test fix.",
            timestamp=time.time(),
            fingerprint="a" * 32,
            trace_id=None,
            context={},
        )

    def test_critical_alert_passes_high_threshold(self):
        from watchers.notifier import _should_notify

        alert = self._make_alert("CRITICAL")
        with patch("watchers.notifier.settings") as mock_settings:
            mock_settings.notifier.min_alert_severity = "HIGH"
            assert _should_notify(alert) is True

    def test_medium_alert_blocked_by_high_threshold(self):
        from watchers.notifier import _should_notify

        alert = self._make_alert("MEDIUM")
        with patch("watchers.notifier.settings") as mock_settings:
            mock_settings.notifier.min_alert_severity = "HIGH"
            assert _should_notify(alert) is False

    def test_low_alert_blocked_by_medium_threshold(self):
        from watchers.notifier import _should_notify

        alert = self._make_alert("LOW")
        with patch("watchers.notifier.settings") as mock_settings:
            mock_settings.notifier.min_alert_severity = "MEDIUM"
            assert _should_notify(alert) is False


# ─── Config Safety Tests ───────────────────────────────────────────────────────

class TestConfigSafety:

    def test_non_production_env_raises(self):
        import os
        os.environ["WATCHTOWER_ENV"] = "staging"
        try:
            from watchers.config import Settings
            s = Settings()
            with pytest.raises(RuntimeError, match="production-only"):
                s.validate()
        finally:
            os.environ["WATCHTOWER_ENV"] = "production"

    def test_production_env_passes(self):
        import os
        os.environ["WATCHTOWER_ENV"] = "production"
        os.environ["REDIS_PASSWORD"] = "a-secure-test-password-123456"
        os.environ["API_WATCHER_TARGETS"] = (
            "https://prod.example.test/health"
        )
        try:
            from watchers.config import Settings
            Settings().validate()
        finally:
            os.environ.pop("API_WATCHER_TARGETS", None)


class TestSafeResolver:

    def test_private_resolution_is_rejected(self):
        import asyncio
        from watchers.api_watcher import SafeResolver

        async def resolve():
            resolver = SafeResolver(allow_loopback=False)
            resolver._resolver.resolve = AsyncMock(
                return_value=[{"host": "10.0.0.1"}]
            )
            try:
                return await resolver.resolve("example.test")
            finally:
                await resolver.close()

        with pytest.raises(OSError, match="prohibited address"):
            asyncio.run(resolve())

    def test_explicitly_allowed_loopback_is_accepted(self):
        import asyncio
        from watchers.api_watcher import SafeResolver

        async def resolve():
            expected = [{"host": "127.0.0.1"}]
            resolver = SafeResolver(allow_loopback=True)
            resolver._resolver.resolve = AsyncMock(return_value=expected)
            try:
                return await resolver.resolve("localhost"), expected
            finally:
                await resolver.close()

        actual, expected = asyncio.run(resolve())
        assert actual == expected

    def test_health_target_requires_explicit_path(self):
        import os
        os.environ["WATCHTOWER_ENV"] = "production"
        os.environ["REDIS_PASSWORD"] = "a-secure-test-password-123456"
        os.environ["API_WATCHER_TARGETS"] = "https://prod.example.test"
        try:
            from watchers.config import Settings
            with pytest.raises(ValueError, match="explicit health endpoint"):
                Settings().validate()
        finally:
            os.environ.pop("API_WATCHER_TARGETS", None)

    def test_health_target_rejects_private_ip(self):
        import os
        from watchers.config import Settings

        os.environ["WATCHTOWER_ENV"] = "production"
        os.environ["REDIS_PASSWORD"] = "a-secure-test-password-123456"
        os.environ["API_WATCHER_TARGETS"] = "https://10.0.0.1/health"
        try:
            with pytest.raises(ValueError, match="prohibited address range"):
                Settings().validate()
        finally:
            os.environ.pop("API_WATCHER_TARGETS", None)


class TestNotifierRedaction:

    def test_generic_payload_redacts_dynamic_secret_text(self):
        from watchers.notifier import _build_webhook_payload

        alert = TestNotifierFiltering()._make_alert("HIGH")
        alert.root_cause = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"
        payload = json.dumps(_build_webhook_payload(alert))
        assert "abcdefghijklmnopqrstuvwxyz123456" not in payload
        assert "[REDACTED]" in payload

    def test_webhook_redirects_are_never_followed(self):
        import watchers.notifier as notifier

        response = MagicMock()
        response.ok = True
        response.status_code = 200
        session = MagicMock()
        session.post.return_value = response

        with patch.object(notifier, "_get_session", return_value=session):
            assert notifier._post(
                "https://alerts.example.test/watchtower",
                {"alert_id": "test"},
                "Webhook",
                "a" * 32,
            )

        assert session.post.call_args.kwargs["allow_redirects"] is False
        assert session.post.call_args.kwargs["stream"] is True
        response.close.assert_called_once_with()


class TestRedisAlertClaim:

    def test_claim_returns_unique_ownership_token(self):
        import watchers.redis_client as redis_client

        fake = MagicMock()
        fake.set.return_value = True
        with patch.object(redis_client, "get_client", return_value=fake):
            token = redis_client.claim_alert("a" * 32, 30)
        assert token
        assert fake.set.call_args.kwargs["nx"] is True
        assert fake.set.call_args.kwargs["ex"] == 30
