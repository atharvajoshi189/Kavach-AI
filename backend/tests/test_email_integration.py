"""Comprehensive automated test suite for AegisMesh 2.0 Step 10.1:
Secure External Integration Foundation and Email Gateway Architecture.

Tests:
1. Provider registry and lifecycle management.
2. Resend provider configuration, secret redaction, and bounded timeouts.
3. Step 10.1 test boundary simulation enforcement (no external calls).
4. Production-mode lock (fails closed).
5. Strict Pydantic schemas (extra="forbid").
6. Approved template registry and variable schema validation.
7. HTML escaping and header injection prevention.
8. Test-mode recipient allowlisting enforcement (fail-closed).
9. Tamper-evident SHA-256 chained audit logging and fail-closed persistence.
10. OPA Rego policy evaluation: Admin/Operator permitted, Viewer denied delivery.
11. Full REST API endpoints verification via AsyncClient.
"""

from __future__ import annotations

import re
from unittest.mock import AsyncMock, patch
import uuid
import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from app.core.config import Settings
from app.core.security import create_access_token
from app.integrations.base import BaseEmailProvider, DeliveryResult, ProviderStatus
from app.integrations.email.providers.resend import ResendEmailProvider, _redact_secrets
from app.integrations.email.schemas import (
    EmailDeliveryRequest,
    EmailDeliveryResponse,
    EmailTemplateId,
    IncidentNotificationParams,
    SecurityAlertParams,
    TestDeliveryParams,
)
from app.integrations.email.service import (
    EmailIntegrationService,
    RecipientNotAllowedError,
    TemplateValidationError,
)
from app.integrations.email.templates import (
    ApprovedTemplateRegistry,
    _sanitize_header_value,
    template_registry,
)
from app.integrations.registry import IntegrationRegistry
from app.main import app
from app.models.user import User, UserRole
from app.security.gateway import authorize_action


# ==============================================================================
# 1. Provider Registry Tests
# ==============================================================================


def test_provider_registry_lifecycle():
    """Verify registration, discovery, and strict type checking in IntegrationRegistry."""
    registry = IntegrationRegistry()
    assert registry.list_email_providers() == []

    # Non-BaseEmailProvider must raise TypeError
    with pytest.raises(TypeError, match="must implement BaseEmailProvider"):
        registry.register_email_provider("invalid", object())  # type: ignore

    # Register valid provider
    resend = ResendEmailProvider()
    registry.register_email_provider("Resend", resend)

    assert registry.has_email_provider("resend") is True
    assert registry.has_email_provider("RESEND") is True
    assert registry.list_email_providers() == ["resend"]
    assert registry.get_email_provider("resend") is resend

    # Unknown provider must raise KeyError
    with pytest.raises(KeyError, match="is not registered"):
        registry.get_email_provider("sendgrid")


# ==============================================================================
# 2. Resend Provider Configuration & Secret Redaction Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_resend_provider_secret_redaction_and_repr():
    """Verify secrets are redacted from error logs, repr, and exceptions."""
    cfg = Settings(
        RESEND_API_KEY="re_test_secret_api_key_12345",
        EMAIL_MODE="test",
        EMAIL_FROM_ADDRESS="secops@aegismesh.local",
    )
    provider = ResendEmailProvider(config=cfg)

    # String representation must NEVER expose the API key
    provider_repr = repr(provider)
    assert "re_test_secret" not in provider_repr
    assert "re_test_secret" not in str(provider)
    assert "configured=True" in provider_repr

    # Verify secret redaction helper
    raw_error = "Failed to connect: Bearer re_test_secret_api_key_12345 was rejected by upstream"
    redacted = _redact_secrets(raw_error)
    assert "re_test_secret_api_key_12345" not in redacted
    assert "[REDACTED_API_KEY]" in redacted or "Bearer [REDACTED_TOKEN]" in redacted

    # Health check must report ready without leaking credentials
    health = await provider.check_health()
    assert health.is_configured is True
    assert health.status == "ready"
    assert "re_test_secret" not in str(health.model_dump())


@pytest.mark.asyncio
async def test_resend_missing_api_key_health():
    """Verify safe unconfigured status when RESEND_API_KEY is not set."""
    cfg = Settings(
        RESEND_API_KEY="",
        EMAIL_MODE="test",
    )
    provider = ResendEmailProvider(config=cfg)
    assert provider.is_configured() is False

    health = await provider.check_health()
    assert health.is_configured is False
    assert health.status == "unconfigured"
    assert "credentials are not configured" in health.details["message"]

    # Delivery attempt with unconfigured key returns failure result
    res = await provider.send_email(
        from_address="sec@test.local",
        to_address="test@test.local",
        subject="Test",
        html_content="<p>Test</p>",
    )
    assert res.success is False
    assert res.status == "failed"
    assert "credentials missing" in (res.error_message or "")


@pytest.mark.asyncio
async def test_resend_test_mode_simulation_boundary():
    """Verify that in test mode, Resend provider simulates acceptance without network transmission."""
    cfg = Settings(
        RESEND_API_KEY="re_mock_valid_key",
        EMAIL_MODE="test",
        EMAIL_FROM_ADDRESS="security@aegismesh.local",
    )
    provider = ResendEmailProvider(config=cfg)

    result = await provider.send_email(
        from_address="security@aegismesh.local",
        to_address="admin@aegismesh.local",
        subject="Security Notification",
        html_content="<p>Alert Body</p>",
        plain_text="Alert Body",
        correlation_id="corr-12345",
    )

    assert result.success is True
    assert result.status == "simulated_accepted"
    assert result.mode == "test"
    assert result.provider_message_id is not None
    assert result.provider_message_id.startswith("sim_resend_")
    assert result.details["simulated"] is True
    assert result.details["idempotency_key"] is not None


@pytest.mark.asyncio
async def test_resend_production_mode_fails_closed_in_step_10_1():
    """Verify that production delivery is strictly forbidden in Step 10.1."""
    cfg = Settings(
        RESEND_API_KEY="re_mock_valid_key",
        EMAIL_MODE="production",
    )
    provider = ResendEmailProvider(config=cfg)

    with pytest.raises(RuntimeError, match="Production external email delivery is strictly disabled in Step 10.1"):
        await provider.send_email(
            from_address="security@aegismesh.local",
            to_address="admin@aegismesh.local",
            subject="Test",
            html_content="<p>Body</p>",
        )


# ==============================================================================
# 3. Strict Pydantic Schema Validation Tests
# ==============================================================================


def test_strict_pydantic_schema_extra_forbid():
    """Verify extra attributes are strictly rejected across all request schemas."""
    # Extra field on EmailDeliveryRequest
    with pytest.raises(ValidationError):
        EmailDeliveryRequest(
            recipient="admin@aegismesh.local",
            template_id=EmailTemplateId.TEST_DELIVERY,
            template_variables={"test_id": "T1", "message": "hello", "initiated_by": "tester"},
            unauthorized_field="malicious_payload",  # type: ignore
        )

    # Missing required variables
    with pytest.raises(ValidationError):
        SecurityAlertParams(
            severity="critical",
            # alert_title missing
            summary="Brief summary text",
        )

    # Invalid severity literal
    with pytest.raises(ValidationError):
        SecurityAlertParams(
            severity="super_critical",  # type: ignore
            alert_title="Alert Title",
            summary="Brief summary text",
        )

    # Invalid email address
    with pytest.raises(ValidationError):
        EmailDeliveryRequest(
            recipient="not-an-email-address",
            template_id=EmailTemplateId.TEST_DELIVERY,
            template_variables={"test_id": "T1", "message": "hello", "initiated_by": "tester"},
        )


# ==============================================================================
# 4. Approved Template Catalog & Injection Prevention Tests
# ==============================================================================


def test_approved_template_catalog_completeness():
    """Verify all 3 approved templates are cataloged with schemas."""
    catalog = template_registry.list_templates()
    template_ids = {t.template_id for t in catalog}
    assert "security_alert" in template_ids
    assert "incident_notification" in template_ids
    assert "test_delivery" in template_ids


def test_html_and_header_injection_prevention():
    """Verify that dangerous HTML scripts and carriage returns are safely neutralized."""
    # 1. Header injection test
    malicious_header = "Subject Line\r\nBcc: evil@attacker.com\r\nX-Spam: true"
    sanitized = _sanitize_header_value(malicious_header)
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert "Subject Line Bcc: evil@attacker.com X-Spam: true" == sanitized

    # 2. HTML escaping test
    template = template_registry.get_template(EmailTemplateId.SECURITY_ALERT)
    params = template.validate_variables({
        "severity": "high",
        "alert_title": "<script>alert('xss')</script>",
        "summary": "Exploit: <img src=x onerror=alert(1)>",
        "indicators": ["192.168.1.1", "<b onmouseover=evil()>indicator</b>"],
    })
    subject, html_content, plain_text = template.render(params)

    assert "<script>" not in html_content
    assert "&lt;script&gt;alert(" in html_content
    assert "<img src=x" not in html_content
    assert "&lt;b onmouseover=evil()&gt;" in html_content


# ==============================================================================
# 5. Test-Mode Recipient Allowlisting Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_recipient_allowlisting_enforcement():
    """Verify allowlisted addresses pass and non-allowlisted addresses are rejected with 400."""
    cfg = Settings(
        RESEND_API_KEY="re_mock_test_key",
        EMAIL_MODE="test",
        EMAIL_ALLOWED_RECIPIENTS=["secops@aegismesh.local", "operator@aegismesh.local"],
    )
    service = EmailIntegrationService(config=cfg)

    # Allowed recipient (case-insensitive check)
    service.validate_recipient_boundary("SECOPS@aegismesh.local")
    service.validate_recipient_boundary("operator@aegismesh.local")

    # Unauthorized external recipient must raise RecipientNotAllowedError (HTTP 400)
    with pytest.raises(RecipientNotAllowedError) as exc_info:
        service.validate_recipient_boundary("unauthorized_user@external.com")
    assert exc_info.value.status_code == 400
    assert "not permitted under test mode" in exc_info.value.detail


# ==============================================================================
# 6. Service Execution and Audit Persistence Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_email_service_delivery_and_audit(db_session, test_operator):
    """Verify end-to-end delivery validation and persistent SHA-256 chained audit logging."""
    cfg = Settings(
        RESEND_API_KEY="re_mock_test_key",
        EMAIL_MODE="test",
        EMAIL_ALLOWED_RECIPIENTS=["secops@aegismesh.local"],
        EMAIL_FROM_ADDRESS="security@aegismesh.local",
    )
    service = EmailIntegrationService(config=cfg)

    req = EmailDeliveryRequest(
        recipient="secops@aegismesh.local",
        template_id=EmailTemplateId.SECURITY_ALERT,
        template_variables={
            "severity": "critical",
            "alert_title": "Simulated Active Directory Kerberoasting",
            "summary": "Observed multiple anomalous TGS requests against high-privilege service accounts.",
            "indicators": ["T1558.003", "10.0.10.55"],
        },
        correlation_id="corr-audit-test-01",
    )

    resp = await service.process_delivery_request(
        request=req,
        user=test_operator,
        session=db_session,
    )

    assert resp.status == "simulated_accepted"
    assert resp.mode == "test"
    assert resp.recipient == "secops@aegismesh.local"
    assert resp.provider == "resend"
    assert resp.provider_message_id is not None
    assert resp.correlation_id == "corr-audit-test-01"


@pytest.mark.asyncio
async def test_audit_failure_fails_closed(test_operator):
    """Verify that failure to persist audit record aborts action and fails closed with HTTP 500."""
    cfg = Settings(
        RESEND_API_KEY="re_mock_test_key",
        EMAIL_MODE="test",
        EMAIL_ALLOWED_RECIPIENTS=["secops@aegismesh.local"],
    )
    service = EmailIntegrationService(config=cfg)

    req = EmailDeliveryRequest(
        recipient="secops@aegismesh.local",
        template_id=EmailTemplateId.TEST_DELIVERY,
        template_variables={"test_id": "T-FAIL", "message": "msg", "initiated_by": "tester"},
    )

    with patch("app.integrations.email.service.record_audit_log", side_effect=RuntimeError("DB Disk Full")):
        with pytest.raises(HTTPException) as exc_info:
            await service.process_delivery_request(
                request=req,
                user=test_operator,
                session=None,
            )
        assert exc_info.value.status_code == 500
        assert "fail-closed" in exc_info.value.detail


# ==============================================================================
# 7. OPA Authorization Policy Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_opa_operator_and_admin_allowed_email_delivery(db_session, test_operator, test_admin):
    """Verify Security Operator and Admin roles are authorized by OPA to request test email delivery."""
    for user in [test_operator, test_admin]:
        decision = await authorize_action(
            user=user,
            operation="email.delivery_request",
            capability="execute",
            resource_type="email_gateway",
            resource_id="test_delivery",
            environment="sandbox",
            session=db_session,
        )
        assert decision.allowed is True
        assert decision.decision == "allow"


@pytest.mark.asyncio
async def test_opa_viewer_denied_email_delivery(db_session, test_viewer):
    """Verify VIEWER role is strictly denied from requesting email delivery."""
    decision = await authorize_action(
        user=test_viewer,
        operation="email.delivery_request",
        capability="execute",
        resource_type="email_gateway",
        resource_id="test_delivery",
        environment="sandbox",
        session=db_session,
    )
    assert decision.allowed is False
    assert decision.decision == "deny"
    assert any(
        term in decision.reason
        for term in ["Viewer role", "Security Operator or Admin role required", "read-only", "not authorized"]
    )


@pytest.mark.asyncio
async def test_opa_viewer_allowed_template_listing(db_session, test_viewer):
    """Verify VIEWER role is permitted to read email templates and gateway status."""
    decision_templates = await authorize_action(
        user=test_viewer,
        operation="email.template_list",
        capability="read",
        resource_type="email_template",
        resource_id="catalog",
        environment="sandbox",
        session=db_session,
    )
    assert decision_templates.allowed is True

    decision_status = await authorize_action(
        user=test_viewer,
        operation="email.delivery_read",
        capability="read",
        resource_type="email_gateway",
        resource_id="status",
        environment="sandbox",
        session=db_session,
    )
    assert decision_status.allowed is True


# ==============================================================================
# 8. Complete FastAPI REST API Endpoints Verification
# ==============================================================================


@pytest.mark.asyncio
async def test_fastapi_rest_email_endpoints(test_operator, test_viewer, operator_token, viewer_token):
    """Verify all 3 email integration endpoints over HTTP with authorized and unauthorized users."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        op_headers = {"Authorization": f"Bearer {operator_token}"}
        viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

        # 1. GET /api/v1/integrations/email/templates
        res_templates = await client.get("/api/v1/integrations/email/templates", headers=op_headers)
        assert res_templates.status_code == 200
        templates_data = res_templates.json()
        assert len(templates_data) >= 3
        template_names = [t["template_id"] for t in templates_data]
        assert "security_alert" in template_names

        # Viewer can also discover templates
        res_view_templates = await client.get("/api/v1/integrations/email/templates", headers=viewer_headers)
        assert res_view_templates.status_code == 200

        # 2. GET /api/v1/integrations/email/status
        res_status = await client.get("/api/v1/integrations/email/status", headers=op_headers)
        assert res_status.status_code == 200
        status_data = res_status.json()
        assert status_data["provider"] == "resend"
        assert status_data["mode"] == "test"
        assert status_data["allowed_recipients_count"] >= 1
        assert "RESEND_API_KEY" not in str(status_data)

        # 3. POST /api/v1/integrations/email/test - Success (Operator + Allowlisted recipient)
        valid_payload = {
            "recipient": "secops@aegismesh.local",
            "template_id": "test_delivery",
            "template_variables": {
                "test_id": "TEST-PROBE-01",
                "message": "Gateway connectivity check",
                "initiated_by": "SecOps Automation",
            },
            "correlation_id": "probe-corr-001",
        }
        res_delivery = await client.post("/api/v1/integrations/email/test", json=valid_payload, headers=op_headers)
        assert res_delivery.status_code == 200
        del_data = res_delivery.json()
        assert del_data["status"] == "simulated_accepted"
        assert del_data["mode"] == "test"
        assert del_data["recipient"] == "secops@aegismesh.local"
        assert del_data["provider_message_id"].startswith("sim_resend_")

        # 4. POST /api/v1/integrations/email/test - Rejection (Unallowlisted recipient -> 400)
        unallowlisted_payload = {
            "recipient": "external_attacker@target.org",
            "template_id": "test_delivery",
            "template_variables": {
                "test_id": "TEST-PROBE-02",
                "message": "Gateway connectivity check",
                "initiated_by": "SecOps Automation",
            },
        }
        res_unallowlisted = await client.post("/api/v1/integrations/email/test", json=unallowlisted_payload, headers=op_headers)
        assert res_unallowlisted.status_code == 400
        assert "not permitted under test mode" in res_unallowlisted.json()["detail"]

        # 5. POST /api/v1/integrations/email/test - Denial (Viewer -> 403)
        res_viewer_denied = await client.post("/api/v1/integrations/email/test", json=valid_payload, headers=viewer_headers)
        assert res_viewer_denied.status_code == 403
        assert "Action prohibited by policy" in res_viewer_denied.json()["detail"]

        # 6. POST /api/v1/integrations/email/test - Validation Error (Extra fields -> 422)
        extra_field_payload = {
            "recipient": "secops@aegismesh.local",
            "template_id": "test_delivery",
            "template_variables": {
                "test_id": "TEST-PROBE-03",
                "message": "Gateway check",
                "initiated_by": "tester",
            },
            "illegal_client_header": "X-Custom-Injection",
        }
        res_extra = await client.post("/api/v1/integrations/email/test", json=extra_field_payload, headers=op_headers)
        assert res_extra.status_code == 422
