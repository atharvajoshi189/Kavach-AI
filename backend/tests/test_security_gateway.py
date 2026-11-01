"""Comprehensive automated tests for OPA policy evaluation, Security Gateway, and fail-closed enforcement."""

from unittest.mock import patch
import httpx
import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app
from app.security.context import build_policy_input
from app.security.gateway import authorize_action
from app.security.opa_client import check_opa_health, evaluate_policy


# --- 1. OPA Connectivity and Health Tests ---

@pytest.mark.asyncio
async def test_opa_connection_health():
    """Verify OPA daemon is reachable and healthy at configured endpoint."""
    is_healthy = await check_opa_health()
    assert is_healthy is True


@pytest.mark.asyncio
async def test_opa_unavailable_fail_closed(test_operator):
    """Verify that if OPA connection fails or times out, the gateway fails closed (DENY)."""
    with patch("app.security.opa_client.get_opa_client") as mock_client_factory:
        mock_client = mock_client_factory.return_value
        mock_client.post.side_effect = httpx.ConnectError("Connection refused to OPA")

        decision = await authorize_action(
            user=test_operator,
            operation="scan.execute",
            capability="scan",
            resource_type="target",
            resource_id="target-100",
            environment="sandbox",
        )

        assert decision.allowed is False
        assert decision.decision == "deny"
        assert "fail-closed" in decision.reason


# --- 2. Live OPA Policy Evaluation Tests ---

@pytest.mark.asyncio
async def test_default_deny(test_operator):
    """Verify unmapped or unknown actions trigger default deny."""
    decision = await authorize_action(
        user=test_operator,
        operation="unknown.arbitrary.action",
        capability="unknown",
        resource_type="system",
        resource_id="sys-1",
    )
    assert decision.allowed is False
    assert decision.decision == "deny"


@pytest.mark.asyncio
async def test_unauthenticated_request_denied(test_operator):
    """Verify that unauthenticated inputs are rejected by policy."""
    policy_input = build_policy_input(
        user=test_operator,
        operation="investigation.read",
        capability="read",
        resource_type="report",
        resource_id="rep-1",
    )
    # Tamper with authentication status
    policy_input.subject.is_authenticated = False

    decision = await evaluate_policy(policy_input)
    assert decision.allowed is False
    assert decision.decision == "deny"
    assert "Authentication required" in decision.reason


@pytest.mark.asyncio
async def test_viewer_denied_scan_execution(test_viewer):
    """Verify that a viewer is denied scan and task execution."""
    decision = await authorize_action(
        user=test_viewer,
        operation="scan.execute",
        capability="scan",
        resource_type="target",
        resource_id="target-1",
        environment="sandbox",
    )
    assert decision.allowed is False
    assert decision.decision == "deny"
    assert "Security Operator or Admin" in decision.reason or "restricted" in decision.reason


@pytest.mark.asyncio
async def test_operator_allowed_sandbox_scan(test_operator):
    """Verify security operator is permitted to execute scans in sandbox."""
    decision = await authorize_action(
        user=test_operator,
        operation="scan.execute",
        capability="scan",
        resource_type="target",
        resource_id="target-1",
        environment="sandbox",
    )
    assert decision.allowed is True
    assert decision.decision == "allow"
    assert decision.reason == "Authorized by policy."


@pytest.mark.asyncio
async def test_analyst_allowed_investigation_read(db_session, test_viewer):
    """Verify security analyst is permitted to execute read and investigation actions."""
    # Temporarily set role to SECURITY_ANALYST
    from app.models.user import UserRole
    test_viewer.role = UserRole.SECURITY_ANALYST

    decision = await authorize_action(
        user=test_viewer,
        operation="investigation.read",
        capability="read",
        resource_type="incident_report",
        resource_id="inc-42",
    )
    assert decision.allowed is True
    assert decision.decision == "allow"


@pytest.mark.asyncio
async def test_admin_only_operations(test_admin, test_operator):
    """Verify administrative capabilities are strictly restricted to admin role."""
    # Operator denied
    op_decision = await authorize_action(
        user=test_operator,
        operation="admin.manage",
        capability="admin",
        resource_type="system",
        resource_id="sys-core",
    )
    assert op_decision.allowed is False
    assert op_decision.decision == "deny"
    assert "Admin role required" in op_decision.reason

    # Admin allowed
    admin_decision = await authorize_action(
        user=test_admin,
        operation="admin.manage",
        capability="admin",
        resource_type="system",
        resource_id="sys-core",
    )
    assert admin_decision.allowed is True
    assert admin_decision.decision == "allow"


@pytest.mark.asyncio
async def test_unapproved_remediation_denied(test_operator):
    """Verify remediation operations require human approval before execution."""
    # Without approval
    unapproved = await authorize_action(
        user=test_operator,
        operation="remediation.execute",
        capability="remediate",
        resource_type="firewall_rule",
        resource_id="fw-99",
        approval_status="none",
    )
    assert unapproved.allowed is False
    assert "Human approval required" in unapproved.reason

    # With approval
    approved = await authorize_action(
        user=test_operator,
        operation="remediation.execute",
        capability="remediate",
        resource_type="firewall_rule",
        resource_id="fw-99",
        approval_status="approved",
    )
    assert approved.allowed is True
    assert approved.decision == "allow"


@pytest.mark.asyncio
async def test_non_sandbox_attack_denied(test_admin):
    """Verify attack execution is prohibited outside sandbox environments even for admin."""
    prod_attack = await authorize_action(
        user=test_admin,
        operation="attack.execute",
        capability="attack",
        resource_type="production_server",
        resource_id="srv-prod-1",
        environment="production",
        approval_status="approved",
    )
    assert prod_attack.allowed is False
    assert "prohibited outside sandbox" in prod_attack.reason


@pytest.mark.asyncio
async def test_external_target_access_denied(test_operator):
    """Verify access to unapproved external targets is denied."""
    ext_decision = await authorize_action(
        user=test_operator,
        operation="scan.execute",
        capability="scan",
        resource_type="external_target",
        resource_id="https://unauthorized-external.com",
        environment="production",
        approval_status="none",
    )
    assert ext_decision.allowed is False
    assert "Unauthorized external target" in ext_decision.reason


# --- 3. Job Submission Enforcement Integration Tests ---

@pytest.mark.asyncio
async def test_job_submission_gateway_enforced(operator_token):
    """Verify background job dispatch evaluates through Security Gateway and succeeds when allowed."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/jobs/health-check",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert response.status_code == 202
        assert response.json()["status"] == "queued"


@pytest.mark.asyncio
async def test_job_submission_gateway_denied_when_opa_fails(operator_token):
    """Verify background job dispatch is rejected (fail-closed) if OPA is down."""
    with patch("app.security.opa_client.get_opa_client") as mock_client_factory:
        mock_client = mock_client_factory.return_value
        mock_client.post.side_effect = httpx.ConnectError("OPA unavailable")

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/jobs/health-check",
                headers={"Authorization": f"Bearer {operator_token}"},
            )
            assert response.status_code == 403
            assert "Action prohibited by policy" in response.json()["detail"]
            assert "fail-closed" in response.json()["detail"]


# --- 4. Public Security Check API Tests ---

@pytest.mark.asyncio
async def test_security_check_api_unauthenticated():
    """Verify POST /api/v1/security/check rejects unauthenticated callers."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/security/check",
            json={
                "operation": "scan.execute",
                "capability": "scan",
                "resource_type": "target",
                "resource_id": "tgt-1",
            },
        )
        assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_security_check_api_authenticated(operator_token, viewer_token):
    """Verify POST /api/v1/security/check returns structured decisions for different roles."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Operator checks sandbox scan -> ALLOW
        op_res = await client.post(
            "/api/v1/security/check",
            headers={"Authorization": f"Bearer {operator_token}"},
            json={
                "operation": "scan.execute",
                "capability": "scan",
                "resource_type": "target",
                "resource_id": "tgt-1",
                "environment": "sandbox",
            },
        )
        assert op_res.status_code == 200
        op_data = op_res.json()
        assert op_data["allowed"] is True
        assert op_data["decision"] == "allow"

        # Viewer checks scan -> DENY
        vw_res = await client.post(
            "/api/v1/security/check",
            headers={"Authorization": f"Bearer {viewer_token}"},
            json={
                "operation": "scan.execute",
                "capability": "scan",
                "resource_type": "target",
                "resource_id": "tgt-1",
                "environment": "sandbox",
            },
        )
        assert vw_res.status_code == 200
        vw_data = vw_res.json()
        assert vw_data["allowed"] is False
        assert vw_data["decision"] == "deny"

