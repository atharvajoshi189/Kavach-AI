"""Comprehensive test suite for AegisMesh Model Context Protocol (MCP) server.

Tests:
1. MCP initialize and tool discovery without credentials over Streamable HTTP transport
2. Tool discovery with valid authentication
3. Tool execution with valid HTTP Authorization header
4. Missing Authorization header rejection
5. Malformed Bearer token and non-Bearer header format rejection
6. Expired JWT rejection
7. Revoked JWT rejection via Redis blacklist
8. Inactive database user rejection
9. OPA authorization denial (fail-closed)
10. Audit persistence failure (fail-closed)
11. Proof that no tool schema or description contains auth_token
12. Proof that credentials and Authorization headers are absent from audit logs and application traces
13. Strict input schema enforcement (extra='forbid')
14. Database-backed domain tools: system_health, agent tools, campaign tools, incident tools
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import json
import logging
from typing import Optional
from unittest.mock import patch
import uuid

import httpx
import jwt
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
import pytest
import pytest_asyncio
from sqlalchemy import select

from app.core.config import settings
from app.core.security import create_access_token, hash_password, revoke_token
from app.database.session import AsyncSessionLocal
from app.mcp.server import get_mcp_asgi_app
from app.models.agent import Agent
from app.models.audit_log import AuditLog
from app.models.campaign import Campaign
from app.models.incident import Incident
from app.models.user import User, UserRole
from app.security.schemas import AuthorizationDecision
from app.services.audit_service import verify_event_hash


@asynccontextmanager
async def mcp_test_client(
    auth_token: Optional[str] = None,
    custom_headers: Optional[dict[str, str]] = None,
) -> AsyncGenerator[ClientSession, None]:
    """Helper context manager establishing a Streamable HTTP client session to the MCP server.

    Injects credentials strictly at the HTTP transport layer via Authorization headers.
    """
    test_app = get_mcp_asgi_app()
    client_headers: dict[str, str] = {}
    if auth_token is not None:
        client_headers["Authorization"] = f"Bearer {auth_token}"
    if custom_headers:
        client_headers.update(custom_headers)

    async with test_app.router.lifespan_context(test_app):
        transport = httpx.ASGITransport(app=test_app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url=f"http://{settings.MCP_SERVER_HOST}:{settings.MCP_SERVER_PORT}",
            headers=client_headers,
        ) as hc:
            async with streamable_http_client(
                f"http://{settings.MCP_SERVER_HOST}:{settings.MCP_SERVER_PORT}{settings.MCP_SERVER_PATH}",
                http_client=hc,
            ) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    yield session


# =====================================================================
# 1. MCP Initialization & Discovery Without Credentials
# =====================================================================

@pytest.mark.asyncio
async def test_mcp_initialize_and_discovery_without_credentials():
    """Verify MCP server initializes and advertises tools without requiring transport credentials."""
    async with mcp_test_client() as session:
        tools_result = await session.list_tools()
        assert tools_result is not None
        assert len(tools_result.tools) >= 7

        tool_names = {t.name for t in tools_result.tools}
        expected_tools = {
            "system_health",
            "list_agents",
            "get_agent",
            "list_campaigns",
            "get_campaign",
            "list_incidents",
            "get_incident",
        }
        assert expected_tools.issubset(tool_names)


# =====================================================================
# 2. Tool Discovery With Valid Authentication
# =====================================================================

@pytest.mark.asyncio
async def test_mcp_discovery_with_valid_authentication(operator_token):
    """Verify authenticated client discovers all tools over Streamable HTTP transport."""
    async with mcp_test_client(auth_token=operator_token) as session:
        tools_result = await session.list_tools()
        assert tools_result is not None
        assert len(tools_result.tools) >= 7


# =====================================================================
# 3. Tool Execution With Valid Authorization Header
# =====================================================================

@pytest.mark.asyncio
async def test_mcp_tool_execution_with_valid_authorization_header(operator_token):
    """Verify tool executes successfully when valid Bearer token is transmitted in HTTP header."""
    async with mcp_test_client(auth_token=operator_token) as session:
        result = await session.call_tool("system_health", arguments={})
        assert result.is_error is False
        data = json.loads(result.content[0].text)
        assert data["status"] in ["healthy", "degraded"]
        assert "services" in data


# =====================================================================
# 4. Missing Authorization Header Rejection
# =====================================================================

@pytest.mark.asyncio
async def test_mcp_missing_authorization_header_rejected():
    """Verify tool execution fails closed when no Authorization header is provided."""
    async with mcp_test_client() as session:
        result = await session.call_tool("system_health", arguments={})
        assert result.is_error is True
        error_msg = result.content[0].text.lower()
        assert "authentication required" in error_msg or "error executing tool" in error_msg


# =====================================================================
# 5. Malformed Bearer Token & Header Format Rejection
# =====================================================================

@pytest.mark.asyncio
async def test_mcp_malformed_bearer_token_rejected():
    """Verify malformed bearer token is rejected."""
    async with mcp_test_client(custom_headers={"Authorization": "Bearer not.a.valid.jwt"}) as session:
        result = await session.call_tool("system_health", arguments={})
        assert result.is_error is True


@pytest.mark.asyncio
async def test_mcp_invalid_authorization_header_format_rejected():
    """Verify non-Bearer authorization scheme is rejected."""
    async with mcp_test_client(custom_headers={"Authorization": "Basic dXNlcjpwYXNz"}) as session:
        result = await session.call_tool("system_health", arguments={})
        assert result.is_error is True


# =====================================================================
# 6. Expired JWT Rejection
# =====================================================================

@pytest.mark.asyncio
async def test_mcp_expired_jwt_rejected(test_operator):
    """Verify expired JWT passed in Authorization header is rejected."""
    expired_token = create_access_token(
        subject=test_operator.id,
        role=test_operator.role.value,
        extra_claims={"exp": int((datetime.now(timezone.utc) - timedelta(seconds=60)).timestamp())},
    )
    async with mcp_test_client(auth_token=expired_token) as session:
        result = await session.call_tool("system_health", arguments={})
        assert result.is_error is True


# =====================================================================
# 7. Revoked JWT Rejection
# =====================================================================

@pytest.mark.asyncio
async def test_mcp_revoked_jwt_rejected(test_operator):
    """Verify JWT revoked in Redis blacklist is rejected."""
    token = create_access_token(subject=test_operator.id, role=test_operator.role.value)
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    await revoke_token(payload["jti"], expires_in_seconds=3600)

    async with mcp_test_client(auth_token=token) as session:
        result = await session.call_tool("system_health", arguments={})
        assert result.is_error is True


# =====================================================================
# 8. Inactive Database User Rejection
# =====================================================================

@pytest.mark.asyncio
async def test_mcp_inactive_user_rejected(db_session):
    """Verify deactivated user account is rejected even with a signed token."""
    user = User(
        email=f"inactive_{uuid.uuid4().hex[:6]}@example.com",
        username=f"inactive_{uuid.uuid4().hex[:6]}",
        hashed_password=hash_password("InactivePass123!"),
        role=UserRole.VIEWER,
        is_active=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token = create_access_token(subject=user.id, role=user.role.value)
    async with mcp_test_client(auth_token=token) as session:
        result = await session.call_tool("system_health", arguments={})
        assert result.is_error is True


# =====================================================================
# 9. OPA Authorization Denial (Fail-Closed)
# =====================================================================

@pytest.mark.asyncio
async def test_mcp_opa_authorization_denial_fail_closed(operator_token):
    """Verify tool execution fails closed when OPA Security Gateway denies access."""
    with patch("app.mcp.security.authorization.authorize_action") as mock_auth:
        mock_auth.return_value = AuthorizationDecision(
            allowed=False,
            decision="deny",
            reason="Explicit policy test denial.",
            policy_version="1.0.0",
        )
        async with mcp_test_client(auth_token=operator_token) as session:
            res = await session.call_tool("system_health", arguments={})
            assert res.is_error is True


# =====================================================================
# 10. Audit Persistence Failure (Fail-Closed)
# =====================================================================

@pytest.mark.asyncio
async def test_mcp_audit_persistence_failure_fail_closed(operator_token):
    """Verify tool execution fails closed if persistent database audit logging fails."""
    with patch("app.mcp.context.record_audit_log", side_effect=RuntimeError("Database audit failure")):
        async with mcp_test_client(auth_token=operator_token) as session:
            res = await session.call_tool("system_health", arguments={})
            assert res.is_error is True


# =====================================================================
# 11. Verify No Tool Schema Contains auth_token
# =====================================================================

@pytest.mark.asyncio
async def test_no_tool_schema_contains_auth_token():
    """Verify that auth_token is completely absent from all tool schemas, parameters, and descriptions."""
    async with mcp_test_client() as session:
        tools_result = await session.list_tools()
        assert len(tools_result.tools) >= 7

        for tool in tools_result.tools:
            properties = tool.input_schema.get("properties", {})
            required = tool.input_schema.get("required", [])

            # Check properties
            assert "auth_token" not in properties, f"auth_token found in {tool.name} properties"
            assert "token" not in properties, f"token found in {tool.name} properties"
            assert "authorization" not in properties, f"authorization found in {tool.name} properties"

            # Check required list
            assert "auth_token" not in required, f"auth_token in {tool.name} required fields"

            # Check description
            assert "auth_token" not in tool.description.lower(), f"auth_token found in {tool.name} description"


# =====================================================================
# 12. Credential Sanitization in Audit & Traces
# =====================================================================

@pytest.mark.asyncio
async def test_credentials_and_headers_never_reach_audit_logs(operator_token, test_operator, db_session, caplog):
    """Verify Authorization header and JWT are never stored in AuditLog.event_data or logged."""
    with caplog.at_level(logging.DEBUG):
        async with mcp_test_client(auth_token=operator_token) as session:
            res = await session.call_tool("system_health", arguments={})
            assert res.is_error is False

    # Check database audit record
    stmt = (
        select(AuditLog)
        .where(AuditLog.actor_id == test_operator.id)
        .where(AuditLog.action == "mcp.system_health")
        .order_by(AuditLog.created_at.desc())
    )
    result = await db_session.execute(stmt)
    audit_entry = result.scalars().first()

    assert audit_entry is not None
    assert audit_entry.actor_id == test_operator.id
    assert audit_entry.event_hash is not None
    assert verify_event_hash(audit_entry) is True

    # Check event_data contains no credentials
    event_data_str = json.dumps(audit_entry.event_data)
    assert operator_token not in event_data_str
    assert "authorization" not in audit_entry.event_data
    assert "auth_token" not in audit_entry.event_data

    # Check application logs contain no plaintext token
    assert operator_token not in caplog.text


# =====================================================================
# 13. Strict Input Schema Enforcement (extra='forbid')
# =====================================================================

@pytest.mark.asyncio
async def test_strict_input_validation_extra_fields_rejected(operator_token):
    """Verify that passing unexpected extra arguments is rejected by strict schema validation."""
    async with mcp_test_client(auth_token=operator_token) as session:
        result = await session.call_tool(
            "system_health",
            arguments={"unexpected_param": "malicious_injection"},
        )
        assert result.is_error is True
        assert "Extra inputs are not permitted" in result.content[0].text


# =====================================================================
# 14. Database-Backed Domain Tools
# =====================================================================

@pytest.mark.asyncio
async def test_tool_system_health_sanitized(operator_token):
    """Verify system_health tool executes cleanly without leaking sensitive infrastructure details."""
    async with mcp_test_client(auth_token=operator_token) as session:
        res = await session.call_tool("system_health", arguments={})
        assert res.is_error is False
        data = json.loads(res.content[0].text)
        assert "status" in data
        assert "services" in data
        assert "database" in data["services"]
        assert "redis" in data["services"]
        assert "policy_engine" in data["services"]

        # Ensure database password and connection strings are never leaked
        payload_str = res.content[0].text
        assert settings.POSTGRES_PASSWORD not in payload_str
        assert "postgres://" not in payload_str
        assert "redis://" not in payload_str


@pytest.mark.asyncio
async def test_tool_agent_lifecycle_read(operator_token, db_session):
    """Verify list_agents and get_agent tools return database records without auth_token parameters."""
    agent = Agent(
        name=f"ReconAgent-{uuid.uuid4().hex[:6]}",
        agent_type="recon",
        description="Reconnaissance agent for testing",
        status="idle",
        environment="sandbox",
        capabilities={"scans": ["port_scan", "service_detect"]},
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)

    async with mcp_test_client(auth_token=operator_token) as session:
        # 1. list_agents
        list_res = await session.call_tool("list_agents", arguments={"page": 1, "page_size": 10})
        assert list_res.is_error is False
        agents_data = json.loads(list_res.content[0].text)
        assert agents_data["count"] >= 1
        found_ids = [a["id"] for a in agents_data["agents"]]
        assert str(agent.id) in found_ids

        # 2. get_agent (existing)
        get_res = await session.call_tool(
            "get_agent",
            arguments={"agent_id": str(agent.id)},
        )
        assert get_res.is_error is False
        agent_data = json.loads(get_res.content[0].text)
        assert agent_data["found"] is True
        assert agent_data["agent"]["name"] == agent.name

        # 3. get_agent (non-existent UUID)
        missing_res = await session.call_tool(
            "get_agent",
            arguments={"agent_id": str(uuid.uuid4())},
        )
        assert missing_res.is_error is False
        missing_data = json.loads(missing_res.content[0].text)
        assert missing_data["found"] is False


@pytest.mark.asyncio
async def test_tool_campaign_lifecycle_read(operator_token, db_session):
    """Verify list_campaigns and get_campaign tools return database records without auth_token parameters."""
    campaign = Campaign(
        name=f"Campaign-{uuid.uuid4().hex[:6]}",
        trigger_type="manual",
        status="pending",
        environment="sandbox",
        configuration={"target": "192.168.1.0/24"},
    )
    db_session.add(campaign)
    await db_session.commit()
    await db_session.refresh(campaign)

    async with mcp_test_client(auth_token=operator_token) as session:
        # 1. list_campaigns
        list_res = await session.call_tool("list_campaigns", arguments={"page": 1, "page_size": 10})
        assert list_res.is_error is False
        campaigns_data = json.loads(list_res.content[0].text)
        assert campaigns_data["count"] >= 1
        found_ids = [c["id"] for c in campaigns_data["campaigns"]]
        assert str(campaign.id) in found_ids

        # 2. get_campaign (existing)
        get_res = await session.call_tool(
            "get_campaign",
            arguments={"campaign_id": str(campaign.id)},
        )
        assert get_res.is_error is False
        camp_data = json.loads(get_res.content[0].text)
        assert camp_data["found"] is True
        assert camp_data["campaign"]["name"] == campaign.name

        # 3. get_campaign (non-existent UUID)
        missing_res = await session.call_tool(
            "get_campaign",
            arguments={"campaign_id": str(uuid.uuid4())},
        )
        assert missing_res.is_error is False
        missing_data = json.loads(missing_res.content[0].text)
        assert missing_data["found"] is False


@pytest.mark.asyncio
async def test_tool_incident_lifecycle_read(operator_token, db_session):
    """Verify list_incidents and get_incident tools return database records without auth_token parameters."""
    incident = Incident(
        title=f"Suspicious activity-{uuid.uuid4().hex[:6]}",
        severity="medium",
        status="open",
        description="High volume of suspicious requests detected.",
    )
    db_session.add(incident)
    await db_session.commit()
    await db_session.refresh(incident)

    async with mcp_test_client(auth_token=operator_token) as session:
        # 1. list_incidents
        list_res = await session.call_tool("list_incidents", arguments={"page": 1, "page_size": 10})
        assert list_res.is_error is False
        incidents_data = json.loads(list_res.content[0].text)
        assert incidents_data["count"] >= 1
        found_ids = [i["id"] for i in incidents_data["incidents"]]
        assert str(incident.id) in found_ids

        # 2. get_incident (existing)
        get_res = await session.call_tool(
            "get_incident",
            arguments={"incident_id": str(incident.id)},
        )
        assert get_res.is_error is False
        inc_data = json.loads(get_res.content[0].text)
        assert inc_data["found"] is True
        assert inc_data["incident"]["title"] == incident.title

        # 3. get_incident (non-existent UUID)
        missing_res = await session.call_tool(
            "get_incident",
            arguments={"incident_id": str(uuid.uuid4())},
        )
        assert missing_res.is_error is False
        missing_data = json.loads(missing_res.content[0].text)
        assert missing_data["found"] is False


# =====================================================================
# 15. Comprehensive Unauthenticated Rejection for All 7 Tools
# =====================================================================

@pytest.mark.asyncio
async def test_all_seven_tools_reject_unauthenticated_execution():
    """Verify that every single tool call without Authorization header fails closed."""
    dummy_uuid = str(uuid.uuid4())
    tool_calls = [
        ("system_health", {}),
        ("list_agents", {}),
        ("get_agent", {"agent_id": dummy_uuid}),
        ("list_campaigns", {}),
        ("get_campaign", {"campaign_id": dummy_uuid}),
        ("list_incidents", {}),
        ("get_incident", {"incident_id": dummy_uuid}),
    ]

    async with mcp_test_client() as session:
        for tool_name, args in tool_calls:
            res = await session.call_tool(tool_name, arguments=args)
            assert res.is_error is True, f"Tool {tool_name} executed without authentication!"
            error_text = res.content[0].text.lower()
            assert "authentication required" in error_text or "error executing tool" in error_text


# =====================================================================
# 16. Identity Spoofing Rejection & Tamper Prevention
# =====================================================================

@pytest.mark.asyncio
async def test_identity_spoofing_prevented_in_tool_arguments_and_metadata(operator_token, test_operator, db_session):
    """Verify that callers cannot spoof actor identity, role, or permissions via arguments."""
    async with mcp_test_client(auth_token=operator_token) as session:
        # 1. Attacker tries to inject spoofed claims via tool arguments
        res_spoof = await session.call_tool(
            "system_health",
            arguments={"actor_id": str(uuid.uuid4()), "role": "admin", "is_admin": True},
        )
        assert res_spoof.is_error is True
        assert "Extra inputs are not permitted" in res_spoof.content[0].text

        # 2. Legitimate execution derives identity strictly from database record
        res_legit = await session.call_tool("system_health", arguments={})
        assert res_legit.is_error is False

    # Check that persisted audit record holds true operator ID, not any caller-controlled value
    stmt = (
        select(AuditLog)
        .where(AuditLog.actor_id == test_operator.id)
        .where(AuditLog.action == "mcp.system_health")
        .order_by(AuditLog.created_at.desc())
    )
    result = await db_session.execute(stmt)
    audit = result.scalars().first()
    assert audit is not None
    assert audit.actor_id == test_operator.id
    assert audit.actor_role == "security_operator"


# =====================================================================
# 17. Single-Pass Authentication (No Duplicate Lookups)
# =====================================================================

@pytest.mark.asyncio
async def test_transport_authentication_eliminates_duplicate_verification(operator_token):
    """Verify that trusted user entity from transport middleware is reused without duplicate DB queries."""
    with patch("app.mcp.context.authenticate_token", side_effect=AssertionError("Redundant authenticate_token call!")) as mock_auth:
        async with mcp_test_client(auth_token=operator_token) as session:
            res = await session.call_tool("system_health", arguments={})
            assert res.is_error is False
            # authenticate_token was NOT invoked inside mcp_security_context because transport middleware cached db_user
            mock_auth.assert_not_called()

