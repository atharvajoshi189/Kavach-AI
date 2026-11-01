"""Comprehensive test suite for AegisMesh 2.0 Step 08: Synthetic Target Agent & Sandbox Foundation.

Verifies:
1. SQLAlchemy models for SandboxEnvironment and SyntheticAsset (relationships, constraints, cascade).
2. Deterministic and idempotent Synthetic Asset Generator (RFC 5737 IP subnets, exact asset distributions).
3. Target Agent service functionality (asset discovery, metadata inspection, simulated findings, cross-sandbox boundary isolation).
4. OPA security policy enforcement (sandbox vs non-sandbox environments, default deny).
5. FastAPI Sandboxes API endpoints (seed, list, get by ID, unauthenticated rejection, 404 handling).
6. Model Context Protocol (MCP) target tools (Streamable HTTP, tool discovery of 10 tools, execution, unauthenticated fail-closed, schema forbid extra, audit trail verification).
"""

import ipaddress
import json
from unittest.mock import patch
import uuid
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.core.security import create_access_token, hash_password
from app.database.session import AsyncSessionLocal
from app.main import app
from app.models.audit_log import AuditLog
from app.models.sandbox import SandboxEnvironment
from app.models.synthetic_asset import SyntheticAsset
from app.models.user import User, UserRole
from app.security.gateway import authorize_action
from app.services.sandbox_service import (
    archive_sandbox,
    create_sandbox,
    delete_sandbox,
    get_sandbox_by_id,
    list_assets_in_sandbox,
    list_sandboxes,
    register_asset,
    validate_asset_sandbox_boundary,
    verify_sandbox_access,
)
from app.services.synthetic_generator import (
    DEMO_ASSET_DEFINITIONS,
    DEMO_SANDBOX_ID,
    DEMO_SANDBOX_NAME,
    RFC_5737_DOCUMENTATION_NETWORKS,
    initialize_demo_sandbox,
)
from app.services.target_agent_service import (
    discover_sandbox_assets,
    get_simulated_findings,
    inspect_synthetic_asset,
)
from app.services.audit_service import verify_event_hash
from tests.test_mcp_server import mcp_test_client


# =====================================================================
# 1. Database Model & Integrity Tests
# =====================================================================

@pytest.mark.asyncio
async def test_sandbox_and_asset_models_create_and_relationship(db_session):
    """Verify SandboxEnvironment and SyntheticAsset creation, relationships, and attributes."""
    sandbox = SandboxEnvironment(
        name=f"test-sandbox-{uuid.uuid4().hex[:6]}",
        description="Isolated verification environment",
        isolation_mode="simulated",
        status="active",
    )
    db_session.add(sandbox)
    await db_session.commit()
    await db_session.refresh(sandbox)

    assert sandbox.id is not None
    assert sandbox.isolation_mode == "simulated"
    assert sandbox.status == "active"

    # Register an asset
    asset = SyntheticAsset(
        sandbox_id=sandbox.id,
        name="test-web-srv",
        asset_type="web_application",
        ip_address="192.0.2.200",
        hostname="test-web.internal",
        os_metadata={"os_name": "Linux", "distribution": "Ubuntu 22.04 LTS"},
        service_metadata={"services": [{"port": 80, "service": "nginx"}]},
        configuration={"environment_mode": "test"},
        risk_level="high",
        simulated_vulnerabilities=[{"finding_id": "SIM-TEST-001", "severity": "high", "description": "Test Vuln"}],
    )
    db_session.add(asset)
    await db_session.commit()
    await db_session.refresh(asset)

    assert asset.id is not None
    assert asset.sandbox_id == sandbox.id
    assert asset.asset_type == "web_application"
    assert asset.ip_address == "192.0.2.200"

    # Query sandbox with assets relationship
    stmt = select(SandboxEnvironment).where(SandboxEnvironment.id == sandbox.id)
    res = await db_session.execute(stmt)
    fetched_sb = res.scalars().first()
    assert fetched_sb is not None

    stmt_assets = select(SyntheticAsset).where(SyntheticAsset.sandbox_id == sandbox.id)
    res_assets = await db_session.execute(stmt_assets)
    assets = list(res_assets.scalars().all())
    assert len(assets) == 1
    assert assets[0].name == "test-web-srv"


@pytest.mark.asyncio
async def test_unique_sandbox_name_constraint(db_session):
    """Verify unique constraint on sandbox name prevents duplicate environments."""
    unique_name = f"unique-sandbox-{uuid.uuid4().hex[:6]}"
    sb1 = SandboxEnvironment(
        name=unique_name,
        isolation_mode="simulated",
    )
    db_session.add(sb1)
    await db_session.commit()

    sb2 = SandboxEnvironment(
        name=unique_name,
        isolation_mode="simulated",
    )
    db_session.add(sb2)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_sandbox_deletion_cascades_to_assets(db_session):
    """Verify deleting a sandbox cascades and removes its synthetic assets."""
    sandbox = SandboxEnvironment(
        name=f"cascade-test-{uuid.uuid4().hex[:6]}",
        isolation_mode="simulated",
    )
    db_session.add(sandbox)
    await db_session.commit()
    await db_session.refresh(sandbox)

    asset = SyntheticAsset(
        sandbox_id=sandbox.id,
        name="cascade-asset",
        asset_type="api",
        hostname="cascade.sandbox.local",
        ip_address="198.51.100.99",
    )
    db_session.add(asset)
    await db_session.commit()
    asset_id = asset.id

    # Delete sandbox
    await db_session.delete(sandbox)
    await db_session.commit()

    # Asset must be deleted via CASCADE
    asset_stmt = select(SyntheticAsset).where(SyntheticAsset.id == asset_id)
    asset_res = await db_session.execute(asset_stmt)
    assert asset_res.scalars().first() is None


# =====================================================================
# 2. Deterministic & Idempotent Synthetic Generator Tests
# =====================================================================

@pytest.mark.asyncio
async def test_synthetic_generator_creates_demo_topology_and_is_idempotent(db_session):
    """Verify initialize_demo_sandbox creates exact topology, RFC 5737 IPs, and is strictly idempotent."""
    # First invocation
    demo_sandbox = await initialize_demo_sandbox(db_session)
    assert demo_sandbox is not None
    assert demo_sandbox.name == DEMO_SANDBOX_NAME
    created_assets = await list_assets_in_sandbox(db_session, demo_sandbox.id)
    assert len(created_assets) == 10

    # Verify exact asset type breakdown:
    # 3 servers, 2 databases, 2 web apps, 2 APIs, 1 network device
    type_counts: dict[str, int] = {}
    for a in created_assets:
        type_counts[a.asset_type] = type_counts.get(a.asset_type, 0) + 1

    assert type_counts.get("server") == 3, f"Expected 3 servers, got {type_counts.get('server')}"
    assert type_counts.get("database") == 2, f"Expected 2 databases, got {type_counts.get('database')}"
    assert type_counts.get("web_application") == 2, f"Expected 2 web applications, got {type_counts.get('web_application')}"
    assert type_counts.get("api") == 2, f"Expected 2 APIs, got {type_counts.get('api')}"
    assert type_counts.get("network_device") == 1, f"Expected 1 network device, got {type_counts.get('network_device')}"

    # Verify all IP addresses belong strictly to RFC 5737 documentation subnets
    doc_nets = [ipaddress.ip_network(net) for net in RFC_5737_DOCUMENTATION_NETWORKS]
    for a in created_assets:
        ip_obj = ipaddress.ip_address(a.ip_address)
        in_doc_range = any(ip_obj in net for net in doc_nets)
        assert in_doc_range is True, f"Asset IP {a.ip_address} is outside RFC 5737 documentation blocks!"
        # Verify simulated vulnerabilities structure
        assert isinstance(a.simulated_vulnerabilities, list)
        for f in a.simulated_vulnerabilities:
            assert "finding_id" in f
            assert "severity" in f
            assert "description" in f
            assert f["severity"] in ["critical", "high", "medium", "low", "info"]

    # Second invocation (Idempotency check)
    sb_second = await initialize_demo_sandbox(db_session)
    assert sb_second.id == demo_sandbox.id
    assets_second = await list_assets_in_sandbox(db_session, sb_second.id)
    assert len(assets_second) == 10
    first_ids = {a.id for a in created_assets}
    second_ids = {a.id for a in assets_second}
    assert first_ids == second_ids

    # Query DB directly to guarantee no duplicate records were added
    count_stmt = select(SyntheticAsset).where(SyntheticAsset.sandbox_id == demo_sandbox.id)
    count_res = await db_session.execute(count_stmt)
    assert len(list(count_res.scalars().all())) == 10


# =====================================================================
# 3. Target Agent Service & Cross-Sandbox Isolation Tests
# =====================================================================

@pytest.mark.asyncio
async def test_target_agent_service_discovery_and_inspection(db_session):
    """Verify Target Agent service discovers assets, filters by type, and inspects single assets."""
    demo_sb = await initialize_demo_sandbox(db_session)

    # 1. Discover all assets
    discovery_res = await discover_sandbox_assets(db_session, demo_sb.id)
    assert discovery_res["found"] is True
    assert discovery_res["count"] == 10

    # 2. Filter by asset_type
    db_res = await discover_sandbox_assets(db_session, demo_sb.id, asset_type="database")
    assert db_res["found"] is True
    assert db_res["count"] == 2
    for d in db_res["assets"]:
        assert d["asset_type"] == "database"

    # 3. Inspect single asset
    target_id = uuid.UUID(discovery_res["assets"][0]["id"])
    detail = await inspect_synthetic_asset(db_session, demo_sb.id, target_id)
    assert detail["found"] is True
    asset_data = detail["asset"]
    assert asset_data["id"] == str(target_id)
    assert "ip_address" in asset_data
    assert "os_metadata" in asset_data
    assert "service_metadata" in asset_data
    assert "simulated_findings_count" in asset_data


@pytest.mark.asyncio
async def test_target_agent_service_simulated_findings_filtering(db_session):
    """Verify get_simulated_findings filters findings by severity."""
    demo_sb = await initialize_demo_sandbox(db_session)
    assets = await list_assets_in_sandbox(db_session, demo_sb.id)

    # Find an asset with findings (e.g. the API Gateway with critical finding)
    target_asset = None
    for a in assets:
        if any(f.get("severity") == "critical" for f in a.simulated_vulnerabilities):
            target_asset = a
            break
    assert target_asset is not None

    # Retrieve all findings
    all_res = await get_simulated_findings(db_session, demo_sb.id, target_asset.id)
    assert all_res["found"] is True
    assert all_res["count"] >= 1
    assert all_res["is_simulated_environment"] is True

    # Retrieve critical findings only
    crit_res = await get_simulated_findings(
        db_session, demo_sb.id, target_asset.id, severity="critical"
    )
    assert crit_res["found"] is True
    assert crit_res["count"] >= 1
    for f in crit_res["findings"]:
        assert f["severity"] == "critical"


@pytest.mark.asyncio
async def test_target_agent_cross_sandbox_isolation(db_session):
    """Verify strict isolation preventing an asset in Sandbox A from being accessed via Sandbox B."""
    # Sandbox A
    sb_a = await initialize_demo_sandbox(db_session)
    assets_a = await list_assets_in_sandbox(db_session, sb_a.id)
    asset_a = assets_a[0]

    # Create distinct Sandbox B
    sb_b = await create_sandbox(
        db_session,
        name=f"isolated-sandbox-{uuid.uuid4().hex[:6]}",
        description="Secondary sandbox",
    )

    # Attempt to inspect Asset A using Sandbox B's ID -> rejected with found=False
    inspect_res = await inspect_synthetic_asset(db_session, sb_b.id, asset_a.id)
    assert inspect_res["found"] is False
    assert "not found in the specified sandbox" in inspect_res["error"]

    # Attempt to retrieve findings for Asset A using Sandbox B's ID -> rejected with found=False
    findings_res = await get_simulated_findings(db_session, sb_b.id, asset_a.id)
    assert findings_res["found"] is False
    assert "not found in the specified sandbox" in findings_res["error"]

    # validate_asset_sandbox_boundary helper
    assert await validate_asset_sandbox_boundary(db_session, sb_b.id, asset_a.id) is False
    assert await validate_asset_sandbox_boundary(db_session, sb_a.id, asset_a.id) is True


@pytest.mark.asyncio
async def test_target_agent_rejects_nonexistent_ids(db_session):
    """Verify proper handling when querying non-existent sandbox or asset IDs."""
    fake_sb = uuid.uuid4()
    fake_asset = uuid.uuid4()

    discover_res = await discover_sandbox_assets(db_session, fake_sb)
    assert discover_res["found"] is False
    assert "not found" in discover_res["error"].lower()

    inspect_res = await inspect_synthetic_asset(db_session, fake_sb, fake_asset)
    assert inspect_res["found"] is False
    assert "not found" in inspect_res["error"].lower()


# =====================================================================
# 4. OPA Policy Enforcement for Target Operations
# =====================================================================

@pytest.mark.asyncio
async def test_opa_target_agent_allowed_in_sandbox(test_operator, test_admin):
    """Verify Target Agent operations are permitted in sandbox environment for operator and admin."""
    # Target list
    op_decision = await authorize_action(
        user=test_operator,
        operation="mcp.target_list_assets",
        capability="read",
        resource_type="synthetic_asset",
        resource_id="asset-demo-1",
        environment="sandbox",
    )
    assert op_decision.allowed is True
    assert op_decision.decision == "allow"

    # Target inspect
    admin_decision = await authorize_action(
        user=test_admin,
        operation="mcp.target_inspect_asset",
        capability="read",
        resource_type="synthetic_asset",
        resource_id="asset-demo-2",
        environment="sandbox",
    )
    assert admin_decision.allowed is True
    assert admin_decision.decision == "allow"

    # Target findings
    findings_decision = await authorize_action(
        user=test_operator,
        operation="mcp.target_get_simulated_findings",
        capability="read",
        resource_type="synthetic_asset",
        resource_id="asset-demo-3",
        environment="sandbox",
    )
    assert findings_decision.allowed is True
    assert findings_decision.decision == "allow"


@pytest.mark.asyncio
async def test_opa_target_agent_prohibited_outside_sandbox(test_operator, test_admin):
    """Verify Target Agent operations are strictly denied outside sandbox environments even for admin."""
    prod_decision = await authorize_action(
        user=test_admin,
        operation="mcp.target_list_assets",
        capability="read",
        resource_type="synthetic_asset",
        resource_id="asset-demo-1",
        environment="production",
    )
    assert prod_decision.allowed is False
    assert prod_decision.decision == "deny"
    assert "restricted to sandbox" in prod_decision.reason


# =====================================================================
# 5. FastAPI Sandboxes REST API Tests
# =====================================================================

@pytest.mark.asyncio
async def test_sandbox_api_seed_and_idempotent(operator_token):
    """Verify POST /api/v1/sandboxes/seed seeds demo topology and is idempotent."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Seed demo sandbox
        res = await client.post(
            "/api/v1/sandboxes/seed",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["seeded_assets_count"] == 10
        assert data["name"] == DEMO_SANDBOX_NAME
        sandbox_id = data["sandbox_id"]

        # 2. Second seed call is idempotent
        res2 = await client.post(
            "/api/v1/sandboxes/seed",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert res2.status_code == 200
        data2 = res2.json()
        assert data2["sandbox_id"] == sandbox_id
        assert data2["seeded_assets_count"] == 10


@pytest.mark.asyncio
async def test_sandbox_api_list_and_get(operator_token, db_session):
    """Verify GET /api/v1/sandboxes/ and GET /api/v1/sandboxes/{id} endpoints."""
    demo_sb = await initialize_demo_sandbox(db_session)
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # List sandboxes
        res_list = await client.get(
            "/api/v1/sandboxes/?limit=100",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert res_list.status_code == 200
        items = res_list.json()
        assert len(items) >= 1

        # Get sandbox by ID
        res_detail = await client.get(
            f"/api/v1/sandboxes/{demo_sb.id}",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert res_detail.status_code == 200
        detail = res_detail.json()
        assert detail["id"] == str(demo_sb.id)
        assert detail["asset_count"] == 10


@pytest.mark.asyncio
async def test_sandbox_api_404_handling(operator_token):
    """Verify GET /api/v1/sandboxes/{id} returns 404 for non-existent sandbox."""
    fake_id = str(uuid.uuid4())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get(
            f"/api/v1/sandboxes/{fake_id}",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert res.status_code == 404
        assert "not found" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_sandbox_api_unauthenticated_rejected():
    """Verify unauthenticated requests to sandboxes API return 401."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/api/v1/sandboxes/")
        assert res.status_code == 401


# =====================================================================
# 6. MCP Target Agent Tools via Streamable HTTP Transport
# =====================================================================

@pytest.mark.asyncio
async def test_mcp_discovery_advertises_all_10_tools(operator_token):
    """Verify MCP tools/list advertises all 10 tools including the 3 new target agent tools."""
    expected_tools = {
        "system_health",
        "list_agents",
        "get_agent",
        "list_campaigns",
        "get_campaign",
        "list_incidents",
        "get_incident",
        "target_list_assets",
        "target_inspect_asset",
        "target_get_simulated_findings",
    }

    async with mcp_test_client(auth_token=operator_token) as session:
        tools_res = await session.list_tools()
        advertised_names = {t.name for t in tools_res.tools}
        assert expected_tools.issubset(advertised_names), f"Missing tools: {expected_tools - advertised_names}"
        assert len(tools_res.tools) == 10

        # Ensure no tool schema contains auth_token
        for tool in tools_res.tools:
            schema_json = json.dumps(tool.input_schema)
            assert "auth_token" not in schema_json, f"auth_token found in {tool.name} schema!"


@pytest.mark.asyncio
async def test_mcp_target_list_assets_tool(operator_token, db_session):
    """Verify target_list_assets MCP tool execution over Streamable HTTP."""
    demo_sb = await initialize_demo_sandbox(db_session)

    async with mcp_test_client(auth_token=operator_token) as session:
        res = await session.call_tool(
            "target_list_assets",
            arguments={"sandbox_id": str(demo_sb.id)},
        )
        assert res.is_error is False
        data = json.loads(res.content[0].text)
        assert data["count"] == 10
        assert data["sandbox_id"] == str(demo_sb.id)
        assert len(data["assets"]) == 10


@pytest.mark.asyncio
async def test_mcp_target_inspect_asset_tool(operator_token, db_session):
    """Verify target_inspect_asset MCP tool execution over Streamable HTTP."""
    demo_sb = await initialize_demo_sandbox(db_session)
    assets = await list_assets_in_sandbox(db_session, demo_sb.id)
    asset = assets[0]

    async with mcp_test_client(auth_token=operator_token) as session:
        res = await session.call_tool(
            "target_inspect_asset",
            arguments={
                "sandbox_id": str(demo_sb.id),
                "asset_id": str(asset.id),
            },
        )
        assert res.is_error is False
        data = json.loads(res.content[0].text)
        assert data["found"] is True
        assert data["asset"]["id"] == str(asset.id)
        assert data["asset"]["name"] == asset.name
        assert data["asset"]["ip_address"] == asset.ip_address


@pytest.mark.asyncio
async def test_mcp_target_get_simulated_findings_tool(operator_token, db_session):
    """Verify target_get_simulated_findings MCP tool execution over Streamable HTTP."""
    demo_sb = await initialize_demo_sandbox(db_session)
    assets = await list_assets_in_sandbox(db_session, demo_sb.id)
    # Find asset with critical finding
    vuln_asset = next(a for a in assets if any(f.get("severity") == "critical" for f in a.simulated_vulnerabilities))

    async with mcp_test_client(auth_token=operator_token) as session:
        res = await session.call_tool(
            "target_get_simulated_findings",
            arguments={
                "sandbox_id": str(demo_sb.id),
                "asset_id": str(vuln_asset.id),
                "severity": "critical",
            },
        )
        assert res.is_error is False
        data = json.loads(res.content[0].text)
        assert data["found"] is True
        assert len(data["findings"]) >= 1
        for f in data["findings"]:
            assert f["severity"] == "critical"


@pytest.mark.asyncio
async def test_mcp_target_tools_unauthenticated_fail_closed(db_session):
    """Verify unauthenticated execution of all 3 target tools fails closed."""
    demo_sb = await initialize_demo_sandbox(db_session)
    assets = await list_assets_in_sandbox(db_session, demo_sb.id)
    asset_id = str(assets[0].id)
    sb_id = str(demo_sb.id)

    target_calls = [
        ("target_list_assets", {"sandbox_id": sb_id}),
        ("target_inspect_asset", {"sandbox_id": sb_id, "asset_id": asset_id}),
        ("target_get_simulated_findings", {"sandbox_id": sb_id, "asset_id": asset_id}),
    ]

    async with mcp_test_client() as session:
        for tool_name, args in target_calls:
            res = await session.call_tool(tool_name, arguments=args)
            assert res.is_error is True, f"Target tool {tool_name} executed without authentication!"


@pytest.mark.asyncio
async def test_mcp_target_tools_extra_fields_forbidden(operator_token, db_session):
    """Verify strict input schema enforcement (extra='forbid') on target tools."""
    demo_sb = await initialize_demo_sandbox(db_session)

    async with mcp_test_client(auth_token=operator_token) as session:
        res = await session.call_tool(
            "target_list_assets",
            arguments={"sandbox_id": str(demo_sb.id), "injected_param": "malicious"},
        )
        assert res.is_error is True
        assert "Extra inputs are not permitted" in res.content[0].text


@pytest.mark.asyncio
async def test_mcp_target_tools_audit_persistence_and_hash_integrity(operator_token, test_operator, db_session):
    """Verify persistent audit logging and SHA-256 hash chaining for target tool operations."""
    demo_sb = await initialize_demo_sandbox(db_session)

    async with mcp_test_client(auth_token=operator_token) as session:
        res = await session.call_tool(
            "target_list_assets",
            arguments={"sandbox_id": str(demo_sb.id)},
        )
        assert res.is_error is False

    # Check database audit log
    stmt = (
        select(AuditLog)
        .where(AuditLog.actor_id == test_operator.id)
        .where(AuditLog.action == "mcp.target_list_assets")
        .order_by(AuditLog.created_at.desc())
    )
    result = await db_session.execute(stmt)
    audit = result.scalars().first()

    assert audit is not None
    assert audit.actor_id == test_operator.id
    assert audit.actor_role == "security_operator"
    assert audit.resource_type == "synthetic_asset"
    assert audit.event_data.get("tool") == "target_list_assets"
    assert verify_event_hash(audit) is True


# =====================================================================
# 7. Step 08.1 Security & Forensic Integrity Hardening Tests
# =====================================================================

@pytest.mark.asyncio
async def test_opa_viewer_role_denied_target_operations(test_viewer):
    """Verify viewer role is strictly denied access to Target Agent tools by OPA least-privilege policy."""
    decision = await authorize_action(
        user=test_viewer,
        operation="mcp.target_list_assets",
        capability="read",
        resource_type="synthetic_asset",
        resource_id="asset-demo-1",
        environment="sandbox",
    )
    assert decision.allowed is False
    assert decision.decision == "deny"
    assert "Viewer role is not authorized" in decision.reason


@pytest.mark.asyncio
async def test_mcp_viewer_denied_target_tools_streamable_http(viewer_token, db_session):
    """Verify viewer calling target tools over Streamable HTTP is rejected fail-closed with permission denied."""
    demo_sb = await initialize_demo_sandbox(db_session)

    async with mcp_test_client(auth_token=viewer_token) as session:
        res = await session.call_tool(
            "target_list_assets",
            arguments={"sandbox_id": str(demo_sb.id)},
        )
        assert res.is_error is True
        error_msg = res.content[0].text.lower()
        assert "permission denied" in error_msg or "error executing tool" in error_msg


@pytest.mark.asyncio
async def test_sandbox_ownership_isolation_between_operators(db_session, test_operator, test_admin):
    """Verify user-assigned sandboxes enforce ownership isolation between distinct operators."""
    # Operator 1 owns Sandbox 1
    sb1 = await create_sandbox(
        db_session,
        name=f"operator1-sandbox-{uuid.uuid4().hex[:6]}",
        owner_id=test_operator.id,
    )

    # Create Operator 2
    suffix = uuid.uuid4().hex[:6]
    op2 = User(
        email=f"op2_{suffix}@example.com",
        username=f"op2_{suffix}",
        hashed_password=hash_password("Op2Pass123!"),
        role=UserRole.SECURITY_OPERATOR,
        is_active=True,
        is_verified=True,
    )
    db_session.add(op2)
    await db_session.commit()
    await db_session.refresh(op2)

    # 1. Operator 1 has access to own sandbox
    assert verify_sandbox_access(sb1, test_operator) is True

    # 2. Operator 2 is rejected from accessing Operator 1's sandbox
    assert verify_sandbox_access(sb1, op2) is False

    # 3. Admin has access to Operator 1's sandbox
    assert verify_sandbox_access(sb1, test_admin) is True


@pytest.mark.asyncio
async def test_unauthorized_user_forbidden_via_sandboxes_api(db_session, test_operator):
    """Verify unauthorized operator receives 403 Forbidden when accessing another user's sandbox via API."""
    # Sandbox owned by test_operator
    sb = await create_sandbox(
        db_session,
        name=f"private-sb-{uuid.uuid4().hex[:6]}",
        owner_id=test_operator.id,
    )

    # Create Operator 2 and token
    suffix = uuid.uuid4().hex[:6]
    op2 = User(
        email=f"op2_{suffix}@example.com",
        username=f"op2_{suffix}",
        hashed_password=hash_password("Op2Pass123!"),
        role=UserRole.SECURITY_OPERATOR,
        is_active=True,
        is_verified=True,
    )
    db_session.add(op2)
    await db_session.commit()
    await db_session.refresh(op2)
    op2_token = create_access_token(subject=op2.id, role=op2.role.value)
    op1_token = create_access_token(subject=test_operator.id, role=test_operator.role.value)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Operator 2 receives 403 Forbidden
        res_op2 = await client.get(
            f"/api/v1/sandboxes/{sb.id}",
            headers={"Authorization": f"Bearer {op2_token}"},
        )
        assert res_op2.status_code == 403
        assert "permission" in res_op2.json()["detail"].lower()

        # Operator 1 receives 200 OK
        res_op1 = await client.get(
            f"/api/v1/sandboxes/{sb.id}",
            headers={"Authorization": f"Bearer {op1_token}"},
        )
        assert res_op1.status_code == 200
        assert res_op1.json()["id"] == str(sb.id)


@pytest.mark.asyncio
async def test_unauthorized_user_denied_via_mcp_target_tools(db_session, test_operator):
    """Verify unauthorized operator cannot discover or inspect another user's sandbox assets via MCP."""
    sb = await create_sandbox(
        db_session,
        name=f"mcp-private-sb-{uuid.uuid4().hex[:6]}",
        owner_id=test_operator.id,
    )

    # Create Operator 2
    suffix = uuid.uuid4().hex[:6]
    op2 = User(
        email=f"op2_{suffix}@example.com",
        username=f"op2_{suffix}",
        hashed_password=hash_password("Op2Pass123!"),
        role=UserRole.SECURITY_OPERATOR,
        is_active=True,
        is_verified=True,
    )
    db_session.add(op2)
    await db_session.commit()
    await db_session.refresh(op2)
    op2_token = create_access_token(subject=op2.id, role=op2.role.value)

    async with mcp_test_client(auth_token=op2_token) as session:
        res = await session.call_tool(
            "target_list_assets",
            arguments={"sandbox_id": str(sb.id)},
        )
        assert res.is_error is False
        data = json.loads(res.content[0].text)
        assert data["found"] is False
        assert "access denied" in data["error"].lower()


@pytest.mark.asyncio
async def test_sandbox_archival_preserves_forensic_assets_and_locks_target_ops(db_session, operator_token):
    """Verify archive_sandbox transitions status to 'archived', preserves all assets, and locks target ops."""
    demo_sb = await initialize_demo_sandbox(db_session)
    assets_before = await list_assets_in_sandbox(db_session, demo_sb.id)
    assert len(assets_before) == 10

    # Archive the sandbox
    archived_sb = await archive_sandbox(db_session, demo_sb.id)
    assert archived_sb.status == "archived"

    # All 10 synthetic assets remain fully preserved for forensic review
    assets_after = await list_assets_in_sandbox(db_session, demo_sb.id)
    assert len(assets_after) == 10

    # Active target inspection operations on archived sandbox are locked out
    async with mcp_test_client(auth_token=operator_token) as session:
        res = await session.call_tool(
            "target_list_assets",
            arguments={"sandbox_id": str(demo_sb.id)},
        )
        assert res.is_error is False
        data = json.loads(res.content[0].text)
        assert data["found"] is False
        assert "archived" in data["error"].lower()

    # Reset status back to active for clean test state
    archived_sb.status = "active"
    await db_session.commit()


@pytest.mark.asyncio
async def test_destructive_deletion_restricted_to_admin(db_session, test_operator, test_admin):
    """Verify destructive delete_sandbox is strictly rejected for non-admins and permitted for admins."""
    sb = await create_sandbox(
        db_session,
        name=f"del-test-sb-{uuid.uuid4().hex[:6]}",
        owner_id=test_operator.id,
    )

    # Non-admin attempt raises PermissionError
    with pytest.raises(PermissionError) as excinfo:
        await delete_sandbox(db_session, sb.id, user=test_operator)
    assert "restricted to administrators" in str(excinfo.value).lower()

    # Admin attempt succeeds
    await delete_sandbox(db_session, sb.id, user=test_admin)
    fetched = await get_sandbox_by_id(db_session, sb.id)
    assert fetched is None


@pytest.mark.asyncio
async def test_audit_persistence_failure_fails_closed_in_target_tools(operator_token, db_session):
    """Verify that if AuditLog persistence fails during target tool execution, the tool fails closed."""
    demo_sb = await initialize_demo_sandbox(db_session)

    with patch("app.mcp.context.record_audit_log", side_effect=RuntimeError("Database write error during audit!")):
        async with mcp_test_client(auth_token=operator_token) as session:
            res = await session.call_tool(
                "target_list_assets",
                arguments={"sandbox_id": str(demo_sb.id)},
            )
            assert res.is_error is True
            error_text = res.content[0].text.lower()
            assert "database write error during audit" in error_text or "error executing tool" in error_text

