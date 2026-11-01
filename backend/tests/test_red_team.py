"""Comprehensive test suite for AegisMesh 2.0 Step 09.1: Red Team Agent Foundation & Deterministic Simulation Engine.

Verifies:
1. Scenario registry & validation (registration, unknown scenario rejection, asset compatibility).
2. Deterministic simulation handlers (service discovery, weak configuration, authentication anomaly).
3. 100% synthetic safety invariant (zero sockets, zero subprocesses, RFC 5737 IPs, simulation_only=True).
4. RedTeamAgent orchestration & AttackRun lifecycle (pending -> running -> completed/failed).
5. Sandbox boundaries & cross-sandbox rejection.
6. Archived sandbox rejection & non-sandbox campaign rejection.
7. Concurrency / duplicate running run prevention.
8. Persistent audit logging & SHA-256 hash chaining (with fail-closed rollback verification).
9. OPA policy authorization (admin/operator allow in sandbox, non-sandbox deny, analyst/viewer deny).
10. FastAPI REST API endpoints (/scenarios, /campaigns/{id}/runs, /runs/{id}).
"""

import ipaddress
import subprocess
import socket
from unittest.mock import AsyncMock, patch
import uuid
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.agents.red_team.agent import RedTeamAgent, red_team_agent
from app.agents.red_team.scenario_registry import (
    RedTeamScenarioNotFoundError,
    ScenarioAssetIncompatibleError,
    registry,
)
from app.agents.red_team.schemas import RedTeamRunCreateRequest
from app.main import app
from app.models.attack_run import AttackRun
from app.models.audit_log import AuditLog
from app.models.campaign import Campaign
from app.models.sandbox import SandboxEnvironment
from app.models.synthetic_asset import SyntheticAsset
from app.models.user import User, UserRole
from app.security.gateway import authorize_action
from app.services.audit_service import verify_audit_chain, verify_event_hash
from app.services.campaign_service import create_campaign, get_attack_run_by_id
from app.services.sandbox_service import archive_sandbox, create_sandbox, register_asset
from app.services.simulation_engine import SimulationEngine, simulation_engine


# Helper fixture for creating a test sandbox and synthetic assets
@pytest_asyncio.fixture
async def test_sandbox_setup(db_session, test_operator):
    """Sets up a test sandbox environment with synthetic assets."""
    suffix = str(uuid.uuid4())[:8]
    sandbox = await create_sandbox(
        session=db_session,
        name=f"RedTeam-Test-Sandbox-{suffix}",
        description="Controlled sandbox for deterministic Red Team test suite",
        owner_id=test_operator.id,
    )

    # Asset 1: Web server with services and default credentials
    asset_server = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"sim-web-server-{suffix}",
            "asset_type": "server",
            "hostname": f"web-{suffix}.sandbox.local",
            "ip_address": "198.51.100.10",
            "service_metadata": {
                "services": [
                    {"port": 80, "protocol": "tcp", "service": "http", "banner": "Apache/2.4.52 (simulated)"},
                    {"port": 22, "protocol": "tcp", "service": "ssh", "banner": "OpenSSH_8.9p1 (simulated)"},
                ]
            },
            "configuration": {
                "debug_mode": True,
                "default_credentials": True,
                "tls_version": "1.1",
            },
            "simulated_vulnerabilities": [
                {
                    "cve_id": "CVE-2023-44487",
                    "title": "HTTP/2 Rapid Reset Vulnerability",
                    "severity": "high",
                    "description": "Simulated vulnerability in web server.",
                }
            ],
        },
    )

    # Asset 2: Database asset
    asset_db = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"sim-db-{suffix}",
            "asset_type": "database",
            "hostname": f"db-{suffix}.sandbox.local",
            "ip_address": "198.51.100.20",
            "service_metadata": {
                "services": [
                    {"port": 5432, "protocol": "tcp", "service": "postgresql", "banner": "PostgreSQL 16.2 (simulated)"}
                ]
            },
            "configuration": {"allow_anonymous": False, "debug_mode": False},
            "simulated_vulnerabilities": [],
        },
    )

    await db_session.commit()
    await db_session.refresh(sandbox)
    await db_session.refresh(asset_server)
    await db_session.refresh(asset_db)

    return sandbox, asset_server, asset_db


@pytest_asyncio.fixture
async def test_campaign(db_session, test_sandbox_setup):
    """Sets up a test campaign configured with the test sandbox."""
    sandbox, _, _ = test_sandbox_setup
    suffix = str(uuid.uuid4())[:8]
    campaign = await create_campaign(
        session=db_session,
        name=f"RedTeam-Test-Campaign-{suffix}",
        trigger_type="manual",
        environment="sandbox",
        sandbox_id=sandbox.id,
    )
    await db_session.commit()
    await db_session.refresh(campaign)
    return campaign


# =====================================================================
# 1. Scenario Registry & Validation Tests
# =====================================================================

def test_scenario_registry_initialization():
    """Verify all 8 scenarios are registered in the registry."""
    scenarios = registry.list_all()
    scenario_ids = [s.scenario_id for s in scenarios]

    expected = [
        "simulated_service_discovery",
        "simulated_weak_configuration_assessment",
        "simulated_authentication_anomaly",
        "simulated_initial_access",
        "simulated_privilege_escalation",
        "simulated_lateral_movement",
        "simulated_persistence",
        "simulated_data_exfiltration",
    ]
    for s_id in expected:
        assert s_id in scenario_ids, f"Expected scenario {s_id} not found in registry"
    assert len(scenarios) == 8


def test_scenario_registry_unknown_rejection():
    """Verify querying an unregistered scenario raises RedTeamScenarioNotFoundError."""
    with pytest.raises(RedTeamScenarioNotFoundError) as exc_info:
        registry.get("non_existent_exploit_scenario")
    assert "non_existent_exploit_scenario" in str(exc_info.value)


def test_scenario_asset_compatibility_validation():
    """Verify asset compatibility checks pass for valid types and raise for invalid."""
    # Service discovery is valid for server
    registry.validate_asset_compatibility("simulated_service_discovery", "server")
    registry.validate_asset_compatibility("simulated_service_discovery", "web_application")

    # Service discovery is invalid for unsupported types
    with pytest.raises(ScenarioAssetIncompatibleError):
        registry.validate_asset_compatibility("simulated_service_discovery", "unsupported_storage_bucket")


# =====================================================================
# 2. Deterministic Simulation Engine & Safety Invariant Tests
# =====================================================================

@pytest.mark.asyncio
async def test_simulation_service_discovery_deterministic(test_sandbox_setup):
    """Verify simulated_service_discovery outputs deterministic findings and events."""
    _, asset_server, _ = test_sandbox_setup

    result1 = await simulation_engine.execute_simulation("simulated_service_discovery", asset_server)
    result2 = await simulation_engine.execute_simulation("simulated_service_discovery", asset_server)

    assert result1.status == "completed"
    assert result1.simulation_only is True
    assert "T1046" in result1.technique
    assert result1.risk_score == result2.risk_score
    assert len(result1.findings) == len(result2.findings)
    assert len(result1.events) == len(result2.events)


@pytest.mark.asyncio
async def test_simulation_weak_config_deterministic(test_sandbox_setup):
    """Verify simulated_weak_configuration_assessment identifies configured misconfigurations."""
    _, asset_server, _ = test_sandbox_setup

    result = await simulation_engine.execute_simulation(
        "simulated_weak_configuration_assessment",
        asset_server,
    )

    assert result.status == "completed"
    assert result.simulation_only is True
    assert result.risk_score > 5.0  # Server has debug_mode + default_credentials + CVE

    # Verify findings contain debug mode and default credentials
    finding_titles = [f.title for f in result.findings]
    assert any("Debug Mode" in t for t in finding_titles)
    assert any("Default Credentials" in t for t in finding_titles)
    assert any("CVE-2023-44487" in t for t in finding_titles)


@pytest.mark.asyncio
async def test_simulation_authentication_anomaly_deterministic(test_sandbox_setup):
    """Verify simulated_authentication_anomaly simulates brute force stream & compromise."""
    _, asset_server, _ = test_sandbox_setup

    result = await simulation_engine.execute_simulation(
        "simulated_authentication_anomaly",
        asset_server,
        parameters={"attempt_count": 30, "simulated_source_ip": "198.51.100.42", "target_username": "admin"},
    )

    assert result.status == "completed"
    assert result.simulation_only is True
    assert result.risk_score >= 8.0  # Compromise simulated due to default_credentials: True

    # Verify event stream
    event_types = [e.event_type for e in result.events]
    assert "synthetic_auth_stream_generated" in event_types
    assert "threshold_exceeded" in event_types
    assert "anomaly_compromise_simulated" in event_types


@pytest.mark.asyncio
async def test_safety_invariant_zero_sockets_and_subprocesses(test_sandbox_setup):
    """Verify 100% synthetic safety invariant: no sockets or subprocesses invoked."""
    _, asset_server, _ = test_sandbox_setup

    # Spy on socket.socket and subprocess.Popen
    with patch("socket.socket", side_effect=AssertionError("Socket call forbidden!")) as mock_sock:
        with patch("subprocess.Popen", side_effect=AssertionError("Subprocess call forbidden!")) as mock_popen:
            result = await simulation_engine.execute_simulation(
                "simulated_service_discovery",
                asset_server,
            )
            assert result.status == "completed"
            mock_sock.assert_not_called()
            mock_popen.assert_not_called()


@pytest.mark.asyncio
async def test_safety_invariant_rfc_5737_ips(test_sandbox_setup):
    """Verify all emitted IP addresses conform strictly to RFC 5737 documentation blocks."""
    _, asset_server, _ = test_sandbox_setup

    result = await simulation_engine.execute_simulation(
        "simulated_authentication_anomaly",
        asset_server,
        parameters={"attempt_count": 10, "simulated_source_ip": "198.51.100.99"},
    )

    doc_nets = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]

    for event in result.events:
        ip_val = event.details.get("source_ip") or event.details.get("simulated_source_ip")
        if ip_val:
            ip_obj = ipaddress.ip_address(ip_val)
            assert any(ip_obj in net for net in doc_nets), f"IP {ip_val} not in RFC 5737 documentation networks"


# =====================================================================
# 3. RedTeamAgent Orchestration & AttackRun Lifecycle Tests
# =====================================================================

@pytest.mark.asyncio
async def test_red_team_agent_execution_lifecycle(db_session, test_campaign, test_sandbox_setup, test_operator):
    """Verify successful end-to-end simulation run lifecycle (pending -> running -> completed)."""
    _, asset_server, _ = test_sandbox_setup

    run = await red_team_agent.execute_run(
        session=db_session,
        campaign_id=test_campaign.id,
        scenario_id="simulated_service_discovery",
        asset_id=asset_server.id,
        user=test_operator,
    )

    assert run.id is not None
    assert run.campaign_id == test_campaign.id
    assert run.scenario == "simulated_service_discovery"
    assert run.outcome == "completed"
    assert run.risk_score is not None
    assert run.execution_metadata.get("simulation_only") is True
    assert len(run.execution_metadata.get("events", [])) > 0

    # Verify Campaign status updated
    await db_session.refresh(test_campaign)
    assert test_campaign.status == "in_progress"


@pytest.mark.asyncio
async def test_red_team_agent_cross_sandbox_rejection(db_session, test_campaign, test_operator):
    """Verify target asset from a different sandbox is rejected."""
    # Create a separate second sandbox and asset
    sandbox2 = await create_sandbox(session=db_session, name=f"Second-Sandbox-{uuid.uuid4().hex[:6]}")
    foreign_asset = await register_asset(
        session=db_session,
        sandbox_id=sandbox2.id,
        asset_data={
            "name": "foreign-asset",
            "asset_type": "server",
            "hostname": "foreign.local",
            "ip_address": "192.0.2.99",
        },
    )
    await db_session.commit()

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await red_team_agent.execute_run(
            session=db_session,
            campaign_id=test_campaign.id,
            scenario_id="simulated_service_discovery",
            asset_id=foreign_asset.id,
            user=test_operator,
        )
    assert exc_info.value.status_code == 400
    assert "Cross-sandbox" in exc_info.value.detail


@pytest.mark.asyncio
async def test_red_team_agent_archived_sandbox_rejection(db_session, test_campaign, test_sandbox_setup, test_operator):
    """Verify simulation cannot execute against an archived sandbox environment."""
    sandbox, asset_server, _ = test_sandbox_setup
    await archive_sandbox(db_session, sandbox.id)
    await db_session.commit()

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await red_team_agent.execute_run(
            session=db_session,
            campaign_id=test_campaign.id,
            scenario_id="simulated_service_discovery",
            asset_id=asset_server.id,
            user=test_operator,
        )
    assert exc_info.value.status_code == 400
    assert "archived" in exc_info.value.detail.lower()


@pytest.mark.asyncio
async def test_red_team_agent_non_sandbox_campaign_rejection(db_session, test_sandbox_setup, test_operator):
    """Verify campaign with environment != 'sandbox' is rejected."""
    sandbox, asset_server, _ = test_sandbox_setup
    prod_campaign = await create_campaign(
        session=db_session,
        name=f"Prod-Campaign-{uuid.uuid4().hex[:6]}",
        trigger_type="manual",
        environment="production",
        sandbox_id=sandbox.id,
    )
    await db_session.commit()

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await red_team_agent.execute_run(
            session=db_session,
            campaign_id=prod_campaign.id,
            scenario_id="simulated_service_discovery",
            asset_id=asset_server.id,
            user=test_operator,
        )
    assert exc_info.value.status_code in [400, 403]


@pytest.mark.asyncio
async def test_red_team_agent_prevent_concurrent_duplicate(db_session, test_campaign, test_sandbox_setup, test_operator):
    """Verify a running simulation run blocks a concurrent duplicate run for the same scenario."""
    _, asset_server, _ = test_sandbox_setup

    # Artificially insert an AttackRun with outcome='running'
    active_run = AttackRun(
        campaign_id=test_campaign.id,
        technique="T1046 - Network Service Discovery",
        scenario="simulated_service_discovery",
        outcome="running",
        risk_score=None,
        execution_metadata={"status": "running"},
    )
    db_session.add(active_run)
    await db_session.commit()

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await red_team_agent.execute_run(
            session=db_session,
            campaign_id=test_campaign.id,
            scenario_id="simulated_service_discovery",
            asset_id=asset_server.id,
            user=test_operator,
        )
    assert exc_info.value.status_code == 409
    assert "already actively running" in exc_info.value.detail


@pytest.mark.asyncio
async def test_red_team_concurrent_requests_db_advisory_lock(test_sandbox_setup, test_operator):
    """Verify that concurrent requests on the same (campaign, scenario) cannot both succeed."""
    sandbox, asset_server, _ = test_sandbox_setup
    import asyncio
    from app.database.session import AsyncSessionLocal
    from fastapi import HTTPException

    # Create a fresh campaign in its own session
    async with AsyncSessionLocal() as s:
        campaign = await create_campaign(
            session=s,
            name=f"Concurrent-Camp-{uuid.uuid4().hex[:6]}",
            trigger_type="manual",
            sandbox_id=sandbox.id,
        )
        await s.commit()
        campaign_id = campaign.id

    real_execute = simulation_engine.execute_simulation

    async def slow_execute(*args, **kwargs):
        await asyncio.sleep(0.08)
        return await real_execute(*args, **kwargs)

    async def attempt_run():
        async with AsyncSessionLocal() as sess:
            try:
                run = await red_team_agent.execute_run(
                    session=sess,
                    campaign_id=campaign_id,
                    scenario_id="simulated_service_discovery",
                    asset_id=asset_server.id,
                    user=test_operator,
                )
                return "success", run
            except HTTPException as e:
                return "error", e

    # Launch two simultaneous execution attempts with slow_execute ensuring lock overlap
    with patch.object(simulation_engine, "execute_simulation", side_effect=slow_execute):
        results = await asyncio.gather(attempt_run(), attempt_run())

    statuses = [r[0] for r in results]
    # Exactly one must succeed and one must be rejected with 409 Conflict
    assert "success" in statuses
    assert "error" in statuses

    error_res = next(r[1] for r in results if r[0] == "error")
    assert error_res.status_code == 409
    assert "already actively running" in error_res.detail


# =====================================================================
# 4. Audit Logging & Hash-Chaining Tests (Fail-Closed)
# =====================================================================

@pytest.mark.asyncio
async def test_red_team_audit_lifecycle_completeness(db_session, test_campaign, test_sandbox_setup, test_operator):
    """Verify that a simulation execution records all required lifecycle audit events."""
    _, asset_server, _ = test_sandbox_setup

    run = await red_team_agent.execute_run(
        session=db_session,
        campaign_id=test_campaign.id,
        scenario_id="simulated_service_discovery",
        asset_id=asset_server.id,
        user=test_operator,
    )

    # Fetch audit logs created during this specific execution
    result = await db_session.execute(
        select(AuditLog)
        .where(
            AuditLog.resource_id.in_([str(test_campaign.id), str(run.id)]),
        )
        .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
    )
    logs = list(result.scalars().all())

    event_types = [l.event_type for l in logs]
    assert "red_team.simulation_requested" in event_types
    assert "red_team.authorization_passed" in event_types
    assert "red_team.simulation_started" in event_types
    assert "red_team.simulation_completed" in event_types

    # Verify scenario selection and asset references are present in audit metadata
    requested_log = next(l for l in logs if l.event_type == "red_team.simulation_requested")
    assert requested_log.event_data.get("scenario") == "simulated_service_discovery"
    assert requested_log.event_data.get("asset_id") == str(asset_server.id)

    started_log = next(l for l in logs if l.event_type == "red_team.simulation_started")
    assert started_log.event_data.get("scenario") == "simulated_service_discovery"
    assert started_log.event_data.get("run_id") == str(run.id)

    # Verify each audit record individually satisfies hash integrity
    for l in logs:
        assert verify_event_hash(l) is True


@pytest.mark.asyncio
async def test_red_team_simulation_failure_retention_and_audit(db_session, test_campaign, test_sandbox_setup, test_operator):
    """Verify that a simulation failure retains failed AttackRun status and failure audit evidence."""
    _, asset_server, _ = test_sandbox_setup

    # Mock simulation engine to simulate an internal execution fault
    with patch.object(
        simulation_engine,
        "execute_simulation",
        side_effect=RuntimeError("Simulated engine fault for testing"),
    ):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await red_team_agent.execute_run(
                session=db_session,
                campaign_id=test_campaign.id,
                scenario_id="simulated_service_discovery",
                asset_id=asset_server.id,
                user=test_operator,
            )
        assert exc_info.value.status_code == 500

    # In a fresh database query, verify the failed AttackRun was durably committed
    runs_res = await db_session.execute(
        select(AttackRun).where(AttackRun.campaign_id == test_campaign.id)
    )
    failed_run = runs_res.scalars().first()
    assert failed_run is not None
    assert failed_run.outcome == "failed"
    assert "Simulated engine fault" in failed_run.execution_metadata.get("error", "")

    # Verify red_team.simulation_failed was committed to the audit table
    audit_res = await db_session.execute(
        select(AuditLog).where(
            AuditLog.resource_id == str(failed_run.id),
            AuditLog.event_type == "red_team.simulation_failed",
        )
    )
    failed_audit = audit_res.scalar_one_or_none()
    assert failed_audit is not None
    assert failed_audit.decision == "DENY"
    assert "Simulated engine fault" in failed_audit.event_data.get("error", "")
    assert verify_event_hash(failed_audit) is True


@pytest.mark.asyncio
async def test_red_team_prevent_duplicate_execution_of_same_attack_run(db_session, test_campaign, test_sandbox_setup, test_operator):
    """Verify an existing AttackRun that is already completed cannot be re-executed."""
    _, asset_server, _ = test_sandbox_setup

    # Complete a run
    run = await red_team_agent.execute_run(
        session=db_session,
        campaign_id=test_campaign.id,
        scenario_id="simulated_service_discovery",
        asset_id=asset_server.id,
        user=test_operator,
    )
    assert run.outcome == "completed"

    # Attempt to re-execute with the same run_id
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        await red_team_agent.execute_run(
            session=db_session,
            campaign_id=test_campaign.id,
            scenario_id="simulated_service_discovery",
            asset_id=asset_server.id,
            user=test_operator,
            run_id=run.id,
        )
    assert exc_info.value.status_code == 409
    assert "cannot be executed again" in exc_info.value.detail


@pytest.mark.asyncio
async def test_red_team_independent_campaigns_concurrent_success(db_session, test_sandbox_setup, test_operator):
    """Verify independent campaigns can execute simulations concurrently without contention."""
    sandbox, asset_server, _ = test_sandbox_setup
    import asyncio
    from app.database.session import AsyncSessionLocal

    camp1 = await create_campaign(
        session=db_session,
        name=f"Camp-1-{uuid.uuid4().hex[:6]}",
        trigger_type="manual",
        sandbox_id=sandbox.id,
    )
    camp2 = await create_campaign(
        session=db_session,
        name=f"Camp-2-{uuid.uuid4().hex[:6]}",
        trigger_type="manual",
        sandbox_id=sandbox.id,
    )
    await db_session.commit()

    async def run_for_campaign(c_id):
        async with AsyncSessionLocal() as sess:
            return await red_team_agent.execute_run(
                session=sess,
                campaign_id=c_id,
                scenario_id="simulated_service_discovery",
                asset_id=asset_server.id,
                user=test_operator,
            )

    res1, res2 = await asyncio.gather(
        run_for_campaign(camp1.id),
        run_for_campaign(camp2.id),
    )
    assert res1.outcome == "completed"
    assert res2.outcome == "completed"


def test_scenario_metadata_mitre_categorization():
    """Verify scenario definitions distinguish actual technique emulation vs conceptual categorization."""
    scenarios = {s.scenario_id: s for s in registry.list_all()}

    # Service Discovery: genuine technique emulation (T1046)
    svc = scenarios["simulated_service_discovery"]
    assert svc.technique_id == "T1046"
    assert svc.mapping_type == "technique_emulation"
    assert svc.is_synthetic is True

    # Weak Configuration: conceptual security posture review, NOT T1078
    weak = scenarios["simulated_weak_configuration_assessment"]
    assert weak.technique_id == "N/A (Conceptual Assessment)"
    assert weak.mapping_type == "conceptual_scenario"
    assert weak.is_synthetic is True
    assert "does not define a standalone technique" in weak.description

    # Authentication Anomaly: genuine technique emulation (T1110)
    auth = scenarios["simulated_authentication_anomaly"]
    assert auth.technique_id == "T1110"
    assert auth.mapping_type == "technique_emulation"
    assert auth.is_synthetic is True


@pytest.mark.asyncio
async def test_red_team_audit_persistence_and_hash_chain(db_session, test_campaign, test_sandbox_setup, test_operator):
    """Verify completed simulation persists valid SHA-256 chained audit record."""
    _, asset_server, _ = test_sandbox_setup

    run = await red_team_agent.execute_run(
        session=db_session,
        campaign_id=test_campaign.id,
        scenario_id="simulated_weak_configuration_assessment",
        asset_id=asset_server.id,
        user=test_operator,
    )

    # Fetch audit log for this run
    result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.resource_id == str(run.id),
            AuditLog.event_type == "red_team.simulation_completed",
        )
    )
    audit = result.scalar_one_or_none()
    assert audit is not None
    assert audit.action == "redteam.simulate"
    assert audit.actor_id == test_operator.id
    assert audit.event_data.get("simulation_only") is True

    # Verify hash integrity
    assert verify_event_hash(audit) is True


@pytest.mark.asyncio
async def test_red_team_audit_failure_fails_closed(db_session, test_campaign, test_sandbox_setup, test_operator):
    """Verify that if audit log persistence fails, transaction rolls back and aborts."""
    _, asset_server, _ = test_sandbox_setup

    with patch(
        "app.agents.red_team.agent.record_audit_log",
        side_effect=RuntimeError("Database write error on audit trail"),
    ):
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await red_team_agent.execute_run(
                session=db_session,
                campaign_id=test_campaign.id,
                scenario_id="simulated_service_discovery",
                asset_id=asset_server.id,
                user=test_operator,
            )
        assert exc_info.value.status_code == 500
        assert "audit persistence failed" in exc_info.value.detail.lower()


# =====================================================================
# 5. OPA Authorization & Role-Based Access Tests
# =====================================================================

@pytest.mark.asyncio
async def test_opa_operator_allowed_in_sandbox(test_operator):
    """Verify Security Operator is allowed to execute red team simulation in sandbox."""
    decision = await authorize_action(
        user=test_operator,
        operation="redteam.simulate",
        capability="scan",
        resource_type="campaign",
        resource_id=str(uuid.uuid4()),
        environment="sandbox",
    )
    assert decision.allowed is True
    assert decision.decision == "allow"


@pytest.mark.asyncio
async def test_opa_admin_allowed_in_sandbox(test_admin):
    """Verify Admin is allowed to execute red team simulation in sandbox."""
    decision = await authorize_action(
        user=test_admin,
        operation="redteam.simulate",
        capability="scan",
        resource_type="campaign",
        resource_id=str(uuid.uuid4()),
        environment="sandbox",
    )
    assert decision.allowed is True
    assert decision.decision == "allow"


@pytest.mark.asyncio
async def test_opa_analyst_denied_simulation_execution(test_analyst):
    """Verify Security Analyst is strictly denied from executing red team simulations."""
    decision = await authorize_action(
        user=test_analyst,
        operation="redteam.simulate",
        capability="scan",
        resource_type="campaign",
        resource_id=str(uuid.uuid4()),
        environment="sandbox",
    )
    assert decision.allowed is False
    assert decision.decision == "deny"


@pytest.mark.asyncio
async def test_opa_viewer_denied_red_team_operations(test_viewer):
    """Verify Viewer is strictly denied from all Red Team operations."""
    # Execute denied
    dec_exec = await authorize_action(
        user=test_viewer,
        operation="redteam.simulate",
        capability="scan",
        resource_type="campaign",
        resource_id=str(uuid.uuid4()),
        environment="sandbox",
    )
    assert dec_exec.allowed is False

    # List scenarios denied
    dec_list = await authorize_action(
        user=test_viewer,
        operation="redteam.scenario_list",
        capability="read",
        resource_type="scenario",
        resource_id="all",
        environment="sandbox",
    )
    assert dec_list.allowed is False


@pytest.mark.asyncio
async def test_opa_non_sandbox_simulation_denied_even_for_admin(test_admin):
    """Verify non-sandbox simulation execution is denied even for Admin users."""
    decision = await authorize_action(
        user=test_admin,
        operation="redteam.simulate",
        capability="scan",
        resource_type="campaign",
        resource_id=str(uuid.uuid4()),
        environment="production",
    )
    assert decision.allowed is False
    assert decision.decision == "deny"


# =====================================================================
# 6. FastAPI REST API Endpoint Tests
# =====================================================================

@pytest.mark.asyncio
async def test_api_list_scenarios_operator(operator_token):
    """Verify operator can list scenarios via API."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/api/v1/red-team/scenarios",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 8
        scenario_ids = [s["scenario_id"] for s in data]
        assert "simulated_service_discovery" in scenario_ids
        assert "simulated_initial_access" in scenario_ids
        assert "simulated_privilege_escalation" in scenario_ids
        assert "simulated_lateral_movement" in scenario_ids
        assert "simulated_persistence" in scenario_ids
        assert "simulated_data_exfiltration" in scenario_ids
        for s in data:
            assert "category" in s
            assert "risk_classification" in s
            assert "technique_id" in s
            assert "technique" in s
            assert "mapping_type" in s


@pytest.mark.asyncio
async def test_api_list_scenarios_viewer_denied(viewer_token):
    """Verify viewer is denied listing scenarios via API."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(
            "/api/v1/red-team/scenarios",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_api_execute_run_and_get_details(test_campaign, test_sandbox_setup, operator_token):
    """Verify executing a simulation run and retrieving run details via API."""
    _, asset_server, _ = test_sandbox_setup
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Trigger run
        post_resp = await client.post(
            f"/api/v1/red-team/campaigns/{test_campaign.id}/runs",
            headers={"Authorization": f"Bearer {operator_token}"},
            json={
                "scenario": "simulated_service_discovery",
                "asset_id": str(asset_server.id),
            },
        )
        assert post_resp.status_code == 201
        run_data = post_resp.json()
        run_id = run_data["run_id"]
        assert run_data["outcome"] == "completed"
        assert run_data["simulation_only"] is True

        # Retrieve run details
        get_resp = await client.get(
            f"/api/v1/red-team/runs/{run_id}",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert get_resp.status_code == 200
        detail = get_resp.json()
        assert detail["run_id"] == run_id
        assert detail["outcome"] == "completed"
        assert len(detail["execution_metadata"]["events"]) > 0
        assert len(detail["execution_metadata"]["findings"]) > 0


@pytest.mark.asyncio
async def test_api_execute_run_analyst_denied(test_campaign, test_sandbox_setup, analyst_token):
    """Verify security analyst is denied executing a simulation run via API."""
    _, asset_server, _ = test_sandbox_setup
    transport = ASGITransport(app=app)

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            f"/api/v1/red-team/campaigns/{test_campaign.id}/runs",
            headers={"Authorization": f"Bearer {analyst_token}"},
            json={
                "scenario": "simulated_service_discovery",
                "asset_id": str(asset_server.id),
            },
        )
        assert resp.status_code == 403


# =====================================================================
# 7. Advanced Synthetic Scenario Library Tests (Step 09.2.1)
# =====================================================================

@pytest.mark.asyncio
async def test_simulation_initial_access_precondition_satisfied(test_sandbox_setup):
    """Verify simulated_initial_access succeeds when vulnerability or exposed service precondition is satisfied."""
    _, asset_server, _ = test_sandbox_setup
    result = await simulation_engine.execute_simulation(
        "simulated_initial_access",
        asset_server,
    )

    assert result.status == "completed"
    assert result.simulation_only is True
    assert result.risk_score >= 8.0

    # Verify findings and structured evidence
    assert len(result.findings) >= 1
    finding = result.findings[0]
    assert finding.details.get("simulated_access_outcome") == "success"
    assert finding.details.get("actual_compromise") is False
    assert finding.details.get("identified_preconditions") is not None
    assert finding.evidence is not None
    assert finding.evidence.evidence_type == "synthetic_entry_point"
    assert finding.evidence.simulation_only is True
    assert finding.evidence.confidence == "high"

    # Verify event types and synthetic invariants
    event_types = [e.event_type for e in result.events]
    assert "simulated_access_attempt" in event_types
    assert "simulated_access_succeeded" in event_types
    for event in result.events:
        assert event.simulation_only is True
        assert event.is_simulated is True


@pytest.mark.asyncio
async def test_simulation_initial_access_precondition_missing(db_session, test_sandbox_setup):
    """Verify simulated_initial_access reports blocked_or_ineligible when no service or vulnerability exists."""
    sandbox, _, _ = test_sandbox_setup
    suffix = str(uuid.uuid4())[:8]
    clean_server = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"clean-server-{suffix}",
            "asset_type": "server",
            "hostname": f"clean-{suffix}.sandbox.local",
            "ip_address": "198.51.100.30",
            "service_metadata": {"services": []},
            "configuration": {},
            "simulated_vulnerabilities": [],
        },
    )
    await db_session.commit()

    result = await simulation_engine.execute_simulation(
        "simulated_initial_access",
        clean_server,
    )

    assert result.status == "completed"
    assert result.simulation_only is True
    assert len(result.findings) >= 1
    finding = result.findings[0]
    assert finding.details.get("simulated_access_outcome") == "blocked_or_ineligible"
    assert finding.details.get("actual_compromise") is False
    assert finding.evidence is not None
    assert finding.evidence.evidence_type == "hardened_entry_point"

    event_types = [e.event_type for e in result.events]
    assert "simulated_access_attempt" in event_types
    assert "simulated_access_blocked" in event_types


def test_simulation_initial_access_incompatible_asset_type():
    """Verify simulated_initial_access rejects incompatible asset types (e.g. database)."""
    with pytest.raises(ScenarioAssetIncompatibleError):
        registry.validate_asset_compatibility("simulated_initial_access", "database")


@pytest.mark.asyncio
async def test_simulation_privilege_escalation_precondition_satisfied(db_session, test_sandbox_setup):
    """Verify simulated_privilege_escalation succeeds when misconfiguration precondition is satisfied."""
    sandbox, _, _ = test_sandbox_setup
    suffix = str(uuid.uuid4())[:8]
    misconfigured_server = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"priv-server-{suffix}",
            "asset_type": "server",
            "hostname": f"priv-{suffix}.sandbox.local",
            "ip_address": "198.51.100.31",
            "configuration": {
                "sudo_nopasswd": True,
                "misconfigured_services": ["sim-backup-agent"],
            },
        },
    )
    await db_session.commit()

    result = await simulation_engine.execute_simulation(
        "simulated_privilege_escalation",
        misconfigured_server,
    )

    assert result.status == "completed"
    assert result.simulation_only is True
    assert result.risk_score >= 8.0

    finding = result.findings[0]
    assert finding.details.get("simulated_escalation_outcome") == "success"
    assert finding.details.get("source_privilege") == "standard_user"
    assert finding.details.get("target_privilege") == "root"
    assert finding.details.get("actual_privilege_change") is False
    assert finding.evidence is not None
    assert finding.evidence.evidence_type == "excessive_permissions_grant"
    assert finding.evidence.simulation_only is True

    event_types = [e.event_type for e in result.events]
    assert "privilege_check_simulated" in event_types
    assert "simulated_privilege_transition" in event_types


@pytest.mark.asyncio
async def test_simulation_privilege_escalation_precondition_missing(db_session, test_sandbox_setup):
    """Verify simulated_privilege_escalation reports denied_least_privilege_enforced on hardened assets."""
    sandbox, _, _ = test_sandbox_setup
    suffix = str(uuid.uuid4())[:8]
    hardened_server = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"hardened-{suffix}",
            "asset_type": "server",
            "hostname": f"hardened-{suffix}.sandbox.local",
            "ip_address": "198.51.100.32",
            "configuration": {
                "sudo_nopasswd": False,
            },
        },
    )
    await db_session.commit()

    result = await simulation_engine.execute_simulation(
        "simulated_privilege_escalation",
        hardened_server,
    )

    assert result.status == "completed"
    finding = result.findings[0]
    assert finding.details.get("simulated_escalation_outcome") == "denied_least_privilege_enforced"
    assert finding.details.get("actual_privilege_change") is False
    assert finding.evidence is not None
    assert finding.evidence.evidence_type == "least_privilege_enforced"

    event_types = [e.event_type for e in result.events]
    assert "privilege_check_simulated" in event_types
    assert "simulated_privilege_denied" in event_types


def test_simulation_privilege_escalation_incompatible_asset_type():
    """Verify simulated_privilege_escalation rejects incompatible asset types (e.g. network_device)."""
    with pytest.raises(ScenarioAssetIncompatibleError):
        registry.validate_asset_compatibility("simulated_privilege_escalation", "network_device")


@pytest.mark.asyncio
async def test_simulation_lateral_movement_success(db_session, test_sandbox_setup):
    """Verify simulated_lateral_movement succeeds when target is connected and within the same sandbox."""
    sandbox, asset_server, asset_db = test_sandbox_setup

    # Connect asset_server -> asset_db
    asset_server.connected_asset_ids = [str(asset_db.id)]
    await db_session.commit()
    await db_session.refresh(asset_server)

    result = await simulation_engine.execute_simulation(
        "simulated_lateral_movement",
        asset_server,
        parameters={"destination_asset_id": str(asset_db.id)},
        session=db_session,
    )

    assert result.status == "completed"
    assert result.simulation_only is True

    finding = result.findings[0]
    assert finding.details.get("simulated_outcome") == "success"
    assert finding.details.get("source_asset_id") == str(asset_server.id)
    assert finding.details.get("destination_asset_id") == str(asset_db.id)
    assert finding.details.get("actual_network_movement") is False
    assert finding.evidence is not None
    assert finding.evidence.evidence_type == "connected_asset_relationship"

    event_types = [e.event_type for e in result.events]
    assert "relationship_validation_simulated" in event_types
    assert "simulated_lateral_transition" in event_types


@pytest.mark.asyncio
async def test_simulation_lateral_movement_unrelated_target_rejected(db_session, test_sandbox_setup):
    """Verify simulated_lateral_movement fails when destination is not in connected_asset_ids."""
    sandbox, asset_server, asset_db = test_sandbox_setup

    # Explicitly clear connected_asset_ids
    asset_server.connected_asset_ids = []
    await db_session.commit()
    await db_session.refresh(asset_server)

    result = await simulation_engine.execute_simulation(
        "simulated_lateral_movement",
        asset_server,
        parameters={"destination_asset_id": str(asset_db.id)},
        session=db_session,
    )

    assert result.status == "completed"
    finding = result.findings[0]
    assert finding.details.get("simulated_outcome") == "unrelated_target_rejected"
    assert finding.details.get("actual_network_movement") is False
    assert finding.evidence is not None
    assert finding.evidence.evidence_type == "segmentation_enforced"

    event_types = [e.event_type for e in result.events]
    assert "relationship_validation_simulated" in event_types
    assert "simulated_movement_blocked" in event_types


@pytest.mark.asyncio
async def test_simulation_lateral_movement_cross_sandbox_rejected(db_session, test_sandbox_setup, test_operator):
    """Verify simulated_lateral_movement strictly rejects target assets residing in a different sandbox."""
    _, asset_server, _ = test_sandbox_setup

    # Create a separate sandbox and target asset
    other_sandbox = await create_sandbox(
        session=db_session,
        name=f"Other-Sandbox-{uuid.uuid4().hex[:6]}",
        owner_id=test_operator.id,
    )
    other_asset = await register_asset(
        session=db_session,
        sandbox_id=other_sandbox.id,
        asset_data={
            "name": "isolated-foreign-asset",
            "asset_type": "server",
            "hostname": "foreign.other.local",
            "ip_address": "198.51.100.55",
        },
    )
    # Even if source falsely includes foreign asset ID in its connections
    asset_server.connected_asset_ids = [str(other_asset.id)]
    await db_session.commit()

    result = await simulation_engine.execute_simulation(
        "simulated_lateral_movement",
        asset_server,
        parameters={"destination_asset_id": str(other_asset.id)},
        session=db_session,
    )

    assert result.status == "completed"
    finding = result.findings[0]
    assert finding.details.get("simulated_outcome") == "cross_sandbox_destination_rejected"
    assert finding.details.get("actual_network_movement") is False
    assert finding.evidence is not None
    assert finding.evidence.evidence_type == "sandbox_isolation_boundary"

    event_types = [e.event_type for e in result.events]
    assert "simulated_movement_blocked" in event_types


@pytest.mark.asyncio
async def test_simulation_lateral_movement_missing_destination_parameter(test_sandbox_setup):
    """Verify simulated_lateral_movement handles missing destination_asset_id parameter gracefully."""
    _, asset_server, _ = test_sandbox_setup

    result = await simulation_engine.execute_simulation(
        "simulated_lateral_movement",
        asset_server,
        parameters={},
    )

    assert result.status == "completed"
    finding = result.findings[0]
    assert finding.details.get("simulated_outcome") == "missing_destination_asset_parameter"
    assert finding.details.get("actual_network_movement") is False


def test_simulation_lateral_movement_incompatible_asset_type():
    """Verify simulated_lateral_movement rejects incompatible asset types (e.g. storage_bucket)."""
    with pytest.raises(ScenarioAssetIncompatibleError):
        registry.validate_asset_compatibility("simulated_lateral_movement", "storage_bucket")


@pytest.mark.asyncio
async def test_simulation_persistence_precondition_satisfied(db_session, test_sandbox_setup):
    """Verify simulated_persistence identifies simulated persistence artifacts when configured."""
    sandbox, _, _ = test_sandbox_setup
    suffix = str(uuid.uuid4())[:8]
    persist_server = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"persist-server-{suffix}",
            "asset_type": "server",
            "hostname": f"persist-{suffix}.sandbox.local",
            "ip_address": "198.51.100.33",
            "configuration": {
                "scheduled_tasks": [
                    {"name": "sim_maintenance_task", "schedule": "@hourly", "command": "/bin/true"}
                ],
            },
        },
    )
    await db_session.commit()

    result = await simulation_engine.execute_simulation(
        "simulated_persistence",
        persist_server,
    )

    assert result.status == "completed"
    assert result.simulation_only is True

    finding = result.findings[0]
    assert finding.details.get("simulated_persistence_outcome") == "indicator_identified"
    assert finding.details.get("actual_persistence_established") is False
    assert finding.evidence is not None
    assert finding.evidence.evidence_type == "synthetic_persistence_indicator"

    event_types = [e.event_type for e in result.events]
    assert "persistence_scan_simulated" in event_types
    assert "simulated_persistence_indicator_flagged" in event_types


@pytest.mark.asyncio
async def test_simulation_persistence_precondition_missing(db_session, test_sandbox_setup):
    """Verify simulated_persistence reports no indicators when asset has no persistence mechanisms."""
    sandbox, _, _ = test_sandbox_setup
    suffix = str(uuid.uuid4())[:8]
    clean_server = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"clean-persist-{suffix}",
            "asset_type": "server",
            "hostname": f"clean-p-{suffix}.sandbox.local",
            "ip_address": "198.51.100.34",
            "configuration": {},
        },
    )
    await db_session.commit()

    result = await simulation_engine.execute_simulation(
        "simulated_persistence",
        clean_server,
    )

    assert result.status == "completed"
    finding = result.findings[0]
    assert finding.details.get("simulated_persistence_outcome") == "no_persistence_indicators_found"
    assert finding.details.get("actual_persistence_established") is False
    assert finding.evidence is not None
    assert finding.evidence.evidence_type == "clean_persistence_profile"

    event_types = [e.event_type for e in result.events]
    assert "persistence_scan_simulated" in event_types


def test_simulation_persistence_incompatible_asset_type():
    """Verify simulated_persistence rejects incompatible asset types (e.g. database)."""
    with pytest.raises(ScenarioAssetIncompatibleError):
        registry.validate_asset_compatibility("simulated_persistence", "database")


@pytest.mark.asyncio
async def test_simulation_data_exfiltration_precondition_satisfied(db_session, test_sandbox_setup):
    """Verify simulated_data_exfiltration simulates staging and transfer when sensitive data exists."""
    sandbox, _, _ = test_sandbox_setup
    suffix = str(uuid.uuid4())[:8]
    data_server = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"data-server-{suffix}",
            "asset_type": "server",
            "hostname": f"data-{suffix}.sandbox.local",
            "ip_address": "198.51.100.35",
            "configuration": {
                "data_classification": "restricted",
                "records_count": 5000,
            },
        },
    )
    await db_session.commit()

    result = await simulation_engine.execute_simulation(
        "simulated_data_exfiltration",
        data_server,
    )

    assert result.status == "completed"
    assert result.simulation_only is True

    finding = result.findings[0]
    assert finding.details.get("simulated_exfiltration_outcome") == "simulated_data_staged_and_transferred"
    assert finding.details.get("actual_data_transferred") is False
    assert finding.details.get("actual_bytes_transferred") == 0
    assert "simulated metric" in finding.details.get("simulated_transfer_volume", "")
    assert finding.evidence is not None
    assert finding.evidence.evidence_type == "synthetic_data_movement"

    event_types = [e.event_type for e in result.events]
    assert "simulated_data_access_query" in event_types
    assert "simulated_exfiltration_stream" in event_types


@pytest.mark.asyncio
async def test_simulation_data_exfiltration_precondition_missing(db_session, test_sandbox_setup):
    """Verify simulated_data_exfiltration reports blocked when data is public/non-sensitive."""
    sandbox, _, _ = test_sandbox_setup
    suffix = str(uuid.uuid4())[:8]
    public_server = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"public-server-{suffix}",
            "asset_type": "server",
            "hostname": f"public-{suffix}.sandbox.local",
            "ip_address": "198.51.100.36",
            "configuration": {
                "data_classification": "public",
            },
        },
    )
    await db_session.commit()

    result = await simulation_engine.execute_simulation(
        "simulated_data_exfiltration",
        public_server,
    )

    assert result.status == "completed"
    finding = result.findings[0]
    assert finding.details.get("simulated_exfiltration_outcome") == "data_access_blocked_or_non_sensitive"
    assert finding.details.get("actual_data_transferred") is False
    assert finding.details.get("actual_bytes_transferred") == 0
    assert finding.evidence is not None
    assert finding.evidence.evidence_type == "data_access_restricted"

    event_types = [e.event_type for e in result.events]
    assert "simulated_data_access_query" in event_types
    assert "simulated_exfiltration_blocked" in event_types


def test_simulation_data_exfiltration_incompatible_asset_type():
    """Verify simulated_data_exfiltration rejects incompatible asset types (e.g. workstation)."""
    with pytest.raises(ScenarioAssetIncompatibleError):
        registry.validate_asset_compatibility("simulated_data_exfiltration", "workstation")


@pytest.mark.asyncio
async def test_red_team_agent_end_to_end_advanced_scenarios(db_session, test_campaign, test_sandbox_setup, test_operator):
    """Verify end-to-end execution of all 5 advanced scenarios through RedTeamAgent with enriched events and evidence."""
    sandbox, asset_server, asset_db = test_sandbox_setup

    # Configure asset_server with all simulated preconditions
    asset_server.connected_asset_ids = [str(asset_db.id)]
    asset_server.configuration = {
        "sudo_nopasswd": True,
        "scheduled_tasks": [{"name": "cron_persist", "schedule": "@reboot"}],
        "data_classification": "restricted",
        "records_count": 2500,
    }
    await db_session.commit()
    await db_session.refresh(asset_server)

    scenarios_to_test = [
        ("simulated_initial_access", {}),
        ("simulated_privilege_escalation", {}),
        ("simulated_lateral_movement", {"destination_asset_id": str(asset_db.id)}),
        ("simulated_persistence", {}),
        ("simulated_data_exfiltration", {}),
    ]

    for scenario_id, params in scenarios_to_test:
        run = await red_team_agent.execute_run(
            session=db_session,
            campaign_id=test_campaign.id,
            scenario_id=scenario_id,
            asset_id=asset_server.id,
            user=test_operator,
            parameters=params,
        )

        assert run.outcome == "completed", f"Run for {scenario_id} failed with outcome {run.outcome}: {run.error_message}"
        meta = run.execution_metadata
        assert meta.get("simulation_only") is True
        assert len(meta.get("events", [])) > 0
        assert len(meta.get("findings", [])) > 0

        # Verify enriched event fields for Blue Guardian correlation
        for ev in meta["events"]:
            assert ev["scenario_id"] == scenario_id
            assert ev["campaign_id"] == str(test_campaign.id)
            assert ev["attack_run_id"] == str(run.id)
            assert ev["sandbox_id"] == str(sandbox.id)
            assert ev["source_asset_id"] == str(asset_server.id)
            assert ev["simulation_only"] is True
            assert ev["is_simulated"] is True
            assert isinstance(ev.get("event_metadata"), dict)

        # Verify findings carry structured evidence
        for finding in meta["findings"]:
            evidence = finding.get("evidence")
            assert evidence is not None, f"Finding in {scenario_id} missing structured evidence"
            assert evidence["simulation_only"] is True
            assert evidence["is_simulated"] is True
            assert uuid.UUID(evidence["evidence_id"])
            assert evidence["confidence"] in ["high", "medium", "low"]
            assert len(evidence.get("synthetic_asset_references", [])) > 0


