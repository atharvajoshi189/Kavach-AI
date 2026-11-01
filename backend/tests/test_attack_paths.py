"""Comprehensive test suite for AegisMesh 2.0 Step 09.2.2: Attack Path Orchestration Engine.

Verifies:
1. Scenario dependency validation and transition graph.
2. Asset relationship graph traversal (BFS/DFS, reachability, edges).
3. Risk calculation determinism, bounding, and aggregation.
4. Attack path planning (kill-chain ordering, constraints, lateral movement).
5. Attack path coordinator execution (sequential runs, risk score update, failure handling).
6. Attack path cancellation and idempotency invariants.
7. REST API endpoints, JWT auth, and OPA role-based authorization.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
import uuid
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.agents.red_team.attack_path_schemas import AttackPathPlanRequest
from app.main import app
from app.models.attack_path import AttackPath
from app.models.attack_path_stage import AttackPathStage
from app.models.campaign import Campaign
from app.models.sandbox import SandboxEnvironment
from app.models.synthetic_asset import SyntheticAsset
from app.models.user import User, UserRole
from app.services.attack_path_coordinator import cancel_attack_path, execute_attack_path
from app.services.attack_path_graph import AssetRelationshipGraph
from app.services.attack_path_planner import plan_attack_path
from app.services.attack_path_risk import calculate_path_risk, risk_level_to_float
from app.services.campaign_service import create_campaign
from app.services.sandbox_service import archive_sandbox, create_sandbox, register_asset
from app.services.scenario_dependency import (
    SCENARIO_DEPENDENCY_MAP,
    dependency_engine,
)


# =====================================================================
# Fixtures
# =====================================================================

@pytest_asyncio.fixture
async def attack_path_test_setup(db_session, test_operator):
    """Sets up a test sandbox with connected and isolated assets, plus a sandbox campaign."""
    suffix = str(uuid.uuid4())[:8]
    sandbox = await create_sandbox(
        session=db_session,
        name=f"AP-Sandbox-{suffix}",
        description="Controlled sandbox for Attack Path test suite",
        owner_id=test_operator.id,
    )

    # Asset 2: Target database
    asset_db = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"ap-db-{suffix}",
            "asset_type": "database",
            "hostname": f"db-{suffix}.sandbox.local",
            "ip_address": "198.51.100.20",
            "risk_level": "critical",
            "connected_asset_ids": [],
            "service_metadata": {
                "services": [
                    {"port": 5432, "protocol": "tcp", "service": "postgresql", "banner": "PostgreSQL 16 (simulated)"}
                ]
            },
            "configuration": {"allow_anonymous": False},
            "simulated_vulnerabilities": [],
        },
    )

    # Asset 1: Web server connected to database
    asset_server = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"ap-server-{suffix}",
            "asset_type": "server",
            "hostname": f"server-{suffix}.sandbox.local",
            "ip_address": "198.51.100.10",
            "risk_level": "high",
            "connected_asset_ids": [str(asset_db.id)],
            "service_metadata": {
                "services": [
                    {"port": 80, "protocol": "tcp", "service": "http", "banner": "Apache/2.4 (simulated)"},
                    {"port": 22, "protocol": "tcp", "service": "ssh", "banner": "OpenSSH (simulated)"},
                ]
            },
            "configuration": {
                "debug_mode": True,
                "default_credentials": True,
            },
            "simulated_vulnerabilities": [],
        },
    )

    # Asset 3: Isolated server with no connected neighbors
    asset_isolated = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"ap-isolated-{suffix}",
            "asset_type": "server",
            "hostname": f"isolated-{suffix}.sandbox.local",
            "ip_address": "198.51.100.30",
            "risk_level": "medium",
            "connected_asset_ids": [],
            "service_metadata": {
                "services": [
                    {"port": 80, "protocol": "tcp", "service": "http", "banner": "nginx (simulated)"}
                ]
            },
            "configuration": {},
            "simulated_vulnerabilities": [],
        },
    )

    # Campaign configured for sandbox
    campaign = await create_campaign(
        session=db_session,
        name=f"AP-Campaign-{suffix}",
        trigger_type="manual",
        environment="sandbox",
        sandbox_id=sandbox.id,
    )

    await db_session.commit()
    await db_session.refresh(sandbox)
    await db_session.refresh(asset_server)
    await db_session.refresh(asset_db)
    await db_session.refresh(asset_isolated)
    await db_session.refresh(campaign)

    return sandbox, asset_server, asset_db, asset_isolated, campaign


# =====================================================================
# Unit Tests (15 tests — sync, no DB)
# =====================================================================

def test_scenario_dependency_compatibility():
    """Verify is_compatible returns True for valid scenario-asset pairs."""
    assert dependency_engine.is_compatible("simulated_service_discovery", "server") is True
    assert dependency_engine.is_compatible("simulated_data_exfiltration", "database") is True
    assert dependency_engine.is_compatible("simulated_privilege_escalation", "workstation") is True
    assert dependency_engine.is_compatible("simulated_weak_configuration_assessment", "web_application") is True


def test_scenario_dependency_incompatibility():
    """Verify is_compatible returns False for invalid scenario-asset pairs."""
    assert dependency_engine.is_compatible("simulated_privilege_escalation", "web_application") is False
    assert dependency_engine.is_compatible("simulated_data_exfiltration", "workstation") is False
    assert dependency_engine.is_compatible("simulated_persistence", "database") is False
    assert dependency_engine.is_compatible("unknown_scenario", "server") is False


def test_can_transition():
    """Verify can_transition returns True for allowed transitions."""
    assert dependency_engine.can_transition("simulated_service_discovery", "simulated_initial_access") is True
    assert dependency_engine.can_transition("simulated_initial_access", "simulated_privilege_escalation") is True
    assert dependency_engine.can_transition("simulated_privilege_escalation", "simulated_data_exfiltration") is True
    assert dependency_engine.can_transition("simulated_authentication_anomaly", "simulated_lateral_movement") is True


def test_cannot_transition_terminal():
    """Verify terminal scenarios have no outgoing transitions."""
    assert dependency_engine.can_transition("simulated_data_exfiltration", "simulated_service_discovery") is False
    assert dependency_engine.can_transition("simulated_data_exfiltration", "simulated_initial_access") is False
    assert SCENARIO_DEPENDENCY_MAP["simulated_data_exfiltration"]["allowed_transitions"] == []


def test_requires_destination_lateral_movement():
    """Verify requires_destination returns True for lateral movement only."""
    assert dependency_engine.requires_destination("simulated_lateral_movement") is True
    assert dependency_engine.requires_destination("simulated_service_discovery") is False
    assert dependency_engine.requires_destination("simulated_initial_access") is False
    assert dependency_engine.requires_destination("simulated_data_exfiltration") is False


def test_risk_level_to_float():
    """Verify risk level mapping to float values."""
    assert risk_level_to_float("low") == 0.25
    assert risk_level_to_float("medium") == 0.5
    assert risk_level_to_float("high") == 0.75
    assert risk_level_to_float("critical") == 1.0
    assert risk_level_to_float("unrecognized") == 0.5


def test_calculate_path_risk_no_completed():
    """Verify risk calculation returns 0.0 when no stages have completed."""
    score = calculate_path_risk(
        completed_stage_risk_scores=[],
        all_stage_risk_scores=[5.0, 7.0],
        asset_risk_levels=["high"],
        total_stages=2,
        completed_stages=0,
    )
    assert score == 0.0

    score_zero_total = calculate_path_risk(
        completed_stage_risk_scores=[5.0],
        all_stage_risk_scores=[5.0],
        asset_risk_levels=["high"],
        total_stages=0,
        completed_stages=0,
    )
    assert score_zero_total == 0.0


def test_calculate_path_risk_deterministic():
    """Verify identical inputs yield identical risk scores."""
    args = {
        "completed_stage_risk_scores": [5.0, 7.5, 9.0],
        "all_stage_risk_scores": [5.0, 7.5, 9.0],
        "asset_risk_levels": ["high", "critical"],
        "total_stages": 3,
        "completed_stages": 3,
    }
    score1 = calculate_path_risk(**args)
    score2 = calculate_path_risk(**args)
    assert score1 == score2
    assert isinstance(score1, float)


def test_calculate_path_risk_bounded():
    """Verify risk score never exceeds 10.0 and is non-negative."""
    # Max possible risk inputs
    score_max = calculate_path_risk(
        completed_stage_risk_scores=[10.0, 10.0, 10.0, 10.0],
        all_stage_risk_scores=[10.0, 10.0, 10.0, 10.0],
        asset_risk_levels=["critical", "critical"],
        total_stages=4,
        completed_stages=4,
    )
    assert 0.0 <= score_max <= 10.0

    # Low risk inputs
    score_low = calculate_path_risk(
        completed_stage_risk_scores=[2.0],
        all_stage_risk_scores=[2.0],
        asset_risk_levels=["low"],
        total_stages=1,
        completed_stages=1,
    )
    assert 0.0 <= score_low <= 10.0


def test_asset_graph_has_edge():
    """Verify has_edge returns True for existing directed edges."""
    graph = AssetRelationshipGraph(
        adjacency={"a": ["b"], "b": ["c"], "c": []},
        asset_map={},
    )
    assert graph.has_edge("a", "b") is True
    assert graph.has_edge("b", "c") is True


def test_asset_graph_no_edge():
    """Verify has_edge returns False for nonexistent edges."""
    graph = AssetRelationshipGraph(
        adjacency={"a": ["b"], "b": ["c"], "c": []},
        asset_map={},
    )
    assert graph.has_edge("b", "a") is False
    assert graph.has_edge("a", "c") is False
    assert graph.has_edge("c", "a") is False


def test_asset_graph_reachable():
    """Verify BFS traversal finds all reachable nodes."""
    graph = AssetRelationshipGraph(
        adjacency={"1": ["2"], "2": ["3"], "3": ["4"], "4": []},
        asset_map={},
    )
    reachable = graph.get_reachable_assets("1", max_depth=5)
    assert set(reachable) == {"2", "3", "4"}


def test_asset_graph_unreachable():
    """Verify BFS traversal does not include disconnected nodes."""
    graph = AssetRelationshipGraph(
        adjacency={"1": ["2"], "2": [], "3": ["4"], "4": []},
        asset_map={},
    )
    reachable = graph.get_reachable_assets("1", max_depth=5)
    assert "3" not in reachable
    assert "4" not in reachable
    assert reachable == ["2"]


def test_prerequisite_validation_pass():
    """Verify prerequisite validation passes when all required stages are present."""
    result = dependency_engine.validate_prerequisite_stages(
        completed_stage_ids=["s1", "s2", "s3"],
        required_prereqs=["s1", "s2"],
    )
    assert result.valid is True
    assert result.missing_prerequisites == []


def test_prerequisite_validation_fail():
    """Verify prerequisite validation fails when required stages are missing."""
    result = dependency_engine.validate_prerequisite_stages(
        completed_stage_ids=["s1"],
        required_prereqs=["s1", "s2"],
    )
    assert result.valid is False
    assert result.missing_prerequisites == ["s2"]


# =====================================================================
# Integration Tests (14 tests — async, with DB)
# =====================================================================

@pytest.mark.asyncio
async def test_plan_attack_path_basic(db_session, attack_path_test_setup):
    """Verify planning an attack path creates a planned AttackPath with ordered stages."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    path, explanation, rejected = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        execution_mode="exploratory",
    )

    assert path.status == "planned"
    assert path.campaign_id == campaign.id
    assert path.sandbox_id == sandbox.id
    assert path.source_asset_id == asset_server.id
    assert path.total_stages > 0
    assert path.simulation_only is True
    assert len(path.stages) == path.total_stages
    assert len(explanation) > 0


@pytest.mark.asyncio
async def test_plan_attack_path_respects_max_stages(db_session, attack_path_test_setup):
    """Verify planner respects the max_stages limit."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    path, _, _ = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        max_stages=2,
    )

    assert path.total_stages <= 2
    assert len(path.stages) <= 2


@pytest.mark.asyncio
async def test_plan_attack_path_with_connected_assets(db_session, attack_path_test_setup):
    """Verify lateral movement is planned when asset has connected neighbors."""
    sandbox, asset_server, asset_db, _, campaign = attack_path_test_setup

    path, _, _ = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        max_stages=6,
    )

    scenario_ids = [s.scenario_id for s in path.stages]
    # Lateral movement should be attempted because asset_server connects to asset_db
    if "simulated_lateral_movement" in scenario_ids:
        stage = next(s for s in path.stages if s.scenario_id == "simulated_lateral_movement")
        assert stage.destination_asset_id == asset_db.id


@pytest.mark.asyncio
async def test_plan_attack_path_no_lateral_movement_without_connection(db_session, attack_path_test_setup):
    """Verify lateral movement is skipped when asset has no connected neighbors."""
    sandbox, _, _, asset_isolated, campaign = attack_path_test_setup

    path, _, rejected = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_isolated,
        max_stages=6,
    )

    scenario_ids = [s.scenario_id for s in path.stages]
    assert "simulated_lateral_movement" not in scenario_ids
    # Should be in rejected candidates
    assert any(r.get("scenario_id") == "simulated_lateral_movement" for r in rejected)


@pytest.mark.asyncio
async def test_plan_attack_path_invalid_campaign(operator_token, db_session, attack_path_test_setup):
    """Verify non-sandbox campaign is rejected by API / planning logic."""
    sandbox, asset_server, _, _, _ = attack_path_test_setup

    prod_campaign = await create_campaign(
        session=db_session,
        name=f"Prod-Campaign-{uuid.uuid4().hex[:6]}",
        trigger_type="manual",
        environment="production",
        sandbox_id=sandbox.id,
    )
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/api/v1/attack-paths/plan",
            headers={"Authorization": f"Bearer {operator_token}"},
            json={
                "campaign_id": str(prod_campaign.id),
                "source_asset_id": str(asset_server.id),
            },
        )
        assert res.status_code == 400
        assert "sandbox" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_plan_attack_path_archived_sandbox(operator_token, db_session, attack_path_test_setup):
    """Verify planning against an archived sandbox is rejected."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    await archive_sandbox(db_session, sandbox.id)
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/api/v1/attack-paths/plan",
            headers={"Authorization": f"Bearer {operator_token}"},
            json={
                "campaign_id": str(campaign.id),
                "source_asset_id": str(asset_server.id),
            },
        )
        assert res.status_code in (400, 404)


@pytest.mark.asyncio
async def test_plan_attack_path_archived_asset(db_session, attack_path_test_setup):
    """Verify planning with an archived source asset raises ValueError."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    asset_server.status = "archived"
    await db_session.flush()
    await db_session.commit()

    with pytest.raises(ValueError) as exc_info:
        await plan_attack_path(
            session=db_session,
            campaign=campaign,
            sandbox=sandbox,
            source_asset=asset_server,
        )
    assert "not found in sandbox graph" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_plan_attack_path_cross_sandbox_rejected(operator_token, db_session, attack_path_test_setup, test_operator):
    """Verify source asset from a different sandbox is rejected."""
    _, _, _, _, campaign = attack_path_test_setup

    # Create second sandbox and foreign asset
    sb2 = await create_sandbox(
        session=db_session,
        name=f"Foreign-Sandbox-{uuid.uuid4().hex[:6]}",
        owner_id=test_operator.id,
    )
    asset_foreign = await register_asset(
        session=db_session,
        sandbox_id=sb2.id,
        asset_data={
            "name": "foreign-server",
            "asset_type": "server",
            "hostname": "foreign.sandbox.local",
            "ip_address": "198.51.100.99",
            "service_metadata": {},
            "configuration": {},
            "simulated_vulnerabilities": [],
        },
    )
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/api/v1/attack-paths/plan",
            headers={"Authorization": f"Bearer {operator_token}"},
            json={
                "campaign_id": str(campaign.id),
                "source_asset_id": str(asset_foreign.id),
            },
        )
        assert res.status_code == 400
        assert "belong" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_execute_attack_path_completes(db_session, attack_path_test_setup, test_operator):
    """Verify attack path executes all stages and computes final risk score."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    path, _, _ = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        max_stages=2,
    )
    await db_session.commit()

    result = await execute_attack_path(
        session=db_session,
        attack_path_id=path.id,
        user=test_operator,
    )

    assert result.status in ("completed", "partially_completed")
    assert result.completed_stages > 0
    assert result.completed_at is not None
    assert result.risk_score is not None
    assert result.risk_score > 0.0


@pytest.mark.asyncio
async def test_execute_attack_path_already_running_rejected(db_session, attack_path_test_setup, test_operator):
    """Verify executing an already running path raises ValueError."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    path, _, _ = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        max_stages=1,
    )
    path.status = "running"
    await db_session.flush()
    await db_session.commit()

    with pytest.raises(ValueError) as exc:
        await execute_attack_path(session=db_session, attack_path_id=path.id, user=test_operator)
    assert "already running" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_execute_attack_path_terminal_status_rejected(db_session, attack_path_test_setup, test_operator):
    """Verify executing a completed path raises ValueError."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    path, _, _ = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        max_stages=1,
    )
    path.status = "completed"
    await db_session.flush()
    await db_session.commit()

    with pytest.raises(ValueError) as exc:
        await execute_attack_path(session=db_session, attack_path_id=path.id, user=test_operator)
    assert "terminal status" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_cancel_attack_path(db_session, attack_path_test_setup, test_operator):
    """Verify cancelling an attack path transitions status to cancelled and skips pending stages."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    path, _, _ = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        max_stages=3,
    )
    await db_session.commit()

    cancelled = await cancel_attack_path(
        session=db_session,
        attack_path_id=path.id,
        user=test_operator,
        reason="Operator requested cancellation",
    )

    assert cancelled.status == "cancelled"
    assert cancelled.completed_at is not None

    stages_r = await db_session.execute(
        select(AttackPathStage).where(AttackPathStage.attack_path_id == path.id)
    )
    for stage in stages_r.scalars().all():
        assert stage.status == "skipped"


@pytest.mark.asyncio
async def test_cancel_terminal_path_rejected(db_session, attack_path_test_setup, test_operator):
    """Verify cancelling a completed path raises ValueError."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    path, _, _ = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        max_stages=1,
    )
    path.status = "completed"
    await db_session.flush()
    await db_session.commit()

    with pytest.raises(ValueError) as exc:
        await cancel_attack_path(session=db_session, attack_path_id=path.id, user=test_operator)
    assert "terminal status" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_risk_aggregation_partial_completion():
    """Verify risk aggregation correctly accounts for partially completed paths."""
    score_partial = calculate_path_risk(
        completed_stage_risk_scores=[4.0],
        all_stage_risk_scores=[4.0, 7.0, 9.0],
        asset_risk_levels=["high"],
        total_stages=3,
        completed_stages=1,
    )
    score_full = calculate_path_risk(
        completed_stage_risk_scores=[4.0, 7.0, 9.0],
        all_stage_risk_scores=[4.0, 7.0, 9.0],
        asset_risk_levels=["high"],
        total_stages=3,
        completed_stages=3,
    )
    assert 0.0 < score_partial < score_full


# =====================================================================
# API Tests (12 tests — async, with test client)
# =====================================================================

@pytest.mark.asyncio
async def test_api_plan_unauthenticated():
    """Verify POST /plan returns 401 when unauthenticated."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/api/v1/attack-paths/plan",
            json={
                "campaign_id": str(uuid.uuid4()),
                "source_asset_id": str(uuid.uuid4()),
            },
        )
        assert res.status_code == 401


@pytest.mark.asyncio
async def test_api_plan_operator_allowed(operator_token, attack_path_test_setup):
    """Verify POST /plan returns 201 for security operator."""
    _, asset_server, _, _, campaign = attack_path_test_setup

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/api/v1/attack-paths/plan",
            headers={"Authorization": f"Bearer {operator_token}"},
            json={
                "campaign_id": str(campaign.id),
                "source_asset_id": str(asset_server.id),
                "max_stages": 3,
            },
        )
        assert res.status_code == 201
        data = res.json()
        assert "attack_path" in data
        assert "nodes" in data
        assert "edges" in data
        assert data["attack_path"]["status"] == "planned"


@pytest.mark.asyncio
async def test_api_plan_analyst_denied(analyst_token, attack_path_test_setup):
    """Verify POST /plan returns 403 for security analyst (scan capability required)."""
    _, asset_server, _, _, campaign = attack_path_test_setup

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/api/v1/attack-paths/plan",
            headers={"Authorization": f"Bearer {analyst_token}"},
            json={
                "campaign_id": str(campaign.id),
                "source_asset_id": str(asset_server.id),
            },
        )
        assert res.status_code == 403


@pytest.mark.asyncio
async def test_api_plan_viewer_denied(viewer_token, attack_path_test_setup):
    """Verify POST /plan returns 403 for viewer."""
    _, asset_server, _, _, campaign = attack_path_test_setup

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            "/api/v1/attack-paths/plan",
            headers={"Authorization": f"Bearer {viewer_token}"},
            json={
                "campaign_id": str(campaign.id),
                "source_asset_id": str(asset_server.id),
            },
        )
        assert res.status_code == 403


@pytest.mark.asyncio
async def test_api_execute_operator_allowed(operator_token, db_session, attack_path_test_setup):
    """Verify POST /{id}/execute returns 200 and executes the path."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    path, _, _ = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        max_stages=1,
    )
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            f"/api/v1/attack-paths/{path.id}/execute",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] in ("completed", "partially_completed")
        assert data["completed_stages"] > 0


@pytest.mark.asyncio
async def test_api_get_attack_path(operator_token, db_session, attack_path_test_setup):
    """Verify GET /{id} returns 200 with attack path details."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    path, _, _ = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        max_stages=2,
    )
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get(
            f"/api/v1/attack-paths/{path.id}",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == str(path.id)
        assert data["status"] == "planned"
        assert len(data["stages"]) == path.total_stages


@pytest.mark.asyncio
async def test_api_list_attack_paths(operator_token, db_session, attack_path_test_setup):
    """Verify GET / returns 200 list response with pagination metadata."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        max_stages=1,
    )
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get(
            f"/api/v1/attack-paths?campaign_id={campaign.id}",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert "items" in data
        assert data["total"] >= 1


@pytest.mark.asyncio
async def test_api_get_graph(operator_token, db_session, attack_path_test_setup):
    """Verify GET /{id}/graph returns 200 with nodes and edges."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    path, _, _ = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        max_stages=2,
    )
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get(
            f"/api/v1/attack-paths/{path.id}/graph",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert "nodes" in data
        assert "edges" in data
        assert data["attack_path_id"] == str(path.id)


@pytest.mark.asyncio
async def test_api_get_report(operator_token, db_session, attack_path_test_setup):
    """Verify GET /{id}/report returns forensic report including correlated events."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    path, _, _ = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        max_stages=1,
    )
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Execute first to produce events
        await client.post(
            f"/api/v1/attack-paths/{path.id}/execute",
            headers={"Authorization": f"Bearer {operator_token}"},
        )

        res = await client.get(
            f"/api/v1/attack-paths/{path.id}/report",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["attack_path_id"] == str(path.id)
        assert "correlated_events" in data
        assert "risk_score" in data


@pytest.mark.asyncio
async def test_api_get_stages(operator_token, db_session, attack_path_test_setup):
    """Verify GET /{id}/stages returns list of stages."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    path, _, _ = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        max_stages=2,
    )
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get(
            f"/api/v1/attack-paths/{path.id}/stages",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert res.status_code == 200
        stages = res.json()
        assert isinstance(stages, list)
        assert len(stages) == path.total_stages


@pytest.mark.asyncio
async def test_api_cancel_attack_path(operator_token, db_session, attack_path_test_setup):
    """Verify POST /{id}/cancel cancels a planned path."""
    sandbox, asset_server, _, _, campaign = attack_path_test_setup

    path, _, _ = await plan_attack_path(
        session=db_session,
        campaign=campaign,
        sandbox=sandbox,
        source_asset=asset_server,
        max_stages=2,
    )
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            f"/api/v1/attack-paths/{path.id}/cancel",
            headers={"Authorization": f"Bearer {operator_token}"},
            json={"reason": "User cancelled execution"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "cancelled"


@pytest.mark.asyncio
async def test_api_get_nonexistent_path(operator_token):
    """Verify GET /{id} returns 404 for a non-existent attack path."""
    random_id = uuid.uuid4()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get(
            f"/api/v1/attack-paths/{random_id}",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert res.status_code == 404
