"""Comprehensive Test Suite for AegisMesh 2.0 Step 09.2.3.2:
Blue Guardian Runtime — Defensive Event Ingestion & Deterministic Correlation Engine.

Verifies:
1. Pydantic v2 schemas, immutability, and 'extra=forbid' constraints.
2. Ingestion of valid synthetic security events and provenance retention.
3. Rejection of non-synthetic events and missing simulation flags.
4. Sandbox boundary isolation and cross-sandbox telemetry rejection.
5. Ingestion idempotency, deduplication, and database uniqueness.
6. Deterministic correlation rules across DIRECT, RELATIONAL, and TEMPORAL dimensions.
7. Stable sorting, deterministic group IDs (UUIDv5), and tie-breaking.
8. Source evidence immutability (original AttackRun and events never modified).
9. OPA role-based access control and sandbox ownership authorization.
10. REST API endpoints under /api/v1/guardian/*.
11. SHA-256 chained audit log emission across the execution lifecycle.
12. Celery background task execution.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import uuid
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.agents.blue_guardian.schemas import (
    CorrelationBasis,
    DefensiveEventEnvelope,
    EpistemicClassification,
    GuardianExecutionCreateRequest,
    GuardianExecutionStatus,
)
from app.main import app
from app.models.attack_path import AttackPath
from app.models.attack_path_stage import AttackPathStage
from app.models.attack_run import AttackRun
from app.models.audit_log import AuditLog
from app.models.campaign import Campaign
from app.models.guardian import CorrelatedEventGroup, DefensiveEventRecord, GuardianExecution
from app.models.sandbox import SandboxEnvironment
from app.models.synthetic_asset import SyntheticAsset
from app.models.user import User, UserRole
from app.services.audit_service import verify_audit_chain, verify_event_hash
from app.services.campaign_service import create_campaign
from app.services.guardian.correlation_service import CorrelationService, generate_deterministic_group_id
from app.services.guardian.ingestion_service import (
    CrossSandboxSecurityViolation,
    IngestionService,
    NonSyntheticEvidenceViolation,
    compute_payload_sha256,
)
from app.services.guardian.orchestrator_service import GuardianOrchestrationService
from app.services.sandbox_service import create_sandbox, register_asset
from app.workers.celery_app import celery_app
from app.workers.guardian_tasks import execute_guardian_analysis_task, run_guardian_analysis_async


# =============================================================================
# Fixtures
# =============================================================================

@pytest_asyncio.fixture
async def guardian_sandbox_fixture(db_session, test_operator):
    """Creates a controlled sandbox environment with synthetic assets for Blue Guardian testing."""
    suffix = str(uuid.uuid4())[:8]
    sandbox = await create_sandbox(
        session=db_session,
        name=f"BG-Sandbox-{suffix}",
        description="Controlled sandbox for Blue Guardian tests",
        owner_id=test_operator.id,
    )

    # Asset 1: Database
    asset_db = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"bg-db-{suffix}",
            "asset_type": "database",
            "hostname": f"db-{suffix}.sandbox.local",
            "ip_address": "198.51.100.20",
            "risk_level": "critical",
            "connected_asset_ids": [],
            "service_metadata": {"services": [{"port": 5432, "service": "postgresql"}]},
            "configuration": {"allow_anonymous": False},
            "simulated_vulnerabilities": [],
        },
    )

    # Asset 2: Web Server connected to Database
    asset_web = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"bg-web-{suffix}",
            "asset_type": "server",
            "hostname": f"web-{suffix}.sandbox.local",
            "ip_address": "198.51.100.10",
            "risk_level": "high",
            "connected_asset_ids": [str(asset_db.id)],
            "service_metadata": {"services": [{"port": 80, "service": "http"}]},
            "configuration": {"debug_mode": True},
            "simulated_vulnerabilities": [],
        },
    )

    # Campaign
    campaign = await create_campaign(
        session=db_session,
        name=f"BG-Campaign-{suffix}",
        trigger_type="manual",
        environment="sandbox",
        sandbox_id=sandbox.id,
    )

    await db_session.commit()
    await db_session.refresh(sandbox)
    await db_session.refresh(asset_db)
    await db_session.refresh(asset_web)
    await db_session.refresh(campaign)

    return {
        "sandbox": sandbox,
        "asset_db": asset_db,
        "asset_web": asset_web,
        "campaign": campaign,
    }


def create_mock_simulation_event(
    event_id: str,
    timestamp: datetime,
    event_type: str = "auth_bypass",
    scenario_id: str = "scenario_api_auth_bypass",
    source_asset_id: str | None = None,
    destination_asset_id: str | None = None,
    is_simulated: bool = True,
    simulation_only: bool = True,
) -> dict:
    """Helper creating a valid simulated event dictionary matching RedTeam format."""
    return {
        "event_id": event_id,
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "scenario_id": scenario_id,
        "source_asset_id": source_asset_id,
        "destination_asset_id": destination_asset_id,
        "severity": "high",
        "message": f"Simulated {event_type} on target asset",
        "details": {"endpoint": "/api/v1/login", "simulated": True},
        "event_metadata": {"rule": "sim_rule_1"},
        "is_simulated": is_simulated,
        "simulation_only": simulation_only,
    }


# =============================================================================
# 1. Schema & Validation Tests
# =============================================================================

def test_defensive_event_envelope_extra_forbid():
    """Verifies that DefensiveEventEnvelope strictly forbids extra fields."""
    with pytest.raises(ValidationError):
        DefensiveEventEnvelope(
            source_event_id="evt-001",
            sandbox_id=uuid.uuid4(),
            timestamp=datetime.now(timezone.utc),
            event_type="auth_bypass",
            severity="high",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            is_simulated=True,
            simulation_only=True,
            classification=EpistemicClassification.OBSERVED,
            extra_field="DISALLOWED",  # Must raise ValidationError
        )


def test_defensive_event_envelope_invalid_hash():
    """Verifies that sha256_hash must be a valid 64-character hex string."""
    with pytest.raises(ValidationError):
        DefensiveEventEnvelope(
            source_event_id="evt-001",
            sandbox_id=uuid.uuid4(),
            timestamp=datetime.now(timezone.utc),
            event_type="auth_bypass",
            severity="high",
            sha256_hash="invalid_short_hash",
            is_simulated=True,
            simulation_only=True,
            classification=EpistemicClassification.OBSERVED,
        )


def test_defensive_event_envelope_non_synthetic_rejected():
    """Verifies that is_simulated must be Literal[True]."""
    with pytest.raises(ValidationError):
        DefensiveEventEnvelope(
            source_event_id="evt-001",
            sandbox_id=uuid.uuid4(),
            timestamp=datetime.now(timezone.utc),
            event_type="auth_bypass",
            severity="high",
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            is_simulated=False,  # Disallowed
            simulation_only=True,
            classification=EpistemicClassification.OBSERVED,
        )


# =============================================================================
# 2. Ingestion & Provenance Tests
# =============================================================================

@pytest.mark.asyncio
async def test_ingestion_valid_synthetic_events(db_session, guardian_sandbox_fixture, test_operator):
    """Verifies ingestion of valid synthetic security events and immutability of source evidence."""
    sandbox = guardian_sandbox_fixture["sandbox"]
    campaign = guardian_sandbox_fixture["campaign"]
    asset_web = guardian_sandbox_fixture["asset_web"]

    now = datetime.now(timezone.utc)
    ev1 = create_mock_simulation_event("evt-bg-001", now, "auth_bypass", source_asset_id=str(asset_web.id))
    ev2 = create_mock_simulation_event("evt-bg-002", now + timedelta(seconds=10), "privilege_escalation", source_asset_id=str(asset_web.id))

    original_metadata = {
        "status": "completed",
        "scenario": "scenario_api_auth_bypass",
        "events": [ev1, ev2],
        "findings": [],
        "risk_score": 7.5,
        "simulation_only": True,
    }

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=7.5,
        execution_metadata=dict(original_metadata),
    )
    db_session.add(run)
    await db_session.commit()
    await db_session.refresh(run)

    # Ingest through Orchestration Service
    service = GuardianOrchestrationService(session=db_session)
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=run.id,
        correlation_window_seconds=300,
    )
    execution = await service.execute_analysis(request=req, user=test_operator)

    assert execution.status == GuardianExecutionStatus.COMPLETED.value
    assert execution.events_ingested == 2
    assert execution.correlation_groups_count >= 1

    # Verify persisted DefensiveEventRecords
    records = (
        await db_session.execute(
            select(DefensiveEventRecord).where(DefensiveEventRecord.guardian_execution_id == execution.id)
        )
    ).scalars().all()
    assert len(records) == 2
    assert records[0].source_event_id == "evt-bg-001"
    assert records[0].is_simulated is True
    assert records[0].simulation_only is True
    assert len(records[0].sha256_hash) == 64

    # Source evidence immutability guarantee: AttackRun metadata must remain strictly identical
    await db_session.refresh(run)
    assert run.execution_metadata == original_metadata


@pytest.mark.asyncio
async def test_ingestion_rejection_non_synthetic(db_session, guardian_sandbox_fixture, test_operator):
    """Verifies that events lacking is_simulated=True are rejected with NonSyntheticEvidenceViolation."""
    sandbox = guardian_sandbox_fixture["sandbox"]
    campaign = guardian_sandbox_fixture["campaign"]

    ev_bad = create_mock_simulation_event("evt-bad-001", datetime.now(timezone.utc), is_simulated=False)

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=5.0,
        execution_metadata={"events": [ev_bad], "simulation_only": True},
    )
    db_session.add(run)
    await db_session.commit()
    await db_session.refresh(run)

    service = GuardianOrchestrationService(session=db_session)
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=run.id,
    )

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as excinfo:
        await service.execute_analysis(request=req, user=test_operator)
    assert excinfo.value.status_code == 400
    assert "Non-synthetic evidence violation" in excinfo.value.detail


@pytest.mark.asyncio
async def test_ingestion_cross_sandbox_rejection(db_session, guardian_sandbox_fixture, test_operator):
    """Verifies that an AttackRun belonging to Sandbox B cannot be ingested for Sandbox A."""
    sandbox_a = guardian_sandbox_fixture["sandbox"]
    suffix = uuid.uuid4().hex[:8]

    # Create Sandbox B
    sandbox_b = await create_sandbox(
        session=db_session,
        name=f"BG-Sandbox-Other-{suffix}",
        description="Isolated secondary sandbox",
        owner_id=test_operator.id,
    )
    campaign_b = await create_campaign(
        session=db_session,
        name=f"BG-Campaign-Other-{suffix}",
        trigger_type="manual",
        environment="sandbox",
        sandbox_id=sandbox_b.id,
    )
    run_b = AttackRun(
        campaign_id=campaign_b.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=5.0,
        execution_metadata={"events": [create_mock_simulation_event("evt-b-001", datetime.now(timezone.utc))]},
    )
    db_session.add(run_b)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    # Attempt to ingest run_b under sandbox_a
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox_a.id,
        attack_run_id=run_b.id,
    )

    from fastapi import HTTPException
    with pytest.raises(HTTPException) as excinfo:
        await service.execute_analysis(request=req, user=test_operator)
    assert excinfo.value.status_code == 400
    assert "does not belong to target sandbox" in excinfo.value.detail


@pytest.mark.asyncio
async def test_ingestion_idempotency_and_deduplication(db_session, guardian_sandbox_fixture, test_operator):
    """Verifies that repeated ingestion does not duplicate defensive records."""
    sandbox = guardian_sandbox_fixture["sandbox"]
    campaign = guardian_sandbox_fixture["campaign"]
    now = datetime.now(timezone.utc)

    ev = create_mock_simulation_event("evt-idemp-001", now)
    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=5.0,
        execution_metadata={"events": [ev, ev]},  # Duplicate in source
    )
    db_session.add(run)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=run.id,
    )
    exec1 = await service.execute_analysis(request=req, user=test_operator)
    assert exec1.events_ingested == 1  # Deduplicated

    records = (
        await db_session.execute(
            select(DefensiveEventRecord).where(DefensiveEventRecord.guardian_execution_id == exec1.id)
        )
    ).scalars().all()
    assert len(records) == 1


# =============================================================================
# 3. Deterministic Correlation Engine Tests
# =============================================================================

@pytest.mark.asyncio
async def test_correlation_direct_attack_run(db_session, guardian_sandbox_fixture, test_operator):
    """Verifies Rule CORR-DIR-001: Direct Attack Run Correlation with DIRECT basis."""
    sandbox = guardian_sandbox_fixture["sandbox"]
    campaign = guardian_sandbox_fixture["campaign"]
    now = datetime.now(timezone.utc)

    ev1 = create_mock_simulation_event("evt-c-001", now)
    ev2 = create_mock_simulation_event("evt-c-002", now + timedelta(seconds=5))

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=6.0,
        execution_metadata={"events": [ev1, ev2]},
    )
    db_session.add(run)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=run.id,
    )
    execution = await service.execute_analysis(request=req, user=test_operator)

    groups = (
        await db_session.execute(
            select(CorrelatedEventGroup).where(
                CorrelatedEventGroup.guardian_execution_id == execution.id,
                CorrelatedEventGroup.correlation_basis == CorrelationBasis.DIRECT.value,
            )
        )
    ).scalars().all()

    assert len(groups) == 1
    direct_group = groups[0]
    assert direct_group.correlation_basis == "DIRECT"
    assert direct_group.member_event_ids == ["evt-c-001", "evt-c-002"]
    assert direct_group.correlation_confidence == 1.0


@pytest.mark.asyncio
async def test_correlation_relational_asset_graph(db_session, guardian_sandbox_fixture, test_operator):
    """Verifies Rule CORR-REL-003: Relational Asset Graph Correlation across connected assets."""
    sandbox = guardian_sandbox_fixture["sandbox"]
    campaign = guardian_sandbox_fixture["campaign"]
    asset_web = guardian_sandbox_fixture["asset_web"]
    asset_db = guardian_sandbox_fixture["asset_db"]
    now = datetime.now(timezone.utc)

    # Event 1 on Web Server, Event 2 on Database (connected to Web Server)
    ev1 = create_mock_simulation_event("evt-rel-001", now, "initial_access", source_asset_id=str(asset_web.id))
    ev2 = create_mock_simulation_event("evt-rel-002", now + timedelta(seconds=15), "lateral_movement", source_asset_id=str(asset_db.id))

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1021",
        scenario="scenario_rbac_privilege_creep_lateral_movement",
        outcome="completed",
        risk_score=7.0,
        execution_metadata={"events": [ev1, ev2]},
    )
    db_session.add(run)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=run.id,
    )
    execution = await service.execute_analysis(request=req, user=test_operator)

    rel_groups = (
        await db_session.execute(
            select(CorrelatedEventGroup).where(
                CorrelatedEventGroup.guardian_execution_id == execution.id,
                CorrelatedEventGroup.correlation_basis == CorrelationBasis.RELATIONAL.value,
            )
        )
    ).scalars().all()

    assert len(rel_groups) >= 1
    rel = rel_groups[0]
    assert rel.correlation_basis == "RELATIONAL"
    assert set(rel.member_event_ids) == {"evt-rel-001", "evt-rel-002"}
    assert rel.stage == "LATERAL_MOVEMENT"


@pytest.mark.asyncio
async def test_correlation_temporal_sliding_window(db_session, guardian_sandbox_fixture, test_operator):
    """Verifies Rule CORR-TEMP-004: Temporal Correlation with explicit non-causality disclaimer."""
    sandbox = guardian_sandbox_fixture["sandbox"]
    campaign = guardian_sandbox_fixture["campaign"]
    now = datetime.now(timezone.utc)

    # Two events within 60s, one event 400s later (beyond 300s window)
    ev1 = create_mock_simulation_event("evt-t-001", now)
    ev2 = create_mock_simulation_event("evt-t-002", now + timedelta(seconds=60))
    ev3 = create_mock_simulation_event("evt-t-003", now + timedelta(seconds=450))

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=5.5,
        execution_metadata={"events": [ev1, ev2, ev3]},
    )
    db_session.add(run)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=run.id,
        correlation_window_seconds=300,
    )
    execution = await service.execute_analysis(request=req, user=test_operator)

    temp_groups = (
        await db_session.execute(
            select(CorrelatedEventGroup).where(
                CorrelatedEventGroup.guardian_execution_id == execution.id,
                CorrelatedEventGroup.correlation_basis == CorrelationBasis.TEMPORAL.value,
            )
        )
    ).scalars().all()

    assert len(temp_groups) == 2  # Window 1: ev1+ev2, Window 2: ev3
    # Verify mandatory causality disclaimer
    assert "Temporal correlation does not imply causality" in temp_groups[0].group_metadata["causality_note"]


@pytest.mark.asyncio
async def test_correlation_determinism(db_session, guardian_sandbox_fixture, test_operator):
    """Verifies that correlation produces identical deterministic outputs and UUIDv5s across repeated evaluations."""
    sandbox = guardian_sandbox_fixture["sandbox"]
    campaign = guardian_sandbox_fixture["campaign"]
    now = datetime.now(timezone.utc)

    ev1 = create_mock_simulation_event("evt-det-001", now)
    ev2 = create_mock_simulation_event("evt-det-002", now + timedelta(seconds=20))

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=6.0,
        execution_metadata={"events": [ev1, ev2]},
    )
    db_session.add(run)
    await db_session.commit()

    corr_service = CorrelationService(session=db_session)
    exec_id = uuid.uuid4()
    mock_exec = GuardianExecution(
        id=exec_id,
        sandbox_id=sandbox.id,
        attack_run_id=run.id,
        status="correlating",
    )

    rec1 = DefensiveEventRecord(
        guardian_execution_id=exec_id,
        sandbox_id=sandbox.id,
        source_event_id="evt-det-001",
        attack_run_id=run.id,
        campaign_id=campaign.id,
        event_type="auth_bypass",
        severity="high",
        original_timestamp=now,
        is_simulated=True,
        simulation_only=True,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    rec2 = DefensiveEventRecord(
        guardian_execution_id=exec_id,
        sandbox_id=sandbox.id,
        source_event_id="evt-det-002",
        attack_run_id=run.id,
        campaign_id=campaign.id,
        event_type="auth_bypass",
        severity="high",
        original_timestamp=now + timedelta(seconds=20),
        is_simulated=True,
        simulation_only=True,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )

    groups_eval1 = corr_service.correlate_by_attack_run(mock_exec, [rec1, rec2])
    groups_eval2 = corr_service.correlate_by_attack_run(mock_exec, [rec2, rec1])  # Reversed input order

    assert len(groups_eval1) == 1
    assert len(groups_eval2) == 1
    # Deterministic UUIDv5 invariant: must match regardless of input ordering
    assert groups_eval1[0].id == groups_eval2[0].id
    assert groups_eval1[0].member_event_ids == groups_eval2[0].member_event_ids


# =============================================================================
# 4. REST API & OPA Authorization Tests
# =============================================================================

@pytest.mark.asyncio
async def test_api_create_execution_operator_allowed(guardian_sandbox_fixture, operator_token, db_session):
    """Verifies that Security Operator can initiate defensive ingestion via API."""
    sandbox = guardian_sandbox_fixture["sandbox"]
    campaign = guardian_sandbox_fixture["campaign"]

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=5.0,
        execution_metadata={"events": [create_mock_simulation_event("evt-api-001", datetime.now(timezone.utc))]},
    )
    db_session.add(run)
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/guardian/executions",
            headers={"Authorization": f"Bearer {operator_token}"},
            json={
                "sandbox_id": str(sandbox.id),
                "attack_run_id": str(run.id),
                "correlation_window_seconds": 300,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "completed"
        assert data["events_ingested"] == 1
        assert "execution_id" in data


@pytest.mark.asyncio
async def test_api_create_execution_viewer_denied(guardian_sandbox_fixture, viewer_token, db_session):
    """Verifies that Viewer role is denied initiating defensive analysis by OPA."""
    sandbox = guardian_sandbox_fixture["sandbox"]
    campaign = guardian_sandbox_fixture["campaign"]

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=5.0,
        execution_metadata={"events": []},
    )
    db_session.add(run)
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/guardian/executions",
            headers={"Authorization": f"Bearer {viewer_token}"},
            json={
                "sandbox_id": str(sandbox.id),
                "attack_run_id": str(run.id),
            },
        )
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_api_get_execution_and_events_operator(guardian_sandbox_fixture, operator_token, db_session):
    """Verifies retrieving execution details, paginated events, and correlated groups via API."""
    sandbox = guardian_sandbox_fixture["sandbox"]
    campaign = guardian_sandbox_fixture["campaign"]

    ev = create_mock_simulation_event("evt-get-001", datetime.now(timezone.utc))
    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=5.0,
        execution_metadata={"events": [ev]},
    )
    db_session.add(run)
    await db_session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Create
        create_resp = await client.post(
            "/api/v1/guardian/executions",
            headers={"Authorization": f"Bearer {operator_token}"},
            json={"sandbox_id": str(sandbox.id), "attack_run_id": str(run.id)},
        )
        assert create_resp.status_code == 201
        exec_id = create_resp.json()["execution_id"]

        # Get details
        detail_resp = await client.get(
            f"/api/v1/guardian/executions/{exec_id}",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert detail_resp.status_code == 200
        assert detail_resp.json()["execution_id"] == exec_id

        # List events
        events_resp = await client.get(
            f"/api/v1/guardian/executions/{exec_id}/events",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert events_resp.status_code == 200
        events_data = events_resp.json()
        assert events_data["total"] == 1
        assert events_data["items"][0]["source_event_id"] == "evt-get-001"

        # List correlated groups
        groups_resp = await client.get(
            f"/api/v1/guardian/executions/{exec_id}/correlated-groups",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert groups_resp.status_code == 200
        groups_data = groups_resp.json()
        assert groups_data["total"] >= 1
        group_id = groups_data["items"][0]["id"]

        # Get single group detail
        single_resp = await client.get(
            f"/api/v1/guardian/executions/{exec_id}/correlated-groups/{group_id}",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert single_resp.status_code == 200
        assert single_resp.json()["group"]["id"] == group_id
        assert len(single_resp.json()["events"]) >= 1


# =============================================================================
# 5. Cryptographic Audit Chain & Celery Task Tests
# =============================================================================

@pytest.mark.asyncio
async def test_audit_chain_emitted_during_execution(db_session, guardian_sandbox_fixture, test_operator):
    """Verifies that Blue Guardian lifecycle emits tamper-evident audit records into the hash chain."""
    sandbox = guardian_sandbox_fixture["sandbox"]
    campaign = guardian_sandbox_fixture["campaign"]

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=5.0,
        execution_metadata={"events": [create_mock_simulation_event("evt-aud-001", datetime.now(timezone.utc))]},
    )
    db_session.add(run)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=run.id,
    )
    execution = await service.execute_analysis(request=req, user=test_operator)

    # Query audit logs for this execution
    logs = (
        await db_session.execute(
            select(AuditLog)
            .where(AuditLog.resource_id == str(execution.id))
            .order_by(AuditLog.id)
        )
    ).scalars().all()

    actions = [l.action for l in logs]
    assert "guardian.execute" in actions
    assert "guardian.ingest" in actions
    assert "guardian.correlate" in actions

    # Verify cryptographic hash integrity on each audit log
    for l in logs:
        assert verify_event_hash(l) is True


@pytest.mark.asyncio
async def test_celery_task_execution(db_session, guardian_sandbox_fixture, test_operator):
    """Verifies that the Celery background task is registered and executes successfully."""
    sandbox = guardian_sandbox_fixture["sandbox"]
    campaign = guardian_sandbox_fixture["campaign"]

    # 1. Verify task registration in Celery
    task_name = "app.workers.guardian_tasks.execute_guardian_analysis_task"
    assert task_name in celery_app.tasks

    # 2. Verify async execution
    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=5.0,
        execution_metadata={"events": [create_mock_simulation_event("evt-cel-001", datetime.now(timezone.utc))]},
    )
    db_session.add(run)
    await db_session.commit()
    await db_session.refresh(run)

    result = await run_guardian_analysis_async(
        sandbox_id=str(sandbox.id),
        user_id=str(test_operator.id),
        attack_run_id=str(run.id),
        correlation_window_seconds=300,
    )

    assert result["status"] == "completed"
    assert result["events_ingested"] == 1
    assert result["correlation_groups_count"] >= 1
    assert "execution_id" in result


@pytest.mark.asyncio
async def test_forensic_retention_restricts_execution_deletion(db_session, guardian_sandbox_fixture, test_operator):
    """Verifies that foreign key ON DELETE RESTRICT prevents deleting a GuardianExecution
    when dependent forensic records exist, preventing accidental cascade destruction.
    """
    sandbox = guardian_sandbox_fixture["sandbox"]
    campaign = guardian_sandbox_fixture["campaign"]
    asset_web = guardian_sandbox_fixture["asset_web"]

    now = datetime.now(timezone.utc)
    ev = create_mock_simulation_event("retention-evt-001", now, source_asset_id=str(asset_web.id))

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=6.0,
        execution_metadata={"events": [ev], "simulation_only": True},
    )
    db_session.add(run)
    await db_session.commit()
    await db_session.refresh(run)

    service = GuardianOrchestrationService(session=db_session)
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=run.id,
        correlation_window_seconds=300,
    )
    execution = await service.execute_analysis(request=req, user=test_operator)
    assert execution.events_ingested == 1

    # Verify that child records exist
    records = (await db_session.execute(
        select(DefensiveEventRecord).where(DefensiveEventRecord.guardian_execution_id == execution.id)
    )).scalars().all()
    assert len(records) == 1

    # Attempting to delete the parent GuardianExecution must raise IntegrityError due to ON DELETE RESTRICT
    exec_record = await db_session.get(GuardianExecution, execution.id)
    await db_session.delete(exec_record)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_historical_archived_asset_event_ingestion(db_session, guardian_sandbox_fixture, test_operator):
    """Verifies that historical events referencing an archived asset within the sandbox
    are properly ingested, maintaining forensic completeness for decommissioned assets.
    """
    sandbox = guardian_sandbox_fixture["sandbox"]
    campaign = guardian_sandbox_fixture["campaign"]

    # Create an archived asset in the sandbox
    archived_asset = SyntheticAsset(
        name="Decommissioned DB Cluster",
        asset_type="database",
        sandbox_id=sandbox.id,
        hostname="hist-db-01.sandbox.local",
        ip_address="10.0.1.99",
        status="archived",
        description="Historical asset decommissioned post-incident",
    )
    db_session.add(archived_asset)
    await db_session.commit()
    await db_session.refresh(archived_asset)

    ingestion_service = IngestionService(db_session)
    valid_assets = await ingestion_service.get_sandbox_asset_ids(sandbox.id)
    assert archived_asset.id in valid_assets

    ev = create_mock_simulation_event(
        "hist-evt-001",
        datetime.now(timezone.utc),
        source_asset_id=str(archived_asset.id),
    )

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=5.0,
        execution_metadata={"events": [ev], "simulation_only": True},
    )
    db_session.add(run)
    await db_session.commit()
    await db_session.refresh(run)

    service = GuardianOrchestrationService(session=db_session)
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=run.id,
        correlation_window_seconds=300,
    )
    execution = await service.execute_analysis(request=req, user=test_operator)
    assert execution.events_ingested == 1

    records = (await db_session.execute(
        select(DefensiveEventRecord).where(DefensiveEventRecord.guardian_execution_id == execution.id)
    )).scalars().all()
    assert len(records) == 1
    assert records[0].source_asset_id == archived_asset.id

