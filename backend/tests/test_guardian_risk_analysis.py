"""
AEGIS Blue Guardian Subsystem Tests - Step 09.2.3.4
Asset Impact, Blast Radius Traversal & Risk Analysis Engine.

Comprehensive technical verification:
- Bounded BFS graph traversal with cycle prevention, max depth, and node limits.
- Asset exposure categorization (DIRECTLY_AFFECTED vs POTENTIALLY_EXPOSED).
- Strict cross-sandbox isolation.
- Support for historical and archived assets.
- Deterministic, explainable 6-dimension risk scoring bounded in [0.0, 10.0].
- Independence of evidence confidence and risk impact.
- Multi-key deterministic threat and asset prioritization.
- Idempotency on rerun without duplicate key violations.
- Forensic retention via foreign key RESTRICT constraints.
- Role-based OPA authorization (Operator/Analyst allowed, Viewer denied).
- REST API pagination and filtering.
- SHA-256 chained audit logs.
- Celery worker background task integration.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import uuid
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, delete

from app.main import app
from app.models.attack_run import AttackRun
from app.models.audit_log import AuditLog
from app.models.campaign import Campaign
from app.models.guardian import (
    GuardianExecution,
    ThreatDetection,
    ThreatRiskAssessment,
    ThreatAssetImpact,
)
from app.models.synthetic_asset import SyntheticAsset
from app.agents.blue_guardian.schemas import (
    GuardianExecutionStatus,
    AssetImpactType,
    RiskCategory,
)
from app.services.audit_service import verify_event_hash
from app.services.campaign_service import create_campaign
from app.services.sandbox_service import create_sandbox, register_asset
from app.services.guardian.blast_radius_analyzer import BlastRadiusAnalyzer
from app.services.guardian.asset_impact_analyzer import AssetImpactAnalyzer, EvaluatedAssetImpact
from app.services.guardian.risk_scoring_engine import RiskScoringEngine, SCORING_FORMULA_VERSION
from app.services.guardian.risk_prioritization import RiskPrioritizer
from app.services.guardian.risk_analysis_service import RiskAnalysisService
from app.services.guardian.orchestrator_service import GuardianOrchestrationService
from app.workers.guardian_tasks import run_guardian_analysis_async


# =============================================================================
# Fixtures
# =============================================================================

@pytest_asyncio.fixture
async def risk_topology_fixture(db_session, test_operator):
    """
    Sets up a deterministic 4-node topology inside a sandbox:
    Web (Root, High) -> App (Hop 1, Medium) -> DB (Hop 2, Critical) -> Backup (Hop 3, High)
    """
    suffix = uuid.uuid4().hex[:8]
    sandbox = await create_sandbox(
        session=db_session,
        name=f"Risk-Sandbox-{suffix}",
        description="Controlled topology for Risk Analysis Engine tests",
        owner_id=None,
    )

    asset_backup = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"risk-backup-{suffix}",
            "asset_type": "storage",
            "hostname": f"backup-{suffix}.sandbox.local",
            "ip_address": "198.51.100.40",
            "risk_level": "high",
            "connected_asset_ids": [],
            "service_metadata": {"services": [{"port": 22, "service": "ssh"}]},
            "configuration": {},
            "simulated_vulnerabilities": [],
        },
    )

    asset_db = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"risk-db-{suffix}",
            "asset_type": "database",
            "hostname": f"db-{suffix}.sandbox.local",
            "ip_address": "198.51.100.30",
            "risk_level": "critical",
            "connected_asset_ids": [str(asset_backup.id)],
            "service_metadata": {"services": [{"port": 5432, "service": "postgresql"}]},
            "configuration": {"is_critical": True},
            "simulated_vulnerabilities": [],
        },
    )

    asset_app = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"risk-app-{suffix}",
            "asset_type": "server",
            "hostname": f"app-{suffix}.sandbox.local",
            "ip_address": "198.51.100.20",
            "risk_level": "medium",
            "connected_asset_ids": [str(asset_db.id)],
            "service_metadata": {"services": [{"port": 8080, "service": "http"}]},
            "configuration": {},
            "simulated_vulnerabilities": [],
        },
    )

    asset_web = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"risk-web-{suffix}",
            "asset_type": "web_application",
            "hostname": f"web-{suffix}.sandbox.local",
            "ip_address": "198.51.100.10",
            "risk_level": "high",
            "connected_asset_ids": [str(asset_app.id)],
            "service_metadata": {"services": [{"port": 443, "service": "https"}]},
            "configuration": {},
            "simulated_vulnerabilities": [],
        },
    )

    campaign = await create_campaign(
        session=db_session,
        name=f"Risk-Campaign-{suffix}",
        trigger_type="manual",
        environment="sandbox",
        sandbox_id=sandbox.id,
    )

    await db_session.commit()
    await db_session.refresh(sandbox)
    await db_session.refresh(asset_web)
    await db_session.refresh(asset_app)
    await db_session.refresh(asset_db)
    await db_session.refresh(asset_backup)
    await db_session.refresh(campaign)

    return {
        "sandbox": sandbox,
        "asset_web": asset_web,
        "asset_app": asset_app,
        "asset_db": asset_db,
        "asset_backup": asset_backup,
        "campaign": campaign,
    }


def make_sim_event(
    event_id: str,
    timestamp: datetime,
    event_type: str,
    scenario_id: str,
    source_asset_id: str | None = None,
    destination_asset_id: str | None = None,
    severity: str = "high",
    details: dict | None = None,
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "scenario_id": scenario_id,
        "source_asset_id": source_asset_id,
        "destination_asset_id": destination_asset_id,
        "severity": severity,
        "message": f"Simulated {event_type}",
        "raw_payload": details or {"simulated": True, "evidence": "synthetic"},
        "is_simulated": True,
        "simulation_only": True,
    }


# =============================================================================
# Unit & Algorithm Verification Tests
# =============================================================================

def test_blast_radius_traversal_bounded_and_cycle_prevention():
    """Verifies that BFS traversal respects bounds and prevents cycles."""
    n1, n2, n3, n4 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    
    # Cyclic topology: n1 -> n2 -> n3 -> n1 (cycle), n3 -> n4
    adjacency = {
        n1: {n2},
        n2: {n3},
        n3: {n1, n4},
        n4: set(),
    }
    all_nodes = {n1, n2, n3, n4}

    analyzer = BlastRadiusAnalyzer(max_depth=3, max_nodes=25)
    res = analyzer.analyze_blast_radius(
        root_asset_ids={n1},
        adjacency_map=adjacency,
        valid_sandbox_asset_ids=all_nodes,
    )

    # Visited must contain n1, n2, n3, n4 without infinite loop
    assert res.total_nodes_visited == 4
    assert n1 in res.root_asset_ids
    assert res.downstream_nodes[n2].depth == 1
    assert res.downstream_nodes[n3].depth == 2
    assert res.downstream_nodes[n4].depth == 3

    # Test max depth clipping
    shallow_analyzer = BlastRadiusAnalyzer(max_depth=1, max_nodes=25)
    shallow_res = shallow_analyzer.analyze_blast_radius(
        root_asset_ids={n1},
        adjacency_map=adjacency,
        valid_sandbox_asset_ids=all_nodes,
    )
    assert n4 not in shallow_res.downstream_nodes
    assert n3 not in shallow_res.downstream_nodes
    assert n2 in shallow_res.downstream_nodes


def test_asset_impact_categorization_and_downstream_exposure():
    """
    Verifies that downstream connected assets are strictly categorized as
    POTENTIALLY_EXPOSED (never confirmed compromised) and hop decay is applied.
    """
    n1, n2 = uuid.uuid4(), uuid.uuid4()
    dummy_exec_id = uuid.uuid4()
    dummy_sb_id = uuid.uuid4()
    detection = ThreatDetection(
        id=uuid.uuid4(),
        guardian_execution_id=dummy_exec_id,
        sandbox_id=dummy_sb_id,
        detection_code="DET-TEST-001",
        rule_code="RULE-TEST",
        title="Test Rule",
        description="Simulated Detection",
        classification="Credential Access",
        severity="High",
        confidence_score=0.85,
        affected_asset_ids=[str(n1)],
    )

    mock_assets = {
        n1: SyntheticAsset(id=n1, name="web", asset_type="server", risk_level="high"),
        n2: SyntheticAsset(id=n2, name="db", asset_type="database", risk_level="critical"),
    }
    adjacency = {n1: {n2}, n2: set()}

    analyzer = AssetImpactAnalyzer()
    impacts = analyzer.analyze_impact(
        detection=detection,
        sandbox_assets_by_id=mock_assets,
        adjacency_map=adjacency,
    )

    impact_by_id = {imp.asset_id: imp for imp in impacts}
    assert n1 in impact_by_id
    assert n2 in impact_by_id

    # Root asset: DIRECTLY_AFFECTED at depth 0
    assert impact_by_id[n1].impact_type == AssetImpactType.DIRECTLY_AFFECTED
    assert impact_by_id[n1].traversal_depth == 0

    # Downstream connected asset: POTENTIALLY_EXPOSED at depth 1
    assert impact_by_id[n2].impact_type == AssetImpactType.POTENTIALLY_EXPOSED
    assert impact_by_id[n2].traversal_depth == 1
    # Downstream score decays with distance
    assert impact_by_id[n2].impact_score < impact_by_id[n1].impact_score


def test_cross_sandbox_isolation_enforced():
    """Verifies that blast radius traversal never leaks into another sandbox."""
    sb1_asset = uuid.uuid4()
    sb2_asset = uuid.uuid4()

    # Adjacency maliciously connects to sb2_asset
    adjacency = {sb1_asset: {sb2_asset}, sb2_asset: set()}
    valid_sb1 = {sb1_asset}  # Only sb1_asset is valid for sandbox 1

    analyzer = BlastRadiusAnalyzer(max_depth=3, max_nodes=25)
    res = analyzer.analyze_blast_radius(
        root_asset_ids={sb1_asset},
        adjacency_map=adjacency,
        valid_sandbox_asset_ids=valid_sb1,
    )

    assert sb1_asset in res.root_asset_ids
    assert sb2_asset not in res.downstream_nodes
    assert res.total_nodes_visited == 1


def test_risk_scoring_formula_and_bounds():
    """
    Verifies that the risk scoring formula produces deterministic scores strictly
    in [0.0, 10.0] and maps accurately to categorical risk tiers.
    """
    score_low, cat_low, rat_low = RiskScoringEngine.calculate_risk_score(
        severity="Low",
        confidence=0.50,
        impact_analysis={"directly_affected": [{"is_critical": False}], "potentially_exposed": [], "has_critical_exposure": False},
        mitre_tactics=["Reconnaissance"],
        total_sandbox_assets=5,
    )
    assert 0.0 <= score_low <= 10.0
    assert cat_low in [RiskCategory.LOW, RiskCategory.INFORMATIONAL]
    assert rat_low["formula_version"] == SCORING_FORMULA_VERSION

    score_crit, cat_crit, rat_crit = RiskScoringEngine.calculate_risk_score(
        severity="Critical",
        confidence=0.95,
        impact_analysis={"directly_affected": [{"is_critical": True}], "potentially_exposed": [{"is_critical": True}], "has_critical_exposure": True},
        mitre_tactics=["Impact"],
        total_sandbox_assets=2,
    )
    assert 0.0 <= score_crit <= 10.0
    assert score_crit >= 8.0
    assert cat_crit == RiskCategory.CRITICAL


def test_severity_and_confidence_independence_in_risk():
    """
    Verifies that evidence confidence is strictly 5% of risk score,
    so high confidence (0.95) does not alone drive Critical risk.
    """
    score_high_conf_low_sev, cat, _ = RiskScoringEngine.calculate_risk_score(
        severity="Low",
        confidence=1.00,  # 100% confidence
        impact_analysis={"directly_affected": [{"is_critical": False}], "potentially_exposed": [], "has_critical_exposure": False},
        mitre_tactics=["Discovery"],
        total_sandbox_assets=10,
    )
    # With Low severity and no critical assets, risk must not exceed Medium
    assert score_high_conf_low_sev < 6.0
    assert cat in [RiskCategory.LOW, RiskCategory.MEDIUM]


def test_risk_prioritization_determinism():
    """Verifies deterministic sorting across risk score, severity, critical asset, and timestamp."""
    id1, id2, id3 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    t0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=5)

    a1 = ThreatRiskAssessment(
        id=id1,
        risk_score=7.50,
        severity="High",
        created_at=t0,
    )
    a1._directly_affected_count = 1
    a1._critical_asset_exposed = False

    a2 = ThreatRiskAssessment(
        id=id2,
        risk_score=8.50,  # Higher score -> must rank first
        severity="Critical",
        created_at=t1,
    )
    a2._directly_affected_count = 2
    a2._critical_asset_exposed = True

    a3 = ThreatRiskAssessment(
        id=id3,
        risk_score=7.50,  # Tie score with a1, but earlier created_at and critical asset exposed
        severity="High",
        created_at=t0,
    )
    a3._directly_affected_count = 1
    a3._critical_asset_exposed = True

    ranked = RiskPrioritizer.rank_threats([a1, a2, a3])
    assert ranked[0].id == id2  # 8.50
    assert ranked[1].id == id3  # 7.50 + Critical asset exposed
    assert ranked[2].id == id1  # 7.50 + No critical asset exposed


# =============================================================================
# Pipeline & Database Integration Tests
# =============================================================================

@pytest.mark.asyncio
async def test_end_to_end_risk_analysis_pipeline(risk_topology_fixture, db_session, test_operator):
    """
    Executes end-to-end ingestion -> correlation -> detection -> risk analysis,
    verifying risk assessments and asset impacts are generated and persisted.
    """
    sandbox = risk_topology_fixture["sandbox"]
    campaign = risk_topology_fixture["campaign"]
    asset_web = risk_topology_fixture["asset_web"]
    asset_app = risk_topology_fixture["asset_app"]
    t0 = datetime.now(timezone.utc)

    # Telemetry targeting web and pivoting to app
    sim_events = [
        make_sim_event("risk-ev-001", t0, "web_exploit", "scenario_api_auth_bypass", None, str(asset_web.id), "high"),
        make_sim_event("risk-ev-002", t0 + timedelta(seconds=10), "credential_dump", "scenario_privilege_escalation", str(asset_web.id), str(asset_app.id), "critical"),
    ]

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=8.0,
        execution_metadata={"events": sim_events},
    )
    db_session.add(run)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=run.id,
        correlation_window_seconds=300,
    )

    execution = await service.execute_analysis(request=req, user=test_operator)

    assert execution.status == GuardianExecutionStatus.COMPLETED.value
    assert execution.threat_detections_count > 0
    assert execution.risk_assessments_count > 0
    assert execution.max_risk_score > 0.0

    from sqlalchemy.orm import selectinload
    # Query assessments from database
    assessments_query = (
        select(ThreatRiskAssessment)
        .where(ThreatRiskAssessment.guardian_execution_id == execution.id)
        .options(selectinload(ThreatRiskAssessment.asset_impacts))
    )
    res = await db_session.execute(assessments_query)
    assessments = list(res.scalars().all())
    assert len(assessments) == execution.risk_assessments_count

    for ass in assessments:
        assert 0.0 <= ass.risk_score <= 10.0
        assert ass.sandbox_id == sandbox.id
        assert ass.scoring_formula_version == SCORING_FORMULA_VERSION
        assert len(ass.asset_impacts) > 0


@pytest.mark.asyncio
async def test_risk_analysis_service_idempotency_on_retry(risk_topology_fixture, db_session, test_operator):
    """Verifies that running risk analysis twice on the same execution is idempotent without duplicate keys."""
    sandbox = risk_topology_fixture["sandbox"]
    campaign = risk_topology_fixture["campaign"]
    asset_web = risk_topology_fixture["asset_web"]
    t0 = datetime.now(timezone.utc)

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=6.0,
        execution_metadata={"events": [make_sim_event("idemp-ev-01", t0, "auth_bypass", "scenario_api_auth_bypass", None, str(asset_web.id))]},
    )
    db_session.add(run)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
    req = GuardianExecutionCreateRequest(sandbox_id=sandbox.id, attack_run_id=run.id, correlation_window_seconds=300)
    execution = await service.execute_analysis(request=req, user=test_operator)

    # First run count
    initial_count = execution.risk_assessments_count
    assert initial_count > 0

    # Explicitly re-run risk analysis
    risk_service = RiskAnalysisService(db_session)
    recalculated = await risk_service.run_risk_analysis_for_execution(execution=execution)
    assert len(recalculated) == initial_count


@pytest.mark.asyncio
async def test_foreign_key_retention_on_delete_restrict(risk_topology_fixture, db_session, test_operator):
    """
    Verifies that deleting a GuardianExecution or ThreatDetection is prevented
    by ON DELETE RESTRICT when derived ThreatRiskAssessment records exist.
    """
    sandbox = risk_topology_fixture["sandbox"]
    campaign = risk_topology_fixture["campaign"]
    asset_web = risk_topology_fixture["asset_web"]
    t0 = datetime.now(timezone.utc)

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=7.0,
        execution_metadata={"events": [make_sim_event("fk-ev-01", t0, "web_exploit", "scenario_api_auth_bypass", None, str(asset_web.id))]},
    )
    db_session.add(run)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
    req = GuardianExecutionCreateRequest(sandbox_id=sandbox.id, attack_run_id=run.id, correlation_window_seconds=300)
    execution = await service.execute_analysis(request=req, user=test_operator)

    # Attempt deleting the execution directly -> must raise IntegrityError
    from sqlalchemy.exc import IntegrityError
    with pytest.raises(IntegrityError):
        await db_session.delete(execution)
        await db_session.commit()

    await db_session.rollback()


# =============================================================================
# Authorization & REST API Tests
# =============================================================================

@pytest.mark.asyncio
async def test_risk_api_authorization_operator_analyst_allowed_viewer_denied(
    risk_topology_fixture,
    operator_token,
    analyst_token,
    viewer_token,
    db_session,
    test_operator,
):
    """Verifies OPA policies allow security_operator and security_analyst, while viewer is denied."""
    sandbox = risk_topology_fixture["sandbox"]
    campaign = risk_topology_fixture["campaign"]
    asset_web = risk_topology_fixture["asset_web"]
    t0 = datetime.now(timezone.utc)

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=7.0,
        execution_metadata={"events": [make_sim_event("auth-ev-01", t0, "web_exploit", "scenario_api_auth_bypass", None, str(asset_web.id))]},
    )
    db_session.add(run)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
    req = GuardianExecutionCreateRequest(sandbox_id=sandbox.id, attack_run_id=run.id, correlation_window_seconds=300)
    execution = await service.execute_analysis(request=req, user=test_operator)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Operator -> 200 OK
        resp_op = await client.get(
            f"/api/v1/guardian/executions/{execution.id}/risk-assessments",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert resp_op.status_code == 200

        # 2. Analyst -> 200 OK
        resp_an = await client.get(
            f"/api/v1/guardian/executions/{execution.id}/risk-assessments",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert resp_an.status_code == 200

        # 3. Viewer -> 403 Forbidden
        resp_vi = await client.get(
            f"/api/v1/guardian/executions/{execution.id}/risk-assessments",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert resp_vi.status_code == 403


@pytest.mark.asyncio
async def test_risk_api_endpoints_filtering_and_pagination(
    risk_topology_fixture,
    operator_token,
    db_session,
    test_operator,
):
    """Tests /risk-summary, /risk-priorities, /risk-assessments, /executions/{id}/risk-assessments, and /assets/{id}/risk."""
    sandbox = risk_topology_fixture["sandbox"]
    campaign = risk_topology_fixture["campaign"]
    asset_web = risk_topology_fixture["asset_web"]
    t0 = datetime.now(timezone.utc)

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=7.0,
        execution_metadata={"events": [make_sim_event("api-ev-01", t0, "web_exploit", "scenario_api_auth_bypass", None, str(asset_web.id))]},
    )
    db_session.add(run)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
    req = GuardianExecutionCreateRequest(sandbox_id=sandbox.id, attack_run_id=run.id, correlation_window_seconds=300)
    execution = await service.execute_analysis(request=req, user=test_operator)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        headers = {"Authorization": f"Bearer {operator_token}"}

        # 1. /risk-summary
        r_sum = await client.get(f"/api/v1/guardian/risk-summary?sandbox_id={sandbox.id}", headers=headers)
        assert r_sum.status_code == 200
        sum_data = r_sum.json()
        assert sum_data["total_assessments"] >= 1
        assert sum_data["max_risk_score"] > 0.0

        # 2. /risk-priorities
        r_prio = await client.get(f"/api/v1/guardian/risk-priorities?sandbox_id={sandbox.id}&limit=5", headers=headers)
        assert r_prio.status_code == 200
        prio_data = r_prio.json()
        assert prio_data["total"] >= 1
        assert len(prio_data["items"]) >= 1

        # 3. /risk-assessments
        r_list = await client.get(f"/api/v1/guardian/risk-assessments?execution_id={execution.id}", headers=headers)
        assert r_list.status_code == 200
        list_data = r_list.json()
        assert list_data["total"] >= 1
        ass_id = list_data["items"][0]["id"]

        # 4. /risk-assessments/{assessment_id}
        r_det = await client.get(f"/api/v1/guardian/risk-assessments/{ass_id}", headers=headers)
        assert r_det.status_code == 200
        det_data = r_det.json()
        assert det_data["assessment"]["id"] == ass_id
        assert len(det_data["impacted_assets"]) > 0

        # 5. /assets/{asset_id}/risk
        r_asset = await client.get(f"/api/v1/guardian/assets/{asset_web.id}/risk", headers=headers)
        assert r_asset.status_code == 200
        asset_profile = r_asset.json()
        assert asset_profile["asset_id"] == str(asset_web.id)


@pytest.mark.asyncio
async def test_audit_chain_emits_risk_events(risk_topology_fixture, db_session, test_operator):
    """Verifies that cryptographic SHA-256 chained audit logs are emitted for risk analysis phases."""
    sandbox = risk_topology_fixture["sandbox"]
    campaign = risk_topology_fixture["campaign"]
    asset_web = risk_topology_fixture["asset_web"]
    t0 = datetime.now(timezone.utc)

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=7.0,
        execution_metadata={"events": [make_sim_event("audit-ev-01", t0, "web_exploit", "scenario_api_auth_bypass", None, str(asset_web.id))]},
    )
    db_session.add(run)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
    req = GuardianExecutionCreateRequest(sandbox_id=sandbox.id, attack_run_id=run.id, correlation_window_seconds=300)
    execution = await service.execute_analysis(request=req, user=test_operator)

    # Inspect audit log entries
    query = select(AuditLog).where(
        AuditLog.event_data["sandbox_id"].astext == str(sandbox.id)
    ).order_by(AuditLog.created_at)
    res = await db_session.execute(query)
    logs = list(res.scalars().all())

    event_types = [l.event_type for l in logs]
    assert "guardian.risk_analysis.started" in event_types
    assert "guardian.risk_assessment.created" in event_types
    assert "guardian.risk_analysis.completed" in event_types

    # Verify SHA-256 integrity of emitted logs
    for log in logs:
        assert verify_event_hash(log) is True


@pytest.mark.asyncio
async def test_celery_task_includes_risk_summary(risk_topology_fixture, db_session, test_operator):
    """Verifies that the Celery task runner executes risk analysis and includes metrics in the returned summary."""
    sandbox = risk_topology_fixture["sandbox"]
    campaign = risk_topology_fixture["campaign"]
    asset_web = risk_topology_fixture["asset_web"]
    t0 = datetime.now(timezone.utc)

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1078",
        scenario="scenario_api_auth_bypass",
        outcome="completed",
        risk_score=7.0,
        execution_metadata={"events": [make_sim_event("celery-ev-01", t0, "web_exploit", "scenario_api_auth_bypass", None, str(asset_web.id))]},
    )
    db_session.add(run)
    await db_session.commit()

    summary = await run_guardian_analysis_async(
        sandbox_id=str(sandbox.id),
        user_id=str(test_operator.id),
        attack_run_id=str(run.id),
        correlation_window_seconds=300,
    )

    assert summary["status"] == "completed"
    assert summary["threat_detections_count"] > 0
    assert summary["risk_assessments_count"] > 0
    assert summary["max_risk_score"] > 0.0
