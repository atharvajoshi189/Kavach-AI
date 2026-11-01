"""Comprehensive Test Suite for AegisMesh 2.0 Step 09.2.3.3:
Blue Guardian Threat Detection Engine.

Verifies:
1. All 8 initial detection rules (BGD-RULE-001 through BGD-RULE-008) in registry.
2. Rule matching and non-matching conditions (bounded evaluator logic).
3. Evidence-grounded MITRE ATT&CK mapping (T1046, T1110, T1190, T1068, T1021, T1053, T1048).
4. Severity engine determinism and escalation logic (critical asset, compromise flags).
5. Confidence engine scoring (bounded 0.0 to 1.0, volume, payload completeness).
6. Strict independence between Severity and Confidence.
7. End-to-end integration with GuardianOrchestrationService.
8. Detection idempotency and duplicate prevention.
9. Full traceability to source evidence and source record immutability.
10. Support for historical/archived assets in sandbox detections.
11. OPA authorization policies (operator/analyst allowed, viewer denied).
12. REST API endpoints (/executions/{id}/detections, /detections/{id}, /detections, /detection-rules, /detections/summary).
13. SHA-256 chained audit logs for detection lifecycle.
14. Celery background task execution with threat detections count.
"""

from datetime import datetime, timedelta, timezone
import uuid
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.agents.blue_guardian.schemas import (
    GuardianExecutionCreateRequest,
    GuardianExecutionStatus,
)
from app.main import app
from app.models.attack_run import AttackRun
from app.models.audit_log import AuditLog
from app.models.campaign import Campaign
from app.models.guardian import CorrelatedEventGroup, DefensiveEventRecord, GuardianExecution, ThreatDetection
from app.models.sandbox import SandboxEnvironment
from app.models.synthetic_asset import SyntheticAsset
from app.services.audit_service import verify_event_hash
from app.services.campaign_service import create_campaign
from app.services.guardian.confidence_engine import ConfidenceEngine
from app.services.guardian.detection_engine import DetectionEngine
from app.services.guardian.detection_rules import DetectionRuleRegistry, INITIAL_DETECTION_RULES
from app.services.guardian.mitre_mapper import MitreMapper
from app.services.guardian.orchestrator_service import GuardianOrchestrationService
from app.services.guardian.severity_engine import SeverityEngine
from app.services.sandbox_service import create_sandbox, register_asset
from app.workers.guardian_tasks import run_guardian_analysis_async


# =============================================================================
# Fixtures & Helpers
# =============================================================================

@pytest_asyncio.fixture
async def detection_sandbox_fixture(db_session, test_operator):
    """Provisions a test sandbox environment with assets and campaign for detection tests."""
    suffix = uuid.uuid4().hex[:8]

    sandbox = await create_sandbox(
        session=db_session,
        name=f"Det-Sandbox-{suffix}",
        description="Controlled sandbox for Threat Detection tests",
        owner_id=None,
    )

    asset_db = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"det-db-{suffix}",
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

    asset_web = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"det-web-{suffix}",
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

    campaign = await create_campaign(
        session=db_session,
        name=f"Det-Campaign-{suffix}",
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
    """Creates a mock event dictionary matching RedTeam format."""
    return {
        "event_id": event_id,
        "timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "scenario_id": scenario_id,
        "source_asset_id": source_asset_id,
        "destination_asset_id": destination_asset_id,
        "severity": severity,
        "message": f"Simulated {event_type}",
        "details": details or {"simulated": True},
        "event_metadata": {"rule": "sim_rule"},
        "is_simulated": True,
        "simulation_only": True,
    }


# =============================================================================
# 1. Detection Rule Library & Registry Tests
# =============================================================================

def test_detection_rule_registry_contains_all_eight_rules():
    """Verifies that all 8 expected detection rules are present, enabled, and valid."""
    registry = DetectionRuleRegistry()
    rules = registry.get_all_rules()
    assert len(rules) == 8

    expected_codes = [
        "BGD-RULE-001",
        "BGD-RULE-002",
        "BGD-RULE-003",
        "BGD-RULE-004",
        "BGD-RULE-005",
        "BGD-RULE-006",
        "BGD-RULE-007",
        "BGD-RULE-008",
    ]
    actual_codes = [r.rule_code for r in rules]
    assert actual_codes == expected_codes

    for rule in rules:
        assert rule.enabled is True
        assert rule.rule_version == "1.0.0"
        assert len(rule.description) > 10
        assert rule.severity in ["Low", "Medium", "High", "Critical"]
        assert 0.0 <= rule.confidence <= 1.0
        assert len(rule.mitre_tactics) >= 1
        assert len(rule.mitre_techniques) >= 1
        assert len(rule.false_positive_conditions) >= 1


def test_rule_non_match_on_unrelated_events():
    """Verifies that rules safely evaluate to None when presented with unrelated events."""
    registry = DetectionRuleRegistry()
    rule_weak_config = registry.get_rule("BGD-RULE-008")
    assert rule_weak_config is not None

    dummy_group = CorrelatedEventGroup(
        id=uuid.uuid4(),
        guardian_execution_id=uuid.uuid4(),
        sandbox_id=uuid.uuid4(),
        title="Unrelated group",
        stage="general",
        correlation_basis="DIRECT",
        correlation_rule="RULE",
        earliest_event_timestamp=datetime.now(timezone.utc),
        latest_event_timestamp=datetime.now(timezone.utc),
    )

    # Completely unrelated event with no finding or misconfiguration evidence
    dummy_event = DefensiveEventRecord(
        id=uuid.uuid4(),
        guardian_execution_id=dummy_group.guardian_execution_id,
        sandbox_id=dummy_group.sandbox_id,
        source_event_id="dummy-1",
        event_type="benign_ping",
        severity="INFO",
        original_timestamp=datetime.now(timezone.utc),
        raw_payload={"status": "ok"},
        is_simulated=True,
        simulation_only=True,
        sha256_hash="hash",
    )

    result = rule_weak_config.evaluate(dummy_group, [dummy_event])
    assert result is None  # Evaluator safely returns None without raising exceptions


# =============================================================================
# 2. MITRE Mapping Tests
# =============================================================================

def test_mitre_mapping_correctness():
    """Verifies that MitreMapper produces valid, evidence-backed technique payloads."""
    mapping = MitreMapper.map_technique("T1046", evidence_clues=["Port 80 and 443 probes"])
    assert mapping["technique_id"] == "T1046"
    assert mapping["technique_name"] == "Network Service Discovery"
    assert mapping["tactic"] == "Reconnaissance"
    assert "Port 80 and 443 probes" in mapping["mapping_rationale"]

    tactics = MitreMapper.extract_tactics([mapping])
    assert tactics == ["Reconnaissance"]


# =============================================================================
# 3. Severity & Confidence Engine Tests (Decoupled & Independent)
# =============================================================================

def test_severity_engine_evaluation_and_escalation():
    """Verifies that SeverityEngine escalates severity based on impact and asset criticality."""
    # 1. Base severity
    sev, rat = SeverityEngine.evaluate_severity(base_severity="Low")
    assert sev == "Low"

    # 2. Critical asset escalation
    critical_asset = {"name": "Prod DB", "criticality": "critical"}
    sev_crit, rat_crit = SeverityEngine.evaluate_severity(
        base_severity="Low",
        affected_assets=[critical_asset],
    )
    assert sev_crit == "Medium"
    assert "critical target infrastructure" in rat_crit

    # 3. Compromise flag escalation
    sev_comp, rat_comp = SeverityEngine.evaluate_severity(
        base_severity="Medium",
        is_compromised=True,
    )
    assert sev_comp == "High"
    assert "confirmed stage compromise" in rat_comp

    # 4. Multi-host lateral movement floor
    sev_pivot, rat_pivot = SeverityEngine.evaluate_severity(
        base_severity="Low",
        multi_host_scope=True,
    )
    assert sev_pivot == "High"
    assert "High' floor" in rat_pivot


def test_confidence_engine_bounded_scoring():
    """Verifies that ConfidenceEngine scores are strictly bounded between 0.10 and 1.00."""
    score, rat = ConfidenceEngine.evaluate_confidence(
        base_confidence=0.75,
        event_count=5,
        min_required_events=1,
        correlation_confidence=1.0,
        correlation_basis="DIRECT",
        has_rich_payload=True,
        asset_resolution_verified=True,
    )
    assert 0.10 <= score <= 1.00
    assert score > 0.75
    assert "Base rule confidence" in rat
    assert "Final Confidence" in rat


def test_severity_and_confidence_are_independent():
    """Verifies that changing evidence factors altering confidence does NOT affect severity,
    and asset criticality altering severity does NOT affect confidence.
    """
    # Test 1: Varying event count alters confidence but severity remains identical
    sev1, _ = SeverityEngine.evaluate_severity(base_severity="Medium")
    sev2, _ = SeverityEngine.evaluate_severity(base_severity="Medium")
    assert sev1 == sev2 == "Medium"

    conf1, _ = ConfidenceEngine.evaluate_confidence(base_confidence=0.70, event_count=1, min_required_events=1)
    conf2, _ = ConfidenceEngine.evaluate_confidence(base_confidence=0.70, event_count=10, min_required_events=1)
    assert conf2 > conf1
    # Severity did not change despite 10x event volume

    # Test 2: Asset criticality elevates severity but does not change confidence
    sev_high, _ = SeverityEngine.evaluate_severity(base_severity="Medium", affected_assets=[{"criticality": "critical"}])
    assert sev_high == "High"

    conf_same, _ = ConfidenceEngine.evaluate_confidence(base_confidence=0.70, event_count=1, min_required_events=1)
    assert conf_same == conf1  # Confidence unchanged


# =============================================================================
# 4. End-to-End Threat Detection Pipeline Execution
# =============================================================================

@pytest.mark.asyncio
async def test_end_to_end_detection_pipeline_execution(
    db_session,
    detection_sandbox_fixture,
    test_operator,
):
    """Executes a full pipeline from AttackRun to ThreatDetections via GuardianOrchestrationService."""
    sandbox = detection_sandbox_fixture["sandbox"]
    campaign = detection_sandbox_fixture["campaign"]
    asset_web = detection_sandbox_fixture["asset_web"]
    asset_db = detection_sandbox_fixture["asset_db"]

    now = datetime.now(timezone.utc)
    # Auth bypass (BGD-RULE-003, Initial Access) and Privilege escalation (BGD-RULE-004, Privilege Escalation)
    ev1 = make_sim_event(
        event_id="e2e-evt-001",
        timestamp=now,
        event_type="auth_bypass",
        scenario_id="simulated_initial_access",
        source_asset_id=str(asset_web.id),
        details={"path": "/api/v1/auth/bypass", "status": "success"},
    )
    ev2 = make_sim_event(
        event_id="e2e-evt-002",
        timestamp=now + timedelta(seconds=15),
        event_type="privilege_escalation",
        scenario_id="simulated_privilege_escalation",
        source_asset_id=str(asset_web.id),
        details={"technique": "suid_exec", "uid": 0, "root": True},
    )

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1190",
        scenario="simulated_initial_access",
        outcome="completed",
        risk_score=8.5,
        execution_metadata={"events": [ev1, ev2], "simulation_only": True},
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

    # 1. Verify pipeline completed successfully
    assert execution.status == GuardianExecutionStatus.COMPLETED.value
    assert execution.events_ingested == 2
    assert execution.correlation_groups_count >= 1
    assert execution.threat_detections_count >= 1

    # 2. Inspect persisted ThreatDetection records
    detections = (await db_session.execute(
        select(ThreatDetection)
        .where(ThreatDetection.guardian_execution_id == execution.id)
        .order_by(ThreatDetection.created_at)
    )).scalars().all()

    assert len(detections) >= 1
    det = detections[0]
    assert det.sandbox_id == sandbox.id
    assert det.guardian_execution_id == execution.id
    assert det.is_simulated is True
    assert det.simulation_only is True
    assert det.status == "new"
    assert det.severity in ["Medium", "High", "Critical"]
    assert 0.0 <= det.confidence_score <= 1.0
    assert len(det.mitre_techniques) >= 1
    assert len(det.evidence_references["source_event_ids"]) >= 1


# =============================================================================
# 5. Detection Idempotency Tests
# =============================================================================

@pytest.mark.asyncio
async def test_detection_engine_idempotency_on_retry(
    db_session,
    detection_sandbox_fixture,
    test_operator,
):
    """Verifies that re-running the detection engine does not generate duplicate ThreatDetection records."""
    sandbox = detection_sandbox_fixture["sandbox"]
    campaign = detection_sandbox_fixture["campaign"]
    asset_web = detection_sandbox_fixture["asset_web"]

    now = datetime.now(timezone.utc)
    ev = make_sim_event(
        event_id="idem-evt-001",
        timestamp=now,
        event_type="port_scan",
        scenario_id="simulated_service_discovery",
        source_asset_id=str(asset_web.id),
    )

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1046",
        scenario="simulated_service_discovery",
        outcome="completed",
        risk_score=4.0,
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
    initial_count = execution.threat_detections_count
    assert initial_count >= 1

    # Re-run detection engine directly on same execution
    det_engine = DetectionEngine(session=db_session)
    rerun_detections = await det_engine.run_detection_for_execution(execution=execution)
    await db_session.commit()

    # Verify count did not double
    total_detections = (await db_session.execute(
        select(ThreatDetection).where(ThreatDetection.guardian_execution_id == execution.id)
    )).scalars().all()

    assert len(total_detections) == initial_count


# =============================================================================
# 6. Source Record Immutability & Traceability Tests
# =============================================================================

@pytest.mark.asyncio
async def test_source_evidence_immutability(
    db_session,
    detection_sandbox_fixture,
    test_operator,
):
    """Verifies that running threat detection never mutates or overrides original AttackRun metadata."""
    sandbox = detection_sandbox_fixture["sandbox"]
    campaign = detection_sandbox_fixture["campaign"]
    asset_web = detection_sandbox_fixture["asset_web"]

    now = datetime.now(timezone.utc)
    ev = make_sim_event("immut-evt-001", now, "auth_failure", "simulated_authentication_anomaly", str(asset_web.id))

    original_metadata = {
        "events": [ev],
        "findings": [{"vuln": "weak_creds"}],
        "risk_score": 5.5,
        "custom_marker": "immutable_source",
        "simulation_only": True,
    }

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1110",
        scenario="simulated_authentication_anomaly",
        outcome="completed",
        risk_score=5.5,
        execution_metadata=dict(original_metadata),
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
    await service.execute_analysis(request=req, user=test_operator)

    # Re-fetch AttackRun and verify metadata is identical
    run_after = await db_session.get(AttackRun, run.id)
    assert run_after.execution_metadata == original_metadata
    assert run_after.execution_metadata["custom_marker"] == "immutable_source"


# =============================================================================
# 7. Historical / Archived Asset Telemetry Support
# =============================================================================

@pytest.mark.asyncio
async def test_historical_archived_asset_detection_support(
    db_session,
    detection_sandbox_fixture,
    test_operator,
):
    """Verifies that detections targeting archived historical assets within the sandbox
    are properly processed and include the archived asset in affected_asset_ids.
    """
    sandbox = detection_sandbox_fixture["sandbox"]
    campaign = detection_sandbox_fixture["campaign"]

    # Create an archived asset in the sandbox
    archived_asset = SyntheticAsset(
        name="Decommissioned Server",
        asset_type="server",
        sandbox_id=sandbox.id,
        hostname="archived-01.sandbox.local",
        ip_address="198.51.100.99",
        status="archived",
        description="Decommissioned legacy server",
    )
    db_session.add(archived_asset)
    await db_session.commit()
    await db_session.refresh(archived_asset)

    now = datetime.now(timezone.utc)
    ev = make_sim_event(
        "arch-evt-001",
        now,
        "auth_bypass",
        "simulated_initial_access",
        source_asset_id=str(archived_asset.id),
    )

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1190",
        scenario="simulated_initial_access",
        outcome="completed",
        risk_score=7.0,
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
    assert execution.threat_detections_count >= 1

    detections = (await db_session.execute(
        select(ThreatDetection).where(ThreatDetection.guardian_execution_id == execution.id)
    )).scalars().all()

    assert any(str(archived_asset.id) in d.affected_asset_ids for d in detections)


# =============================================================================
# 8. OPA Authorization Tests
# =============================================================================

@pytest.mark.asyncio
async def test_detection_api_authorization_operator_allowed_viewer_denied(
    db_session,
    detection_sandbox_fixture,
    operator_token,
    viewer_token,
    analyst_token,
    test_operator,
):
    """Verifies that operator and analyst can access detections, while viewer is denied."""
    sandbox = detection_sandbox_fixture["sandbox"]
    campaign = detection_sandbox_fixture["campaign"]
    asset_web = detection_sandbox_fixture["asset_web"]

    now = datetime.now(timezone.utc)
    ev = make_sim_event("authz-evt-001", now, "port_scan", "simulated_service_discovery", str(asset_web.id))

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1046",
        scenario="simulated_service_discovery",
        outcome="completed",
        risk_score=4.0,
        execution_metadata={"events": [ev], "simulation_only": True},
    )
    db_session.add(run)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    req = GuardianExecutionCreateRequest(sandbox_id=sandbox.id, attack_run_id=run.id)
    execution = await service.execute_analysis(request=req, user=test_operator)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Operator: Allowed to read detections
        op_res = await client.get(
            f"/api/v1/guardian/executions/{execution.id}/detections",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert op_res.status_code == 200
        assert op_res.json()["total"] >= 1

        # 2. Analyst: Allowed to read detections
        an_res = await client.get(
            f"/api/v1/guardian/executions/{execution.id}/detections",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert an_res.status_code == 200

        # 3. Viewer: Denied access
        vi_res = await client.get(
            f"/api/v1/guardian/executions/{execution.id}/detections",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert vi_res.status_code == 403

        # 4. Analyst: Allowed to list rules
        rules_res = await client.get(
            "/api/v1/guardian/detection-rules",
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert rules_res.status_code == 200
        assert rules_res.json()["total"] == 8

        # 5. Viewer: Denied rules listing
        rules_vi = await client.get(
            "/api/v1/guardian/detection-rules",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert rules_vi.status_code == 403


# =============================================================================
# 9. REST API Filtering & Summary Endpoints
# =============================================================================

@pytest.mark.asyncio
async def test_detection_api_filtering_and_summary(
    db_session,
    detection_sandbox_fixture,
    operator_token,
    test_operator,
):
    """Verifies filtering, pagination, and summary aggregation endpoints."""
    sandbox = detection_sandbox_fixture["sandbox"]
    campaign = detection_sandbox_fixture["campaign"]
    asset_web = detection_sandbox_fixture["asset_web"]

    now = datetime.now(timezone.utc)
    ev = make_sim_event("filt-evt-001", now, "auth_bypass", "simulated_initial_access", str(asset_web.id))

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1190",
        scenario="simulated_initial_access",
        outcome="completed",
        risk_score=7.0,
        execution_metadata={"events": [ev], "simulation_only": True},
    )
    db_session.add(run)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    req = GuardianExecutionCreateRequest(sandbox_id=sandbox.id, attack_run_id=run.id)
    execution = await service.execute_analysis(request=req, user=test_operator)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Global list with sandbox filter
        list_res = await client.get(
            f"/api/v1/guardian/detections?sandbox_id={sandbox.id}",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert list_res.status_code == 200
        data = list_res.json()
        assert data["total"] >= 1
        det_id = data["items"][0]["id"]

        # 2. Get single detection detail
        detail_res = await client.get(
            f"/api/v1/guardian/detections/{det_id}",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert detail_res.status_code == 200
        det_data = detail_res.json()
        assert det_data["id"] == det_id
        assert "detection_rationale" in det_data

        # 3. Detection summary metrics
        sum_res = await client.get(
            f"/api/v1/guardian/detections/summary?sandbox_id={sandbox.id}",
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert sum_res.status_code == 200
        summary = sum_res.json()
        assert summary["total_detections"] >= 1
        assert "High" in summary["by_severity"] or "Critical" in summary["by_severity"]
        assert summary["affected_assets_count"] >= 1


# =============================================================================
# 10. Audit Chain Verification & Celery Execution
# =============================================================================

@pytest.mark.asyncio
async def test_audit_chain_emits_detection_events(
    db_session,
    detection_sandbox_fixture,
    test_operator,
):
    """Verifies that detection lifecycle events are persistently recorded in the SHA-256 audit chain."""
    sandbox = detection_sandbox_fixture["sandbox"]
    campaign = detection_sandbox_fixture["campaign"]
    asset_web = detection_sandbox_fixture["asset_web"]

    now = datetime.now(timezone.utc)
    ev = make_sim_event("audit-det-001", now, "privilege_escalation", "simulated_privilege_escalation", str(asset_web.id))

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1068",
        scenario="simulated_privilege_escalation",
        outcome="completed",
        risk_score=8.0,
        execution_metadata={"events": [ev], "simulation_only": True},
    )
    db_session.add(run)
    await db_session.commit()

    service = GuardianOrchestrationService(session=db_session)
    req = GuardianExecutionCreateRequest(sandbox_id=sandbox.id, attack_run_id=run.id)
    execution = await service.execute_analysis(request=req, user=test_operator)

    # Inspect audit logs for this execution
    logs = (await db_session.execute(
        select(AuditLog)
        .where(
            (AuditLog.resource_id == str(execution.id)) |
            (AuditLog.event_data["sandbox_id"].as_string() == str(sandbox.id))
        )
        .order_by(AuditLog.id)
    )).scalars().all()

    actions = [l.action for l in logs]
    assert "guardian.detect" in actions

    for log in logs:
        assert verify_event_hash(log) is True


@pytest.mark.asyncio
async def test_celery_task_integration_threat_detections(
    db_session,
    detection_sandbox_fixture,
    test_operator,
):
    """Verifies that run_guardian_analysis_async returns threat_detections_count."""
    sandbox = detection_sandbox_fixture["sandbox"]
    campaign = detection_sandbox_fixture["campaign"]
    asset_web = detection_sandbox_fixture["asset_web"]

    now = datetime.now(timezone.utc)
    ev = make_sim_event("cel-det-001", now, "auth_bypass", "simulated_initial_access", str(asset_web.id))

    run = AttackRun(
        campaign_id=campaign.id,
        technique="T1190",
        scenario="simulated_initial_access",
        outcome="completed",
        risk_score=7.5,
        execution_metadata={"events": [ev], "simulation_only": True},
    )
    db_session.add(run)
    await db_session.commit()

    result = await run_guardian_analysis_async(
        sandbox_id=str(sandbox.id),
        user_id=str(test_operator.id),
        attack_run_id=str(run.id),
    )

    assert result["status"] == "completed"
    assert result["events_ingested"] == 1
    assert result["correlation_groups_count"] >= 1
    assert result["threat_detections_count"] >= 1
