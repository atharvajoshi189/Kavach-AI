"""
AEGIS Blue Guardian Subsystem Tests - Step 09.2.3.5
Defensive Recommendations, Remediation Planning & Incident Reports.

Comprehensive technical verification:
1. Playbook catalog spanning all 8 threat classes.
2. Deterministic recommendation priority calculation (P0, P1, P2, P3).
3. Strict evidence-backed requirement (no fabricated recommendations without supporting evidence).
4. Recommendation idempotency across execution re-runs.
5. Remediation plan priority ordering, dependency tracking, and action deduplication.
6. Epistemic boundary segregation in incident reports (Observed, Derived, Inferred, Advisory).
7. Non-compromised blast radius classification (marked POTENTIALLY_EXPOSED).
8. Report versioning without overwriting historical records.
9. Executive posture summary generation with deterministic narrative fallback.
10. OPA role-based access control (Operator/Analyst allowed, Viewer denied).
11. REST API endpoints for recommendations, remediation plans, incident reports, and summaries.
12. Full end-to-end pipeline execution and Celery background task integration.
13. SHA-256 chained audit logs for recommendation, remediation, and report events.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import uuid
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.main import app
from app.models.attack_run import AttackRun
from app.models.audit_log import AuditLog
from app.models.campaign import Campaign
from app.models.guardian import (
    DefensiveRecommendation,
    GuardianExecution,
    IncidentReport,
    RemediationPlan,
    RemediationPlanAction,
    ThreatDetection,
    ThreatRiskAssessment,
    ThreatAssetImpact,
)
from app.models.synthetic_asset import SyntheticAsset
from app.agents.blue_guardian.schemas import (
    GuardianExecutionStatus,
    RecommendationPriority,
    RecommendationStatus,
    RecommendationType,
    RemediationPlanStatus,
    IncidentReportStatus,
)
from app.services.audit_service import verify_event_hash
from app.services.campaign_service import create_campaign
from app.services.sandbox_service import create_sandbox, register_asset
from app.services.guardian.playbook_library import PlaybookLibrary
from app.services.guardian.recommendation_engine import RecommendationEngine
from app.services.guardian.remediation_planner import RemediationPlanner
from app.services.guardian.incident_report_service import IncidentReportService
from app.services.guardian.ai_enrichment import AIEnrichmentProvider
from app.services.guardian.orchestrator_service import GuardianOrchestrationService
from app.workers.guardian_tasks import run_guardian_analysis_async


# =============================================================================
# Fixtures
# =============================================================================

@pytest_asyncio.fixture
async def recommendation_topology_fixture(db_session, test_operator):
    """Sets up a realistic sandbox topology and Red Team attack run for recommendation tests."""
    suffix = uuid.uuid4().hex[:8]
    sandbox = await create_sandbox(
        session=db_session,
        name=f"Rec-Sandbox-{suffix}",
        description="Controlled topology for Step 09.2.3.5 recommendation tests",
        owner_id=None,
    )

    asset_db = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"rec-db-{suffix}",
            "asset_type": "database",
            "hostname": f"db-{suffix}.sandbox.local",
            "ip_address": "198.51.100.30",
            "risk_level": "critical",
            "connected_asset_ids": [],
            "service_metadata": {"services": [{"port": 5432, "service": "postgresql"}]},
            "configuration": {"is_critical": True},
            "simulated_vulnerabilities": [],
        },
    )

    asset_web = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"rec-web-{suffix}",
            "asset_type": "web_application",
            "hostname": f"web-{suffix}.sandbox.local",
            "ip_address": "198.51.100.10",
            "risk_level": "high",
            "connected_asset_ids": [str(asset_db.id)],
            "service_metadata": {"services": [{"port": 443, "service": "https"}]},
            "configuration": {},
            "simulated_vulnerabilities": [],
        },
    )

    campaign = await create_campaign(
        session=db_session,
        name=f"rec-campaign-{suffix}",
        trigger_type="manual",
        environment="sandbox",
        sandbox_id=sandbox.id,
    )

    now = datetime.now(timezone.utc)
    attack_run = AttackRun(
        id=uuid.uuid4(),
        campaign_id=campaign.id,
        technique="T1003",
        scenario="credential_theft",
        outcome="completed",
        risk_score=8.5,
        execution_metadata={
            "events": [
                {
                    "event_id": f"rec-ev-1-{suffix}",
                    "timestamp": (now - timedelta(minutes=4)).isoformat(),
                    "event_type": "credential_dump_lsass",
                    "scenario_id": "credential_theft",
                    "source_asset_id": str(asset_web.id),
                    "destination_asset_id": str(asset_db.id),
                    "severity": "critical",
                    "message": "Simulated credential theft event",
                    "raw_payload": {
                        "scenario_id": "credential_theft",
                        "technique": "T1003",
                        "user": "synthetic_admin",
                        "memory_dump_path": "/tmp/mimikatz_dump.bin",
                    },
                    "is_simulated": True,
                    "simulation_only": True,
                },
                {
                    "event_id": f"rec-ev-2-{suffix}",
                    "timestamp": (now - timedelta(minutes=2)).isoformat(),
                    "event_type": "lateral_psexec_execution",
                    "scenario_id": "lateral_movement",
                    "source_asset_id": str(asset_web.id),
                    "destination_asset_id": str(asset_db.id),
                    "severity": "high",
                    "message": "Simulated lateral movement execution",
                    "raw_payload": {
                        "scenario_id": "lateral_movement",
                        "technique": "T1021",
                        "command": "psexec.exe \\\\db-host",
                    },
                    "is_simulated": True,
                    "simulation_only": True,
                },
            ]
        },
    )
    db_session.add(attack_run)
    await db_session.flush()
    await db_session.commit()
    await db_session.refresh(sandbox)
    await db_session.refresh(asset_web)
    await db_session.refresh(asset_db)
    await db_session.refresh(campaign)

    return {
        "sandbox": sandbox,
        "campaign": campaign,
        "attack_run": attack_run,
        "asset_web": asset_web,
        "asset_db": asset_db,
    }


# =============================================================================
# 1. Playbook Library Tests
# =============================================================================

def test_playbook_library_coverage():
    """Verifies that all 8 threat classes are covered with structured playbooks."""
    library = PlaybookLibrary()
    playbooks = library.get_all_playbooks()

    assert len(playbooks) >= 8
    categories = {pb.category for pb in playbooks}
    expected_categories = {
        "Credential Access",
        "Initial Access",
        "Privilege Escalation",
        "Lateral Movement",
        "Persistence",
        "Exfiltration",
        "Reconnaissance",
        "Weak Configuration",
    }
    assert expected_categories.issubset(categories)

    # Verify each playbook has required fields and action templates
    for pb in playbooks:
        assert pb.playbook_id.startswith("BGD-PB-")
        assert pb.title
        assert pb.description
        assert pb.rationale
        assert pb.expected_outcome
        assert len(pb.verification_criteria) > 0
        assert len(pb.action_templates) > 0
        assert pb.complexity in ("low", "medium", "high")
        for act in pb.action_templates:
            assert act.action_code
            assert act.title
            assert act.action_type
            assert act.sequence_order >= 1


def test_playbook_matching():
    """Verifies deterministic playbook lookup by threat classification and MITRE technique."""
    library = PlaybookLibrary()

    # Match by classification
    matches_cred = library.find_playbooks_for_detection("Credential Access")
    assert any(pb.playbook_id == "BGD-PB-001" for pb in matches_cred)

    # Match by MITRE technique
    matches_tech = library.find_playbooks_for_detection("Custom Detection", ["T1048"])
    assert any(pb.playbook_id == "BGD-PB-006" for pb in matches_tech)

    # Fallback to general hardening (Weak Configuration) when unknown
    matches_unknown = library.find_playbooks_for_detection("Unknown Classification", ["T9999"])
    assert any(pb.playbook_id == "BGD-PB-008" for pb in matches_unknown)


# =============================================================================
# 2. Recommendation Engine Tests
# =============================================================================

@pytest.mark.asyncio
async def test_recommendation_generation_and_priority(db_session, test_operator, recommendation_topology_fixture):
    """Verifies deterministic recommendation generation and priority calculation."""
    fixture = recommendation_topology_fixture
    sandbox = fixture["sandbox"]
    attack_run = fixture["attack_run"]

    # Run guardian analysis through orchestrator
    orchestrator = GuardianOrchestrationService(db_session)
    from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=attack_run.id,
    )
    execution = await orchestrator.execute_analysis(req, test_operator)

    assert execution.status == GuardianExecutionStatus.COMPLETED.value
    assert execution.recommendations_count > 0

    # Query generated recommendations
    rec_query = select(DefensiveRecommendation).where(
        DefensiveRecommendation.guardian_execution_id == execution.id
    )
    recs = (await db_session.execute(rec_query)).scalars().all()
    assert len(recs) == execution.recommendations_count

    # Verify recommendations are evidence-backed
    for rec in recs:
        assert rec.evidence_references
        assert "detection_id" in rec.evidence_references
        assert "risk_score" in rec.evidence_references
        assert rec.rationale
        assert rec.expected_outcome
        assert len(rec.verification_criteria) > 0
        assert rec.priority in ("P0", "P1", "P2", "P3")
        assert rec.is_simulated is True
        assert rec.simulation_only is True

    # P0 priority verification: Credential Access against critical DB path should yield P0
    p0_recs = [r for r in recs if r.priority == "P0"]
    assert len(p0_recs) >= 1


@pytest.mark.asyncio
async def test_recommendation_idempotency(db_session, test_operator, recommendation_topology_fixture):
    """Verifies that re-running recommendation generation is idempotent without unique constraint violations."""
    fixture = recommendation_topology_fixture
    sandbox = fixture["sandbox"]
    attack_run = fixture["attack_run"]

    orchestrator = GuardianOrchestrationService(db_session)
    from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=attack_run.id,
    )
    execution = await orchestrator.execute_analysis(req, test_operator)

    rec_engine = RecommendationEngine(db_session)
    # Re-run recommendation generation
    second_recs = await rec_engine.generate_recommendations_for_execution(execution)

    assert len(second_recs) == execution.recommendations_count


# =============================================================================
# 3. Remediation Planning Tests
# =============================================================================

@pytest.mark.asyncio
async def test_remediation_planner_ordering_and_deduplication(db_session, test_operator, recommendation_topology_fixture):
    """Verifies remediation plan sequence ordering (P0 first), dependency preservation, and deduplication."""
    fixture = recommendation_topology_fixture
    sandbox = fixture["sandbox"]
    attack_run = fixture["attack_run"]

    orchestrator = GuardianOrchestrationService(db_session)
    from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=attack_run.id,
    )
    execution = await orchestrator.execute_analysis(req, test_operator)

    plan_query = (
        select(RemediationPlan)
        .where(RemediationPlan.guardian_execution_id == execution.id)
    )
    plan = (await db_session.execute(plan_query)).scalars().first()
    assert plan is not None
    assert plan.overall_priority == "P0"
    assert plan.status == RemediationPlanStatus.DRAFT.value
    assert len(plan.target_asset_ids) > 0

    # Query actions
    action_query = (
        select(RemediationPlanAction)
        .where(RemediationPlanAction.remediation_plan_id == plan.id)
        .order_by(RemediationPlanAction.sequence_order)
    )
    actions = (await db_session.execute(action_query)).scalars().all()
    assert len(actions) > 0

    # Verify sequence order starts at 1 and is strictly increasing
    sequences = [a.sequence_order for a in actions]
    assert sequences == list(range(1, len(actions) + 1))

    # Verify P0 actions are prioritized before P2/P3 actions
    first_action = actions[0]
    assert first_action.priority in ("P0", "P1")

    # Verify all action signatures are unique (deduplication)
    seen_types = set()
    for a in actions:
        sig = (a.action_type, tuple(sorted(a.target_asset_ids)))
        assert sig not in seen_types
        seen_types.add(sig)


# =============================================================================
# 4. Incident Report Service & Epistemic Boundary Tests
# =============================================================================

@pytest.mark.asyncio
async def test_incident_report_epistemic_boundaries(db_session, test_operator, recommendation_topology_fixture):
    """Verifies that incident reports distinguish Observed, Derived, Inferred, and Advisory sections,
    and never classify downstream blast radius assets as confirmed compromised.
    """
    fixture = recommendation_topology_fixture
    sandbox = fixture["sandbox"]
    attack_run = fixture["attack_run"]
    asset_db = fixture["asset_db"]

    orchestrator = GuardianOrchestrationService(db_session)
    from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=attack_run.id,
    )
    execution = await orchestrator.execute_analysis(req, test_operator)

    report_query = select(IncidentReport).where(
        IncidentReport.guardian_execution_id == execution.id
    )
    report = (await db_session.execute(report_query)).scalars().first()
    assert report is not None
    assert report.report_version == 1
    assert report.max_risk_score > 0.0
    assert report.executive_summary

    content = report.report_content
    assert "epistemic_sections" in content
    sections = content["epistemic_sections"]

    # 1. Observed facts: raw telemetry
    assert "observed_facts" in sections
    assert sections["observed_facts"]["total_events_ingested"] >= 2
    assert len(sections["observed_facts"]["event_timeline"]) >= 2

    # 2. Derived conclusions: detections and risk
    assert "derived_conclusions" in sections
    assert sections["derived_conclusions"]["total_threat_detections"] >= 1

    # 3. Inferred exposure: blast radius traversal
    assert "inferred_exposure" in sections
    inferred = sections["inferred_exposure"]
    assert "exposure_caveat" in inferred
    # Inferred exposure must explicitly maintain POTENTIALLY_EXPOSED status
    assert "POTENTIALLY_EXPOSED" in inferred["exposure_caveat"]

    # 4. Advisory recommendations: proposals only
    assert "advisory_recommendations" in sections
    assert sections["advisory_recommendations"]["total_recommendations"] >= 1


@pytest.mark.asyncio
async def test_incident_report_versioning(db_session, test_operator, recommendation_topology_fixture):
    """Verifies report version incrementation without overwriting prior published reports."""
    fixture = recommendation_topology_fixture
    sandbox = fixture["sandbox"]
    attack_run = fixture["attack_run"]

    orchestrator = GuardianOrchestrationService(db_session)
    from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=attack_run.id,
    )
    execution = await orchestrator.execute_analysis(req, test_operator)

    report_service = IncidentReportService(db_session)

    # Generate version 2
    report_v2 = await report_service.generate_incident_report(
        execution=execution,
        report_version=2,
        custom_title="Custom Post-Incident Forensic Review v2",
    )
    assert report_v2.report_version == 2
    assert report_v2.title == "Custom Post-Incident Forensic Review v2"

    # Query all reports for this execution
    all_reports = (
        await db_session.execute(
            select(IncidentReport)
            .where(IncidentReport.guardian_execution_id == execution.id)
            .order_by(IncidentReport.report_version)
        )
    ).scalars().all()

    assert len(all_reports) == 2
    assert all_reports[0].report_version == 1
    assert all_reports[1].report_version == 2


# =============================================================================
# 5. Executive Summary & AI Fallback Tests
# =============================================================================

@pytest.mark.asyncio
async def test_executive_summary_deterministic_fallback(db_session, test_operator, recommendation_topology_fixture):
    """Verifies executive summary produces valid posture metrics and narrative even without GEMINI_API_KEY."""
    fixture = recommendation_topology_fixture
    sandbox = fixture["sandbox"]
    attack_run = fixture["attack_run"]

    orchestrator = GuardianOrchestrationService(db_session)
    from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=attack_run.id,
    )
    execution = await orchestrator.execute_analysis(req, test_operator)

    # Force AI provider with no API key to guarantee fallback testing
    ai_provider = AIEnrichmentProvider(api_key="")
    report_service = IncidentReportService(db_session, ai_provider=ai_provider)

    summary = await report_service.generate_executive_summary(
        execution_id=execution.id,
        sandbox_id=sandbox.id,
    )

    assert summary.posture_rating in ("Critical Risk", "High Risk", "Moderate Risk", "Low Risk / Hardened")
    assert summary.max_risk_score > 0.0
    assert summary.total_detections > 0
    assert summary.total_recommendations > 0
    assert len(summary.executive_summary) > 50
    assert len(summary.immediate_priorities) >= 1
    assert len(summary.residual_risks_and_uncertainties) >= 1
    assert summary.ai_enriched is False


# =============================================================================
# 6. REST API Endpoints & OPA Authorization Tests
# =============================================================================

@pytest.mark.asyncio
async def test_api_playbooks_and_recommendations(
    operator_token: str,
    analyst_token: str,
    viewer_token: str,
    recommendation_topology_fixture: dict,
    db_session,
    test_operator,
):
    """Verifies REST endpoints for playbooks and recommendations with role-based authorization."""
    fixture = recommendation_topology_fixture
    sandbox = fixture["sandbox"]
    attack_run = fixture["attack_run"]

    orchestrator = GuardianOrchestrationService(db_session)
    from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=attack_run.id,
    )
    execution = await orchestrator.execute_analysis(req, test_operator)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        op_headers = {"Authorization": f"Bearer {operator_token}"}
        an_headers = {"Authorization": f"Bearer {analyst_token}"}
        vi_headers = {"Authorization": f"Bearer {viewer_token}"}

        # 1. GET /api/v1/guardian/playbooks
        # Operator: Allowed
        resp = await client.get("/api/v1/guardian/playbooks", headers=op_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 8

        # Analyst: Allowed
        resp_analyst = await client.get("/api/v1/guardian/playbooks", headers=an_headers)
        assert resp_analyst.status_code == 200

        # Viewer: Denied by OPA
        resp_viewer = await client.get("/api/v1/guardian/playbooks", headers=vi_headers)
        assert resp_viewer.status_code == 403

        # 2. GET /api/v1/guardian/executions/{id}/recommendations
        resp_rec = await client.get(
            f"/api/v1/guardian/executions/{execution.id}/recommendations",
            headers=op_headers,
        )
        assert resp_rec.status_code == 200
        rec_data = resp_rec.json()
        assert rec_data["total"] > 0
        first_rec = rec_data["items"][0]

        # 3. GET /api/v1/guardian/recommendations/{id}
        rec_id = first_rec["id"]
        resp_single = await client.get(
            f"/api/v1/guardian/recommendations/{rec_id}",
            headers=op_headers,
        )
        assert resp_single.status_code == 200
        assert resp_single.json()["id"] == rec_id


@pytest.mark.asyncio
async def test_api_remediation_plans_and_reports(
    operator_token: str,
    recommendation_topology_fixture: dict,
    db_session,
    test_operator,
):
    """Verifies REST endpoints for remediation plans, incident reports, and executive summaries."""
    fixture = recommendation_topology_fixture
    sandbox = fixture["sandbox"]
    attack_run = fixture["attack_run"]

    orchestrator = GuardianOrchestrationService(db_session)
    from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=attack_run.id,
    )
    execution = await orchestrator.execute_analysis(req, test_operator)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        op_headers = {"Authorization": f"Bearer {operator_token}"}

        # 1. GET /api/v1/guardian/executions/{id}/remediation-plans
        resp_plans = await client.get(
            f"/api/v1/guardian/executions/{execution.id}/remediation-plans",
            headers=op_headers,
        )
        assert resp_plans.status_code == 200
        plans_data = resp_plans.json()
        assert plans_data["total"] >= 1
        plan_id = plans_data["items"][0]["id"]

        # 2. GET /api/v1/guardian/remediation-plans/{id}
        resp_plan_detail = await client.get(
            f"/api/v1/guardian/remediation-plans/{plan_id}",
            headers=op_headers,
        )
        assert resp_plan_detail.status_code == 200
        assert len(resp_plan_detail.json()["actions"]) > 0

        # 3. GET /api/v1/guardian/executions/{id}/incident-reports
        resp_reports = await client.get(
            f"/api/v1/guardian/executions/{execution.id}/incident-reports",
            headers=op_headers,
        )
        assert resp_reports.status_code == 200
        reports_data = resp_reports.json()
        assert reports_data["total"] >= 1
        report_id = reports_data["items"][0]["id"]

        # 4. GET /api/v1/guardian/incident-reports/{id}
        resp_report_detail = await client.get(
            f"/api/v1/guardian/incident-reports/{report_id}",
            headers=op_headers,
        )
        assert resp_report_detail.status_code == 200
        rep_json = resp_report_detail.json()
        assert "report_content" in rep_json
        assert "observed_facts" in rep_json["report_content"]["epistemic_sections"]

        # 5. POST /api/v1/guardian/executions/{id}/incident-reports/generate
        gen_resp = await client.post(
            f"/api/v1/guardian/executions/{execution.id}/incident-reports/generate",
            headers=op_headers,
            json={"custom_title": "API Generated Forensic Report v2"},
        )
        assert gen_resp.status_code == 200
        assert gen_resp.json()["report_version"] == 2

        # 6. GET /api/v1/guardian/executions/{id}/executive-summary
        summary_resp = await client.get(
            f"/api/v1/guardian/executions/{execution.id}/executive-summary",
            headers=op_headers,
        )
        assert summary_resp.status_code == 200
        summary_data = summary_resp.json()
        assert "posture_rating" in summary_data
        assert "immediate_priorities" in summary_data


# =============================================================================
# 7. Celery Background Worker Task Integration & Audit Logging
# =============================================================================

@pytest.mark.asyncio
async def test_celery_worker_and_audit_trail(db_session, test_operator, recommendation_topology_fixture):
    """Verifies that the Celery worker task runs all stages including recommendations and reports,
    and produces a cryptographically verifiable SHA-256 audit trail.
    """
    fixture = recommendation_topology_fixture
    sandbox = fixture["sandbox"]
    attack_run = fixture["attack_run"]

    # Run background task directly via async helper
    result = await run_guardian_analysis_async(
        sandbox_id=str(sandbox.id),
        user_id=str(test_operator.id),
        attack_run_id=str(attack_run.id),
    )

    assert result["status"] == "completed"
    assert result["recommendations_count"] > 0
    assert result["remediation_plans_count"] > 0
    assert result["incident_reports_count"] > 0

    # Verify SHA-256 chained audit logs
    audit_query = (
        select(AuditLog)
        .where(AuditLog.event_data.op("->>")("sandbox_id") == str(sandbox.id))
        .order_by(AuditLog.created_at)
    )
    logs = (await db_session.execute(audit_query)).scalars().all()
    assert len(logs) >= 5

    event_types = [log.event_type for log in logs]
    assert "guardian.recommendations.started" in event_types
    assert "guardian.recommendation.created" in event_types
    assert "guardian.recommendations.completed" in event_types
    assert "guardian.remediation_plan.created" in event_types
    assert "guardian.incident_report.generated" in event_types

    # Cryptographic hash verification on audit trail
    for log in logs:
        assert verify_event_hash(log) is True
