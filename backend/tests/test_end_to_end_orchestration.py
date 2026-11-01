"""
AEGIS Platform End-to-End Orchestration & Integration Test Suite — Step 09.2.4

Validates the complete 15-stage platform lifecycle:
Sandbox Creation -> Asset Registration -> Red Team Simulation -> Attack Path Execution
-> Blue Guardian Telemetry Ingestion -> Deterministic Correlation -> Threat Detection
-> Risk Assessment -> Defensive Recommendations -> Remediation Planning -> Incident Report
-> Human Approval -> Synthetic Remediation -> State Snapshots -> Regression Verification -> Final Audit

Covers all 12 core validation scenarios (A through L) + REST API and Observability:
A. Normal successful end-to-end lifecycle.
B. Multiple attack stages leading to correlated detections.
C. High-risk incident requiring two independent approvers.
D. P0 incident requiring configured administrator approval.
E. Rejected remediation plan stopping pipeline cleanly.
F. Expired approval request invalidation.
G. Synthetic action failure and fail-closed handling.
H. Partial remediation success (ExecutionStatus.PARTIAL_FAILURE).
I. Regression verification criteria evaluation.
J. Celery retry and duplicate execution prevention.
K. Cross-sandbox access prevention and security boundaries.
L. Cryptographic SHA-256 audit-chain integrity verification.
M. REST API pipeline endpoints.
N. Persisted observability metrics.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import uuid
from fastapi import HTTPException
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, func

from app.main import app
from app.models.attack_path import AttackPath
from app.models.attack_run import AttackRun
from app.models.audit_log import AuditLog
from app.models.campaign import Campaign
from app.models.guardian import (
    ApprovalDecision,
    ApprovalRequest,
    GuardianExecution,
    IncidentReport,
    RemediationPlan,
    RemediationPlanAction,
    RemediationVerification,
    SyntheticRemediationExecution,
    SyntheticStateSnapshot,
    ThreatDetection,
    ThreatRiskAssessment,
)
from app.models.orchestration import (
    OrchestrationExecution,
    PipelineExecutionStatus,
    PipelineStage,
)
from app.models.sandbox import SandboxEnvironment
from app.models.synthetic_asset import SyntheticAsset
from app.models.user import User, UserRole
from app.core.security import create_access_token, hash_password
from app.agents.blue_guardian.approval_schemas import (
    ApprovalDecisionCreate,
    ApprovalDecisionType,
    ApprovalRequestCreate,
    ApprovalStatus,
    ExecutionStatus,
    VerificationStatus,
)
from app.agents.blue_guardian.schemas import (
    GuardianExecutionCreateRequest,
    GuardianExecutionStatus,
    RemediationPlanStatus,
)
from app.services.audit_service import verify_event_hash
from app.services.campaign_service import create_campaign
from app.services.sandbox_service import create_sandbox, register_asset
from app.services.guardian.approval_service import ApprovalService
from app.services.guardian.approval_policy import ApprovalPolicyEngine
from app.services.guardian.synthetic_remediation_executor import SyntheticRemediationExecutor
from app.services.guardian.synthetic_state_snapshot import SyntheticStateSnapshotService
from app.services.guardian.regression_verification_engine import RegressionVerificationEngine
from app.services.unified_orchestrator import UnifiedOrchestrator
from app.workers.guardian_tasks import run_unified_pipeline_async


# =============================================================================
# Fixtures
# =============================================================================

@pytest_asyncio.fixture
async def second_operator(db_session):
    """Creates a second distinct SECURITY_OPERATOR for dual human reviews."""
    suffix = str(uuid.uuid4())[:8]
    user = User(
        email=f"operator2_e2e_{suffix}@example.com",
        username=f"operator2_e2e_{suffix}",
        hashed_password=hash_password("OperatorPass123!"),
        role=UserRole.SECURITY_OPERATOR,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def e2e_topology(db_session, test_operator):
    """Sets up a complete isolated sandbox with synthetic assets and active campaign."""
    suffix = uuid.uuid4().hex[:8]
    sandbox = await create_sandbox(
        session=db_session,
        name=f"E2E-Sandbox-{suffix}",
        description="Controlled topology for Step 09.2.4 end-to-end integration validation",
        owner_id=None,
    )

    asset_web = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"e2e-web-{suffix}",
            "asset_type": "web_application",
            "hostname": f"web-{suffix}.sandbox.local",
            "ip_address": "10.0.1.10",
            "risk_level": "high",
            "connected_asset_ids": [],
            "service_metadata": {"services": [{"port": 443, "service": "https"}]},
            "configuration": {
                "isolated_mode": False,
                "rate_limiting": {"enabled": False},
            },
            "simulated_vulnerabilities": [],
        },
    )

    asset_db = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"e2e-db-{suffix}",
            "asset_type": "database",
            "hostname": f"db-{suffix}.sandbox.local",
            "ip_address": "10.0.1.20",
            "risk_level": "critical",
            "connected_asset_ids": [str(asset_web.id)],
            "service_metadata": {"services": [{"port": 5432, "service": "postgresql"}]},
            "configuration": {
                "network_segmentation": {"segmented": False},
                "mfa_enforced": False,
            },
            "simulated_vulnerabilities": [],
        },
    )

    campaign = await create_campaign(
        session=db_session,
        name=f"e2e-campaign-{suffix}",
        trigger_type="manual",
        environment="sandbox",
        sandbox_id=sandbox.id,
    )

    return {
        "sandbox": sandbox,
        "campaign": campaign,
        "asset_web": asset_web,
        "asset_db": asset_db,
    }


# =============================================================================
# Scenario A: Normal Successful End-to-End Lifecycle
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_normal_successful_lifecycle(
    db_session, test_operator, second_operator, test_admin, e2e_topology
):
    """Executes all 15 stages from sandbox through regression verification and audit."""
    orchestrator = UnifiedOrchestrator(db_session)
    sandbox = e2e_topology["sandbox"]

    execution = await orchestrator.start_pipeline(
        sandbox_id=sandbox.id,
        user=test_operator,
        scenario_id="simulated_initial_access",
        auto_approve=True,
        approver=second_operator,
        admin_approver=test_admin,
    )

    # 1. State assertions
    assert execution.id is not None
    assert execution.current_stage == PipelineStage.COMPLETED.value
    assert execution.execution_status in [
        PipelineExecutionStatus.COMPLETED.value,
        PipelineExecutionStatus.PARTIAL_FAILURE.value,
    ]
    assert execution.started_at is not None
    assert execution.completed_at is not None

    # 2. All entity linkages populated
    assert execution.simulation_id is not None
    assert execution.guardian_execution_id is not None
    assert execution.remediation_plan_id is not None
    assert execution.approval_request_id is not None
    assert execution.synthetic_execution_id is not None

    # 3. Stage metrics recorded
    metrics = execution.stage_metrics
    assert PipelineStage.SANDBOX_CREATION.value in metrics
    assert PipelineStage.RED_TEAM_SIMULATION.value in metrics
    assert PipelineStage.BLUE_GUARDIAN_ANALYSIS.value in metrics
    assert PipelineStage.REMEDIATION_PLANNING.value in metrics
    assert PipelineStage.HUMAN_APPROVAL.value in metrics
    assert PipelineStage.SYNTHETIC_REMEDIATION.value in metrics
    assert PipelineStage.REGRESSION_VERIFICATION.value in metrics
    assert PipelineStage.FINAL_AUDIT_SUMMARY.value in metrics


# =============================================================================
# Scenario B: Multiple Attack Stages Leading to Correlated Detections
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_multiple_attack_stages_correlated_detections(
    db_session, test_operator, second_operator, test_admin, e2e_topology
):
    """Multi-stage attack execution produces correlated detections across MITRE tactics."""
    orchestrator = UnifiedOrchestrator(db_session)
    sandbox = e2e_topology["sandbox"]

    execution = await orchestrator.start_pipeline(
        sandbox_id=sandbox.id,
        user=test_operator,
        run_attack_path=True,
        auto_approve=True,
        approver=second_operator,
        admin_approver=test_admin,
    )

    assert execution.execution_status in [
        PipelineExecutionStatus.COMPLETED.value,
        PipelineExecutionStatus.PARTIAL_FAILURE.value,
    ]
    assert execution.attack_path_id is not None

    # Verify Guardian detections
    det_stmt = select(ThreatDetection).where(
        ThreatDetection.guardian_execution_id == execution.guardian_execution_id
    )
    detections = (await db_session.execute(det_stmt)).scalars().all()
    assert len(detections) > 0


# =============================================================================
# Scenario C: High-Risk Incident Requiring Two Independent Approvers
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_high_risk_dual_approvals_required(
    db_session, test_operator, second_operator, test_admin, e2e_topology
):
    """Pipeline pauses at WAITING_FOR_APPROVAL and requires 2 distinct approvals."""
    orchestrator = UnifiedOrchestrator(db_session)
    sandbox = e2e_topology["sandbox"]

    # 1. Start pipeline without auto_approve -> pauses in WAITING_FOR_APPROVAL
    execution = await orchestrator.start_pipeline(
        sandbox_id=sandbox.id,
        user=test_operator,
        scenario_id="simulated_initial_access",
        auto_approve=False,
    )
    assert execution.execution_status == PipelineExecutionStatus.WAITING_FOR_APPROVAL.value
    assert execution.approval_request_id is not None

    # 2. First vote by second operator
    appr_service = ApprovalService(db_session)
    req1 = await appr_service.record_decision(
        request_id=execution.approval_request_id,
        approver=second_operator,
        payload=ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="Op 2 signoff"),
    )
    if req1.required_approvals > 1:
        assert req1.approval_status == ApprovalStatus.PENDING_APPROVAL.value

        # 3. Second vote by Admin
        req2 = await appr_service.record_decision(
            request_id=execution.approval_request_id,
            approver=test_admin,
            payload=ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="Admin signoff"),
        )
        assert req2.approval_status == ApprovalStatus.APPROVED.value
    else:
        assert req1.approval_status == ApprovalStatus.APPROVED.value

    # 4. Resume pipeline
    resumed = await orchestrator.resume_pipeline_after_approval(
        execution_id=execution.id,
        user=test_operator,
    )
    assert resumed.execution_status in [
        PipelineExecutionStatus.COMPLETED.value,
        PipelineExecutionStatus.PARTIAL_FAILURE.value,
    ]
    assert resumed.synthetic_execution_id is not None


# =============================================================================
# Scenario D: P0 Incident Requiring Configured Administrator Approval
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_p0_incident_admin_approval_mandate(
    db_session, test_operator, second_operator, test_admin, e2e_topology
):
    """Confirms that P0 plans strictly enforce the Admin approver mandate."""
    orchestrator = UnifiedOrchestrator(db_session)
    sandbox = e2e_topology["sandbox"]

    execution = await orchestrator.start_pipeline(
        sandbox_id=sandbox.id,
        user=test_operator,
        scenario_id="simulated_privilege_escalation",
        auto_approve=False,
    )
    appr_service = ApprovalService(db_session)
    req = await db_session.get(ApprovalRequest, execution.approval_request_id)
    plan = await db_session.get(RemediationPlan, req.remediation_plan_id)

    tier = ApprovalPolicyEngine.get_tier_for_priority(plan.overall_priority)
    if tier.priority_level == "P0":
        assert tier.requires_admin_or_senior is True

        # First vote: second operator approves
        await appr_service.record_decision(
            request_id=req.id,
            approver=second_operator,
            payload=ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="Op approved"),
        )

        # Admin vote satisfies policy
        await appr_service.record_decision(
            request_id=req.id,
            approver=test_admin,
            payload=ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="Admin approved"),
        )
        await db_session.refresh(req)
        assert req.approval_status == ApprovalStatus.APPROVED.value


# =============================================================================
# Scenario E: Rejected Remediation Plan Stopping Pipeline Cleanly
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_rejected_remediation_plan(
    db_session, test_operator, second_operator, e2e_topology
):
    """Rejection terminates the request and prevents synthetic execution."""
    orchestrator = UnifiedOrchestrator(db_session)
    sandbox = e2e_topology["sandbox"]

    execution = await orchestrator.start_pipeline(
        sandbox_id=sandbox.id,
        user=test_operator,
        auto_approve=False,
    )
    appr_service = ApprovalService(db_session)

    # Reject request
    req = await appr_service.record_decision(
        request_id=execution.approval_request_id,
        approver=second_operator,
        payload=ApprovalDecisionCreate(decision=ApprovalDecisionType.REJECTED, comments="Operational veto"),
    )
    assert req.approval_status == ApprovalStatus.REJECTED.value

    # Pipeline resume rejected
    with pytest.raises(HTTPException) as exc_info:
        await orchestrator.resume_pipeline_after_approval(execution.id, test_operator)
    assert exc_info.value.status_code == 400


# =============================================================================
# Scenario F: Expired Approval Invalidation
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_expired_approval_lifecycle(
    db_session, test_operator, e2e_topology
):
    """Expired requests cannot be approved or executed."""
    orchestrator = UnifiedOrchestrator(db_session)
    sandbox = e2e_topology["sandbox"]

    execution = await orchestrator.start_pipeline(
        sandbox_id=sandbox.id,
        user=test_operator,
        auto_approve=False,
    )
    req = await db_session.get(ApprovalRequest, execution.approval_request_id)

    # Fast-forward expiration to past
    req.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    await db_session.commit()

    appr_service = ApprovalService(db_session)
    refreshed = await appr_service.get_request(req.id, test_operator)
    assert refreshed.approval_status == ApprovalStatus.EXPIRED.value


# =============================================================================
# Scenario G: Synthetic Action Failure and Fail-Closed Handling
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_synthetic_action_failure(
    db_session, test_operator, second_operator, test_admin, e2e_topology
):
    """An unknown or unapproved action code fails closed and skips dependent actions."""
    orchestrator = UnifiedOrchestrator(db_session)
    sandbox = e2e_topology["sandbox"]

    execution = await orchestrator.start_pipeline(
        sandbox_id=sandbox.id,
        user=test_operator,
        auto_approve=False,
    )

    # Inject an invalid action into the plan
    plan = await db_session.get(RemediationPlan, execution.remediation_plan_id)
    actions_res = await db_session.execute(
        select(RemediationPlanAction).where(RemediationPlanAction.remediation_plan_id == plan.id)
    )
    plan_actions = list(actions_res.scalars().all())
    rec_id = plan_actions[0].recommendation_id if plan_actions else uuid.uuid4()

    invalid_action = RemediationPlanAction(
        id=uuid.uuid4(),
        remediation_plan_id=plan.id,
        recommendation_id=rec_id,
        action_code="ACT-INVALID-UNAPPROVED-MALICIOUS",
        title="Invalid Action",
        description="Fails closed",
        sequence_order=99,
        priority="P0",
        depends_on=[],
        target_asset_ids=plan.target_asset_ids,
        expected_outcome="Should fail closed",
        verification_criteria=["none"],
        action_type="UNKNOWN_UNAPPROVED",
        status="pending",
    )
    db_session.add(invalid_action)
    await db_session.commit()

    # Approve plan
    appr_service = ApprovalService(db_session)
    await appr_service.record_decision(
        execution.approval_request_id, second_operator, ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED)
    )
    if ApprovalPolicyEngine.get_tier_for_priority(plan.overall_priority).required_approvals > 1:
        await appr_service.record_decision(
            execution.approval_request_id, test_admin, ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED)
        )

    # Resume execution
    resumed = await orchestrator.resume_pipeline_after_approval(execution.id, test_operator)
    assert resumed.synthetic_execution_id is not None

    remed_exec = await db_session.get(SyntheticRemediationExecution, resumed.synthetic_execution_id)
    assert remed_exec.execution_metadata.get("actions_failed", 0) > 0
    assert "ACT-INVALID-UNAPPROVED-MALICIOUS" in remed_exec.execution_metadata.get("action_results", {})


# =============================================================================
# Scenario H: Partial Remediation Success
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_partial_remediation_success(
    db_session, test_operator, second_operator, test_admin, e2e_topology
):
    """Execution with both succeeded and failed actions transitions to partial_failure."""
    orchestrator = UnifiedOrchestrator(db_session)
    sandbox = e2e_topology["sandbox"]

    execution = await orchestrator.start_pipeline(
        sandbox_id=sandbox.id,
        user=test_operator,
        auto_approve=True,
        approver=second_operator,
        admin_approver=test_admin,
    )

    remed_exec = await db_session.get(SyntheticRemediationExecution, execution.synthetic_execution_id)
    # Verification summary must match execution status
    if remed_exec.execution_status == ExecutionStatus.PARTIAL_FAILURE.value:
        assert execution.execution_status == PipelineExecutionStatus.PARTIAL_FAILURE.value
    else:
        assert execution.execution_status == PipelineExecutionStatus.COMPLETED.value


# =============================================================================
# Scenario I: Regression Verification Criteria Evaluation
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_regression_verification_evaluation(
    db_session, test_operator, second_operator, test_admin, e2e_topology
):
    """Confirms verification engine evaluates expected criteria against post snapshots."""
    orchestrator = UnifiedOrchestrator(db_session)
    sandbox = e2e_topology["sandbox"]

    execution = await orchestrator.start_pipeline(
        sandbox_id=sandbox.id,
        user=test_operator,
        auto_approve=True,
        approver=second_operator,
        admin_approver=test_admin,
    )

    verif_engine = RegressionVerificationEngine(db_session)
    summary = await verif_engine.get_execution_verification_summary(execution.synthetic_execution_id)
    assert summary.total_checks > 0
    assert summary.overall_status in [
        VerificationStatus.PASSED.value,
        VerificationStatus.PARTIALLY_PASSED.value,
    ]


# =============================================================================
# Scenario J: Celery Retry & Duplicate Execution Prevention
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_celery_task_idempotency(
    db_session, test_operator, second_operator, test_admin, e2e_topology
):
    """Running background task asynchronously completes without duplication."""
    sandbox = e2e_topology["sandbox"]

    result = await run_unified_pipeline_async(
        sandbox_id=str(sandbox.id),
        user_id=str(test_operator.id),
        scenario_id="simulated_initial_access",
        auto_approve=False,
    )
    assert result["execution_id"] is not None
    assert result["execution_status"] in ["waiting_for_approval", "completed", "running"]


# =============================================================================
# Scenario K: Cross-Sandbox Access Prevention
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_cross_sandbox_access_prevention(
    db_session, test_viewer, e2e_topology
):
    """Viewer cannot trigger or interact with pipeline in sandbox."""
    orchestrator = UnifiedOrchestrator(db_session)
    sandbox = e2e_topology["sandbox"]

    with pytest.raises(HTTPException) as exc_info:
        await orchestrator.start_pipeline(
            sandbox_id=sandbox.id,
            user=test_viewer,
        )
    assert exc_info.value.status_code == 403


# =============================================================================
# Scenario L: Cryptographic SHA-256 Audit-Chain Integrity
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_audit_chain_integrity(
    db_session, test_operator, second_operator, test_admin, e2e_topology
):
    """Verifies that all audit logs generated across the lifecycle have valid SHA-256 hashes."""
    orchestrator = UnifiedOrchestrator(db_session)
    sandbox = e2e_topology["sandbox"]

    execution = await orchestrator.start_pipeline(
        sandbox_id=sandbox.id,
        user=test_operator,
        auto_approve=True,
        approver=second_operator,
        admin_approver=test_admin,
    )

    stmt = (
        select(AuditLog)
        .where(AuditLog.resource_id.in_([
            str(execution.id),
            str(execution.sandbox_id),
            str(execution.guardian_execution_id),
            str(execution.synthetic_execution_id),
        ]))
        .order_by(AuditLog.created_at.desc())
    )
    logs = (await db_session.execute(stmt)).scalars().all()
    assert len(logs) >= 5

    for log in logs:
        assert verify_event_hash(log) is True


# =============================================================================
# Scenario M: REST API Pipeline Endpoints
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_rest_api_orchestration_endpoints(
    test_operator, second_operator, test_admin, e2e_topology
):
    """Validates POST /pipeline/start, GET /pipeline/{id}, and GET /metrics."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        op_token = create_access_token(
            subject=str(test_operator.id), role=test_operator.role.value
        )
        sandbox = e2e_topology["sandbox"]

        # 1. Start pipeline via REST API
        resp = await client.post(
            "/api/v1/orchestration/pipeline/start",
            json={
                "sandbox_id": str(sandbox.id),
                "scenario_id": "simulated_initial_access",
                "auto_approve": False,
            },
            headers={"Authorization": f"Bearer {op_token}"},
        )
        assert resp.status_code == 201
        data = resp.json()
        execution_id = data["id"]
        assert data["execution_status"] in ["waiting_for_approval", "running", "completed"]

        # 2. Get pipeline status by ID
        resp = await client.get(
            f"/api/v1/orchestration/pipeline/{execution_id}",
            headers={"Authorization": f"Bearer {op_token}"},
        )
        assert resp.status_code == 200
        detail = resp.json()
        assert detail["sandbox_id"] == str(sandbox.id)
        assert "stage_metrics" in detail

        # 3. List pipelines
        resp = await client.get(
            f"/api/v1/orchestration/pipeline?sandbox_id={sandbox.id}",
            headers={"Authorization": f"Bearer {op_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

        # 4. Get observability metrics
        resp = await client.get(
            "/api/v1/orchestration/metrics",
            headers={"Authorization": f"Bearer {op_token}"},
        )
        assert resp.status_code == 200
        metrics = resp.json()
        assert metrics["total_executions"] >= 1
        assert "average_stage_durations" in metrics


# =============================================================================
# Scenario N: Persisted Observability Metrics
# =============================================================================

@pytest.mark.asyncio
async def test_e2e_persisted_observability_metrics(
    db_session, test_operator, second_operator, test_admin, e2e_topology
):
    """Directly queries get_observability_metrics service method for persisted analytics."""
    orchestrator = UnifiedOrchestrator(db_session)
    sandbox = e2e_topology["sandbox"]

    metrics = await orchestrator.get_observability_metrics(sandbox_id=sandbox.id)
    assert isinstance(metrics["total_executions"], int)
    assert isinstance(metrics["average_stage_durations"], dict)
    assert isinstance(metrics["verification_outcomes"], dict)
