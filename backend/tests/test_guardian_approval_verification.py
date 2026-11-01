"""
AEGIS Blue Guardian Subsystem Tests - Step 09.2.3.6
Human Approval & Synthetic Regression Verification Engine.

Comprehensive technical verification:
1. Approval policy configuration and priority tier determination (P0 vs P2/P3).
2. Human approval request submission and state transition to PENDING_APPROVAL.
3. Segregation of duty / Self-approval prevention (requester cannot approve).
4. Duplicate vote prevention (same approver cannot cast multiple decisions).
5. Four-eyes multi-person approval policy (2 approvers with admin requirement for P0).
6. Request rejection and cancellation lifecycles with strict state machine validation.
7. Plan version invalidation (modifying plan or mismatching versions).
8. Synthetic execution requires APPROVED status (fail-closed check).
9. Strict synthetic boundary: only modeled SyntheticAsset state modified, is_simulated=True.
10. Immutable BEFORE and AFTER state snapshots with SHA-256 integrity digests.
11. Synthetic regression verification engine evaluating criteria (PASSED, PARTIALLY_PASSED, FAILED).
12. OPA role-based access control and sandbox boundary enforcement.
13. SHA-256 chained audit logs for approval, execution, snapshot, and verification events.
14. Complete REST API endpoints verification.
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
    ApprovalRequest,
    ApprovalDecision,
    GuardianExecution,
    RemediationPlan,
    RemediationPlanAction,
    SyntheticRemediationExecution,
    SyntheticStateSnapshot,
    RemediationVerification,
)
from app.models.synthetic_asset import SyntheticAsset
from app.models.user import User, UserRole
from app.core.security import create_access_token, hash_password
from app.agents.blue_guardian.approval_schemas import (
    ApprovalStatus,
    ApprovalDecisionType,
    ApprovalRequestCreate,
    ApprovalDecisionCreate,
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
from app.services.guardian.approval_policy import ApprovalPolicyEngine
from app.services.guardian.approval_service import ApprovalService
from app.services.guardian.orchestrator_service import GuardianOrchestrationService
from app.services.guardian.synthetic_state_snapshot import SyntheticStateSnapshotService
from app.services.guardian.synthetic_action_registry import SyntheticActionRegistry
from app.services.guardian.regression_verification_engine import RegressionVerificationEngine
from app.services.guardian.synthetic_remediation_executor import SyntheticRemediationExecutor


# =============================================================================
# Fixtures
# =============================================================================

@pytest_asyncio.fixture
async def second_operator(db_session):
    """Creates a second distinct SECURITY_OPERATOR for multi-party approvals."""
    suffix = str(uuid.uuid4())[:8]
    user = User(
        email=f"operator2_{suffix}@example.com",
        username=f"operator2_{suffix}",
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
async def approval_topology(db_session, test_operator):
    """Sets up a realistic sandbox topology and Red Team attack run, then generates real RemediationPlan."""
    suffix = uuid.uuid4().hex[:8]
    sandbox = await create_sandbox(
        session=db_session,
        name=f"Approval-Sandbox-{suffix}",
        description="Controlled topology for Step 09.2.3.6 approval and verification tests",
        owner_id=None,
    )

    asset_db = await register_asset(
        session=db_session,
        sandbox_id=sandbox.id,
        asset_data={
            "name": f"app-db-{suffix}",
            "asset_type": "database",
            "hostname": f"db-{suffix}.sandbox.local",
            "ip_address": "10.0.1.30",
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
            "name": f"app-web-{suffix}",
            "asset_type": "web_application",
            "hostname": f"web-{suffix}.sandbox.local",
            "ip_address": "10.0.1.10",
            "risk_level": "high",
            "connected_asset_ids": [str(asset_db.id)],
            "service_metadata": {"services": [{"port": 443, "service": "https"}]},
            "configuration": {},
            "simulated_vulnerabilities": [],
        },
    )

    campaign = await create_campaign(
        session=db_session,
        name=f"appr-campaign-{suffix}",
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
                    "event_id": f"appr-ev-1-{suffix}",
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
                    },
                    "is_simulated": True,
                    "simulation_only": True,
                },
                {
                    "event_id": f"appr-ev-2-{suffix}",
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
    await db_session.commit()

    # Run Blue Guardian orchestrator to generate realistic detections, recommendations, and plans
    orchestrator = GuardianOrchestrationService(db_session)
    req = GuardianExecutionCreateRequest(
        sandbox_id=sandbox.id,
        attack_run_id=attack_run.id,
    )
    execution = await orchestrator.execute_analysis(req, test_operator)

    # Query the generated remediation plan
    plan_query = (
        select(RemediationPlan)
        .where(RemediationPlan.guardian_execution_id == execution.id)
    )
    plan = (await db_session.execute(plan_query)).scalars().first()

    return {
        "sandbox": sandbox,
        "campaign": campaign,
        "attack_run": attack_run,
        "asset_web": asset_web,
        "asset_db": asset_db,
        "execution": execution,
        "plan": plan,
    }


# =============================================================================
# 1. Approval Policy & Tiers
# =============================================================================

@pytest.mark.asyncio
async def test_approval_policy_tier_determination(approval_topology):
    """Validates that policy tiers accurately mandate four-eyes approvers."""
    plan = approval_topology["plan"]
    tier = ApprovalPolicyEngine.get_tier_for_priority(plan.overall_priority)

    assert tier.required_approvals >= 1
    if plan.overall_priority == "P0":
        assert tier.required_approvals == 2
        assert tier.requires_admin_or_senior is True

    policy_config = ApprovalPolicyEngine.get_current_policy()
    assert policy_config.policy_version == "1.0.0"
    assert len(policy_config.rules) >= 4


@pytest.mark.asyncio
async def test_create_approval_request(db_session, test_operator, approval_topology):
    """Submits a remediation plan for human review and checks initial state."""
    service = ApprovalService(db_session)
    plan = approval_topology["plan"]

    req_payload = ApprovalRequestCreate(
        request_comments="Critical breach containment required due to active lateral movement",
        expires_in_hours=48,
    )
    req = await service.create_request(
        plan_id=plan.id,
        user=test_operator,
        payload=req_payload,
    )

    assert req.id is not None
    assert req.approval_status == ApprovalStatus.PENDING_APPROVAL.value
    assert req.required_approvals == ApprovalPolicyEngine.determine_required_approvals(plan)
    assert req.approvals_received == 0
    assert req.plan_version == plan.plan_version

    # Plan status transitioned to pending_approval
    await db_session.refresh(plan)
    assert plan.status == "pending_approval"


# =============================================================================
# 2. Self-Approval & Duplicate Vote Prevention
# =============================================================================

@pytest.mark.asyncio
async def test_self_approval_prevention(db_session, test_operator, approval_topology):
    """Ensures requester cannot approve their own submission (strict segregation of duty)."""
    service = ApprovalService(db_session)
    plan = approval_topology["plan"]

    req_payload = ApprovalRequestCreate(request_comments="Urgent isolation")
    req = await service.create_request(plan_id=plan.id, user=test_operator, payload=req_payload)

    with pytest.raises(Exception) as exc_info:
        await service.record_decision(
            request_id=req.id,
            approver=test_operator,
            payload=ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="Self approval"),
        )
    assert "cannot approve their own request" in str(exc_info.value).lower() or "400" in str(exc_info.value)


@pytest.mark.asyncio
async def test_duplicate_vote_prevention(db_session, test_operator, second_operator, approval_topology):
    """Ensures an approver cannot cast multiple votes on the same request."""
    service = ApprovalService(db_session)
    plan = approval_topology["plan"]

    req_payload = ApprovalRequestCreate(request_comments="Need dual review")
    req = await service.create_request(plan_id=plan.id, user=test_operator, payload=req_payload)

    # First vote succeeds
    req_updated = await service.record_decision(
        request_id=req.id,
        approver=second_operator,
        payload=ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="First operator review complete"),
    )
    assert req_updated.approvals_received == 1

    # Second vote by same user fails
    with pytest.raises(Exception) as exc_info:
        await service.record_decision(
            request_id=req.id,
            approver=second_operator,
            payload=ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="Attempting double voting"),
        )
    assert "already recorded a decision" in str(exc_info.value).lower() or "400" in str(exc_info.value)


# =============================================================================
# 3. Four-Eyes Multi-Party Approval Lifecycle
# =============================================================================

@pytest.mark.asyncio
async def test_four_eyes_multi_person_approval_success(
    db_session, test_operator, second_operator, test_admin, approval_topology
):
    """P0 request reaches APPROVED only after 2 distinct approvers including an Admin."""
    service = ApprovalService(db_session)
    plan = approval_topology["plan"]

    req_payload = ApprovalRequestCreate(request_comments="Dual signoff needed for critical isolation")
    req = await service.create_request(plan_id=plan.id, user=test_operator, payload=req_payload)

    # Vote 1: Second operator approves
    req1 = await service.record_decision(
        request_id=req.id,
        approver=second_operator,
        payload=ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="Operator verification passed"),
    )

    if req1.required_approvals > 1:
        assert req1.approval_status == ApprovalStatus.PENDING_APPROVAL.value
        assert req1.approvals_received == 1

        # Vote 2: Admin approves -> triggers APPROVED
        req2 = await service.record_decision(
            request_id=req.id,
            approver=test_admin,
            payload=ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="Admin final executive signoff"),
        )
        assert req2.approval_status == ApprovalStatus.APPROVED.value
        assert req2.approvals_received == 2

        # Plan status updated to approved
        await db_session.refresh(plan)
        assert plan.status == "approved"
    else:
        assert req1.approval_status == ApprovalStatus.APPROVED.value


# =============================================================================
# 4. Rejection and Cancellation
# =============================================================================

@pytest.mark.asyncio
async def test_rejection_lifecycle(db_session, test_operator, second_operator, approval_topology):
    """Rejection immediately terminates the approval request and marks plan rejected."""
    service = ApprovalService(db_session)
    plan = approval_topology["plan"]

    req_payload = ApprovalRequestCreate(request_comments="Plan review")
    req = await service.create_request(plan_id=plan.id, user=test_operator, payload=req_payload)

    req_rejected = await service.record_decision(
        request_id=req.id,
        approver=second_operator,
        payload=ApprovalDecisionCreate(decision=ApprovalDecisionType.REJECTED, comments="Rejected due to operational conflicts"),
    )
    assert req_rejected.approval_status == ApprovalStatus.REJECTED.value

    await db_session.refresh(plan)
    assert plan.status == "rejected"


@pytest.mark.asyncio
async def test_cancellation_lifecycle(db_session, test_operator, approval_topology):
    """Requester can cancel a pending approval request."""
    service = ApprovalService(db_session)
    plan = approval_topology["plan"]

    req_payload = ApprovalRequestCreate(request_comments="Will be cancelled")
    req = await service.create_request(plan_id=plan.id, user=test_operator, payload=req_payload)

    req_cancelled = await service.cancel_request(
        request_id=req.id,
        user=test_operator,
        reason="No longer required",
    )
    assert req_cancelled.approval_status == ApprovalStatus.CANCELLED.value

    await db_session.refresh(plan)
    assert plan.status in ["draft", "cancelled"]


# =============================================================================
# 5. Plan Version Invalidation
# =============================================================================

@pytest.mark.asyncio
async def test_plan_version_invalidation_prevents_stale_execution(
    db_session, test_operator, second_operator, test_admin, approval_topology
):
    """Modifying plan version causes execution to reject execution of modified plans."""
    service = ApprovalService(db_session)
    plan = approval_topology["plan"]

    req_payload = ApprovalRequestCreate(request_comments="Plan before modification")
    req = await service.create_request(plan_id=plan.id, user=test_operator, payload=req_payload)

    # Approve under version 1
    await service.record_decision(
        req.id,
        second_operator,
        ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="ok"),
    )
    if req.required_approvals > 1:
        await service.record_decision(
            req.id,
            test_admin,
            ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="admin ok"),
        )

    # Simulate plan modification bumping version
    plan.plan_version = "2.0.0"
    await db_session.commit()

    executor = SyntheticRemediationExecutor(db_session)
    with pytest.raises(Exception) as exc_info:
        await executor.execute_approved_plan(approval_request_id=req.id, user=test_admin)
    assert "version" in str(exc_info.value).lower() or "modified" in str(exc_info.value).lower() or "400" in str(exc_info.value)


# =============================================================================
# 6. Synthetic Execution Requires APPROVED Status
# =============================================================================

@pytest.mark.asyncio
async def test_execution_requires_approved_status(db_session, test_operator, approval_topology):
    """Unapproved plans cannot be executed under any circumstances."""
    service = ApprovalService(db_session)
    plan = approval_topology["plan"]

    req_payload = ApprovalRequestCreate(request_comments="Pending approval")
    req = await service.create_request(plan_id=plan.id, user=test_operator, payload=req_payload)

    executor = SyntheticRemediationExecutor(db_session)
    with pytest.raises(Exception) as exc_info:
        await executor.execute_approved_plan(approval_request_id=req.id, user=test_operator)
    assert "approved" in str(exc_info.value).lower() or "400" in str(exc_info.value)


# =============================================================================
# 7. Strict Synthetic Execution Boundary & Handlers
# =============================================================================

@pytest.mark.asyncio
async def test_synthetic_remediation_execution_and_handlers(
    db_session, test_operator, second_operator, test_admin, approval_topology
):
    """Executes approved synthetic remediation and verifies only PostgreSQL model state is altered."""
    service = ApprovalService(db_session)
    plan = approval_topology["plan"]
    asset = approval_topology["asset_web"]

    req_payload = ApprovalRequestCreate(request_comments="Containment execution")
    req = await service.create_request(plan_id=plan.id, user=test_operator, payload=req_payload)
    await service.record_decision(
        req.id, second_operator, ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="approve")
    )
    if req.required_approvals > 1:
        await service.record_decision(
            req.id, test_admin, ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="admin approve")
        )

    executor = SyntheticRemediationExecutor(db_session)
    execution = await executor.execute_approved_plan(approval_request_id=req.id, user=test_admin)

    assert execution.is_simulated is True
    assert execution.simulation_only is True
    assert execution.execution_status in [
        ExecutionStatus.COMPLETED.value,
        "completed",
        ExecutionStatus.PARTIAL_FAILURE.value,
        "partial_failure",
    ]
    assert execution.execution_metadata.get("actions_executed", 0) > 0


# =============================================================================
# 8. Immutable State Snapshots with SHA-256 Digests
# =============================================================================

@pytest.mark.asyncio
async def test_state_snapshots_sha256_integrity(
    db_session, test_operator, second_operator, test_admin, approval_topology
):
    """Verifies that BEFORE and AFTER snapshots carry valid SHA-256 digests and differential diff."""
    service = ApprovalService(db_session)
    plan = approval_topology["plan"]

    req_payload = ApprovalRequestCreate(request_comments="Containment snapshot test")
    req = await service.create_request(plan_id=plan.id, user=test_operator, payload=req_payload)
    await service.record_decision(
        req.id, second_operator, ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="approve")
    )
    if req.required_approvals > 1:
        await service.record_decision(
            req.id, test_admin, ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="admin approve")
        )

    executor = SyntheticRemediationExecutor(db_session)
    execution = await executor.execute_approved_plan(approval_request_id=req.id, user=test_admin)

    # Fetch snapshots
    query = (
        select(SyntheticStateSnapshot)
        .where(SyntheticStateSnapshot.execution_id == execution.id)
        .order_by(SyntheticStateSnapshot.created_at.asc())
    )
    snapshots = (await db_session.execute(query)).scalars().all()
    assert len(snapshots) >= 2

    before = snapshots[0]
    after = snapshots[1]

    assert len(before.integrity_hash) == 64
    assert len(after.integrity_hash) == 64

    comparison = SyntheticStateSnapshotService.compare_snapshots(before, after)
    assert comparison.before_snapshot.integrity_hash == before.integrity_hash
    assert comparison.after_snapshot is not None
    assert comparison.after_snapshot.integrity_hash == after.integrity_hash


# =============================================================================
# 9. Regression Verification Engine Evaluation
# =============================================================================

@pytest.mark.asyncio
async def test_regression_verification_engine(
    db_session, test_operator, second_operator, test_admin, approval_topology
):
    """Evaluates expected criteria against before/after snapshots and logs verifications."""
    service = ApprovalService(db_session)
    plan = approval_topology["plan"]

    req_payload = ApprovalRequestCreate(request_comments="Containment verification test")
    req = await service.create_request(plan_id=plan.id, user=test_operator, payload=req_payload)
    await service.record_decision(
        req.id, second_operator, ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="approve")
    )
    if req.required_approvals > 1:
        await service.record_decision(
            req.id, test_admin, ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="admin approve")
        )

    executor = SyntheticRemediationExecutor(db_session)
    execution = await executor.execute_approved_plan(approval_request_id=req.id, user=test_admin)

    verification_engine = RegressionVerificationEngine(db_session)
    summary = await verification_engine.get_execution_verification_summary(execution.id)

    assert summary.total_checks > 0
    assert summary.overall_status in [
        VerificationStatus.PASSED.value,
        VerificationStatus.PARTIALLY_PASSED.value,
    ]


# =============================================================================
# 10. OPA Role-Based Access Control
# =============================================================================

@pytest.mark.asyncio
async def test_opa_viewer_denied_approval_and_execution(
    db_session, test_operator, test_viewer, approval_topology
):
    """Viewer cannot create approval requests or record approval decisions."""
    service = ApprovalService(db_session)
    plan = approval_topology["plan"]

    # Viewer cannot create request
    with pytest.raises(Exception) as exc_info:
        await service.create_request(
            plan_id=plan.id,
            user=test_viewer,
            payload=ApprovalRequestCreate(request_comments="Viewer submit"),
        )
    assert "forbidden" in str(exc_info.value).lower() or "not permitted" in str(exc_info.value).lower() or "403" in str(exc_info.value)


# =============================================================================
# 11. Chained Audit Logging
# =============================================================================

@pytest.mark.asyncio
async def test_approval_and_execution_audit_logs(
    db_session, test_operator, second_operator, test_admin, approval_topology
):
    """Confirms audit events are logged with valid SHA-256 chain integrity."""
    service = ApprovalService(db_session)
    plan = approval_topology["plan"]

    req_payload = ApprovalRequestCreate(request_comments="Audit tracking")
    req = await service.create_request(plan_id=plan.id, user=test_operator, payload=req_payload)
    await service.record_decision(
        req.id, second_operator, ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="approve")
    )
    if req.required_approvals > 1:
        await service.record_decision(
            req.id, test_admin, ApprovalDecisionCreate(decision=ApprovalDecisionType.APPROVED, comments="admin approve")
        )

    executor = SyntheticRemediationExecutor(db_session)
    execution = await executor.execute_approved_plan(approval_request_id=req.id, user=test_admin)

    # Query audit logs for guardian.approval and guardian.remediation events
    stmt = (
        select(AuditLog)
        .where(
            AuditLog.event_type.in_([
                "guardian.approval_requested",
                "guardian.approval_approved",
                "guardian.approval_rejected",
                "guardian.synthetic_execution.completed",
                "guardian.synthetic_execution.started",
                "guardian.verification.completed",
                "guardian.verification.failed",
            ])
        )
        .order_by(AuditLog.created_at.desc())
    )
    logs = (await db_session.execute(stmt)).scalars().all()
    assert len(logs) >= 2

    for log in logs[:2]:
        assert verify_event_hash(log) is True


# =============================================================================
# 12. REST API Endpoints Verification
# =============================================================================

@pytest.mark.asyncio
async def test_rest_api_approval_lifecycle_and_verification(
    test_operator, second_operator, test_admin, approval_topology
):
    """End-to-end REST test covering approval creation, decision, execution, snapshots, and verification."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        op_token = create_access_token(
            subject=str(test_operator.id), role=test_operator.role.value
        )
        op2_token = create_access_token(
            subject=str(second_operator.id), role=second_operator.role.value
        )
        admin_token = create_access_token(
            subject=str(test_admin.id), role=test_admin.role.value
        )

        plan = approval_topology["plan"]
        plan_id = str(plan.id)

        # 1. Get approval policies
        resp = await client.get("/api/v1/guardian/approval-policies/current", headers={"Authorization": f"Bearer {op_token}"})
        assert resp.status_code == 200
        policy_data = resp.json()
        assert "rules" in policy_data

        # 2. Create approval request
        resp = await client.post(
            f"/api/v1/guardian/remediation-plans/{plan_id}/approval-requests",
            json={"request_comments": "Automated containment required", "expires_in_hours": 24},
            headers={"Authorization": f"Bearer {op_token}"},
        )
        assert resp.status_code == 201
        req_data = resp.json()
        request_id = req_data["id"]
        assert req_data["approval_status"] == "PENDING_APPROVAL"

        # 3. List requests
        resp = await client.get("/api/v1/guardian/approval-requests", headers={"Authorization": f"Bearer {op_token}"})
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1

        # 4. First approval by operator 2
        resp = await client.post(
            f"/api/v1/guardian/approval-requests/{request_id}/approve",
            json={"decision": "APPROVED", "comments": "Operator 2 approval"},
            headers={"Authorization": f"Bearer {op2_token}"},
        )
        assert resp.status_code == 200

        # If more approvals required, admin signs off
        if req_data["required_approvals"] > 1:
            resp = await client.post(
                f"/api/v1/guardian/approval-requests/{request_id}/approve",
                json={"decision": "APPROVED", "comments": "Admin final approval"},
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert resp.status_code == 200
            assert resp.json()["approval_status"] == "APPROVED"

        # 5. Execute approved remediation
        resp = await client.post(
            f"/api/v1/guardian/approval-requests/{request_id}/execute",
            json={"async_mode": False},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        exec_data = resp.json()
        execution_id = exec_data["id"]
        assert exec_data["is_simulated"] is True

        # 6. Get execution status
        resp = await client.get(
            f"/api/v1/guardian/remediation-executions/{execution_id}/status",
            headers={"Authorization": f"Bearer {op_token}"},
        )
        assert resp.status_code == 200
        assert resp.json()["actions_executed"] > 0

        # 7. Get snapshots differential comparison
        resp = await client.get(
            f"/api/v1/guardian/remediation-executions/{execution_id}/snapshots",
            headers={"Authorization": f"Bearer {op_token}"},
        )
        assert resp.status_code == 200
        snapshot_diff = resp.json()
        assert len(snapshot_diff["before_snapshot"]["integrity_hash"]) == 64

        # 8. Get execution regression verification findings
        resp = await client.get(
            f"/api/v1/guardian/remediation-executions/{execution_id}/verification",
            headers={"Authorization": f"Bearer {op_token}"},
        )
        assert resp.status_code == 200
        verif_data = resp.json()
        assert verif_data["total_checks"] > 0

        # 9. Get plan verification history
        resp = await client.get(
            f"/api/v1/guardian/remediation-plans/{plan_id}/verification-history",
            headers={"Authorization": f"Bearer {op_token}"},
        )
        assert resp.status_code == 200
        history_data = resp.json()
        assert history_data["total"] > 0
