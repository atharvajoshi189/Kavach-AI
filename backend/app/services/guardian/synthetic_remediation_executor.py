"""Synthetic Remediation Executor executing approved mitigation actions inside isolated sandboxes."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.agents.blue_guardian.approval_schemas import (
    ApprovalStatus,
    ExecutionStatus,
    SyntheticRemediationExecutionResponse,
    VerificationStatus,
)
from app.models.guardian import (
    ApprovalRequest,
    RemediationPlan,
    RemediationPlanAction,
    SyntheticRemediationExecution,
)
from app.models.synthetic_asset import SyntheticAsset
from app.models.user import User
from app.security.gateway import authorize_action
from app.services.audit_service import record_audit_log
from app.services.guardian.approval_policy import ApprovalPolicyEngine
from app.services.guardian.regression_verification_engine import RegressionVerificationEngine
from app.services.guardian.synthetic_action_registry import SyntheticActionRegistry
from app.services.guardian.synthetic_state_snapshot import SyntheticStateSnapshotService
from app.services.sandbox_service import get_sandbox_by_id, verify_sandbox_access

logger = logging.getLogger("aegismesh.guardian.remediation_executor")


class SyntheticRemediationExecutor:
    """Executes allowlisted synthetic actions for approved remediation plans with snapshotting and verification."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.snapshot_service = SyntheticStateSnapshotService(session)
        self.verification_engine = RegressionVerificationEngine(session)

    @classmethod
    def execution_to_response(cls, ex: SyntheticRemediationExecution) -> SyntheticRemediationExecutionResponse:
        return SyntheticRemediationExecutionResponse(
            id=ex.id,
            approval_request_id=ex.approval_request_id,
            remediation_plan_id=ex.remediation_plan_id,
            sandbox_id=ex.sandbox_id,
            execution_status=ex.execution_status,
            is_simulated=ex.is_simulated,
            simulation_only=ex.simulation_only,
            started_at=ex.started_at,
            completed_at=ex.completed_at,
            error_summary=ex.error_summary,
            execution_metadata=ex.execution_metadata or {},
            created_at=ex.created_at,
            updated_at=ex.updated_at,
        )

    async def execute_approved_plan(
        self,
        approval_request_id: uuid.UUID,
        user: User,
    ) -> SyntheticRemediationExecution:
        """Executes a fully approved remediation plan within sandbox boundaries."""
        # 1. Load approval request
        approval_req = await self.session.get(ApprovalRequest, approval_request_id)
        if not approval_req:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"ApprovalRequest '{approval_request_id}' not found.",
            )

        # 2. Strict approval status check
        if approval_req.approval_status != ApprovalStatus.APPROVED.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Execution rejected: ApprovalRequest is in '{approval_req.approval_status}' status. Only APPROVED plans can execute.",
            )

        # 3. Load plan and actions
        plan_query = (
            select(RemediationPlan)
            .options(selectinload(RemediationPlan.actions))
            .where(RemediationPlan.id == approval_req.remediation_plan_id)
        )
        plan = (await self.session.execute(plan_query)).scalar_one_or_none()
        if not plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="RemediationPlan not found.",
            )

        # 4. Plan version integrity check
        if plan.plan_version != approval_req.plan_version:
            approval_req.approval_status = ApprovalStatus.EXPIRED.value
            await self.session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Plan version mismatch: The plan was modified after approval. A new approval request must be submitted.",
            )

        # 5. Sandbox boundary validation
        sandbox = await get_sandbox_by_id(self.session, plan.sandbox_id)
        if not sandbox or not verify_sandbox_access(sandbox, user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to target sandbox environment.",
            )

        if sandbox.status == "archived":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target sandbox environment is archived. Cannot execute remediation in archived sandbox.",
            )

        # 6. OPA Authorization
        decision = await authorize_action(
            user=user,
            operation="guardian.synthetic_execute",
            capability="remediation",
            resource_type="remediation_plan",
            resource_id=str(plan.id),
            environment="sandbox",
            session=self.session,
        )
        if not decision.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=decision.reason,
            )

        # 7. Initialize Execution Record
        now = datetime.now(timezone.utc)
        execution = SyntheticRemediationExecution(
            id=uuid.uuid4(),
            approval_request_id=approval_req.id,
            remediation_plan_id=plan.id,
            sandbox_id=plan.sandbox_id,
            execution_status=ExecutionStatus.EXECUTING.value,
            is_simulated=True,
            simulation_only=True,
            started_at=now,
            execution_metadata={
                "requester_id": str(user.id),
                "approval_policy_version": approval_req.approval_policy_version,
                "plan_version": plan.plan_version,
                "actions_total": len(plan.actions),
            },
        )
        self.session.add(execution)

        # Transition approval status
        approval_req.approval_status = ApprovalStatus.EXECUTING.value
        await self.session.flush()

        # Audit execution started
        try:
            await record_audit_log(
                session=self.session,
                event_type="guardian.synthetic_execution.started",
                action="guardian.synthetic_execute",
                resource_type="remediation_execution",
                actor_id=user.id,
                actor_role=user.role,
                resource_id=str(execution.id),
                decision="EXECUTE",
                event_data={
                    "execution_id": str(execution.id),
                    "approval_request_id": str(approval_req.id),
                    "remediation_plan_id": str(plan.id),
                    "sandbox_id": str(plan.sandbox_id),
                    "is_simulated": True,
                },
            )
            await self.session.flush()
        except Exception as e:
            logger.warning("Audit log recording failed for execution start: %s", e)

        # 8. Collect all target asset IDs
        all_target_asset_ids: List[str] = []
        for a in plan.actions:
            for aid in (a.target_asset_ids or []):
                if aid not in all_target_asset_ids:
                    all_target_asset_ids.append(str(aid))

        # 9. Capture BEFORE Snapshot
        before_snapshot = await self.snapshot_service.capture_snapshot(
            execution=execution,
            snapshot_type="BEFORE",
            target_asset_ids=all_target_asset_ids,
            actor_id=user.id,
        )

        # 10. Execute Allowlisted Actions in Sequence
        actions_sorted = sorted(plan.actions, key=lambda a: a.sequence_order)
        successful_actions: List[str] = []
        failed_actions: List[str] = []
        skipped_actions: List[str] = []
        action_results: Dict[str, Any] = {}

        for action in actions_sorted:
            # Check prerequisites / dependencies
            deps = action.depends_on or []
            missing_deps = [
                d for d in deps
                if not any(d == sa or d in sa for sa in successful_actions)
            ]
            if missing_deps:
                action.status = "failed"
                skipped_actions.append(action.action_code)
                action_results[action.action_code] = {
                    "success": False,
                    "skipped": True,
                    "reason": f"Prerequisite action(s) {missing_deps} not completed.",
                }
                continue

            # Resolve handler
            handler = SyntheticActionRegistry.get_handler(action.action_code, action.action_type)
            if not handler:
                action.status = "failed"
                failed_actions.append(action.action_code)
                action_results[action.action_code] = {
                    "success": False,
                    "reason": f"Unknown or unapproved synthetic action code: {action.action_code}",
                }
                try:
                    await record_audit_log(
                        session=self.session,
                        event_type="guardian.synthetic_action.failed",
                        action="guardian.action_execute",
                        resource_type="remediation_action",
                        actor_id=user.id,
                        resource_id=str(action.id),
                        decision="FAIL_CLOSED",
                        event_data={
                            "action_code": action.action_code,
                            "error": "Unapproved action code failed closed",
                        },
                    )
                except Exception:
                    pass
                continue

            # Load target asset models within sandbox
            asset_uuids = []
            for aid in (action.target_asset_ids or []):
                try:
                    asset_uuids.append(uuid.UUID(str(aid)))
                except (ValueError, TypeError):
                    continue

            asset_query = select(SyntheticAsset).where(
                SyntheticAsset.sandbox_id == plan.sandbox_id,
            )
            if asset_uuids:
                asset_query = asset_query.where(SyntheticAsset.id.in_(asset_uuids))

            target_assets = (await self.session.execute(asset_query)).scalars().all()

            # Execute synthetic handler
            try:
                res = handler(action, list(target_assets))
                await self.session.flush()

                if res.success:
                    action.status = "completed"
                    successful_actions.append(action.action_code)
                    action_results[action.action_code] = {
                        "success": True,
                        "applied_changes": res.applied_changes,
                    }
                    try:
                        await record_audit_log(
                            session=self.session,
                            event_type="guardian.synthetic_action.completed",
                            action="guardian.action_execute",
                            resource_type="remediation_action",
                            actor_id=user.id,
                            resource_id=str(action.id),
                            decision="COMPLETED",
                            event_data={
                                "action_code": action.action_code,
                                "target_assets": res.target_asset_ids,
                                "is_simulated": True,
                            },
                        )
                    except Exception:
                        pass
                else:
                    action.status = "failed"
                    failed_actions.append(action.action_code)
                    action_results[action.action_code] = {
                        "success": False,
                        "error": res.error_message,
                    }
            except Exception as act_err:
                action.status = "failed"
                failed_actions.append(action.action_code)
                action_results[action.action_code] = {
                    "success": False,
                    "error": str(act_err),
                }

        # 11. Capture AFTER Snapshot
        after_snapshot = await self.snapshot_service.capture_snapshot(
            execution=execution,
            snapshot_type="AFTER",
            target_asset_ids=all_target_asset_ids,
            actor_id=user.id,
        )

        # 12. Run Regression Verification
        execution.execution_status = ExecutionStatus.VERIFYING.value
        approval_req.approval_status = ApprovalStatus.VERIFYING.value
        await self.session.flush()

        v_summary = await self.verification_engine.verify_execution(
            execution=execution,
            plan=plan,
            actions=actions_sorted,
            before_snapshot=before_snapshot,
            after_snapshot=after_snapshot,
            actor_id=user.id,
        )

        # 13. Evaluate final status
        all_passed = (v_summary.overall_status == VerificationStatus.PASSED.value) and (len(failed_actions) == 0)
        has_partial = (v_summary.passed_checks > 0) and not all_passed

        if all_passed:
            execution.execution_status = ExecutionStatus.COMPLETED.value
            approval_req.approval_status = ApprovalStatus.VERIFIED.value
            plan.status = "executed"
        elif has_partial:
            execution.execution_status = ExecutionStatus.PARTIAL_FAILURE.value
            approval_req.approval_status = ApprovalStatus.VERIFICATION_FAILED.value
            plan.status = "partially_executed"
        else:
            execution.execution_status = ExecutionStatus.FAILED.value
            approval_req.approval_status = ApprovalStatus.FAILED.value
            plan.status = "failed"

        execution.completed_at = datetime.now(timezone.utc)
        execution.execution_metadata = {
            "requester_id": str(user.id),
            "approval_policy_version": approval_req.approval_policy_version,
            "plan_version": plan.plan_version,
            "actions_total": len(plan.actions),
            "actions_executed": len(successful_actions) + len(failed_actions),
            "actions_succeeded": len(successful_actions),
            "actions_failed": len(failed_actions),
            "actions_successful": successful_actions,
            "actions_skipped": skipped_actions,
            "action_results": action_results,
            "verification_status": v_summary.overall_status,
            "verification_summary": {
                "overall_status": v_summary.overall_status,
                "passed_checks": v_summary.passed_checks,
                "failed_checks": v_summary.failed_checks,
                "inconclusive_checks": v_summary.inconclusive_checks,
            },
        }

        # Final audit event
        try:
            await record_audit_log(
                session=self.session,
                event_type="guardian.synthetic_execution.completed",
                action="guardian.synthetic_execute",
                resource_type="remediation_execution",
                actor_id=user.id,
                resource_id=str(execution.id),
                decision=execution.execution_status.upper(),
                event_data={
                    "execution_id": str(execution.id),
                    "status": execution.execution_status,
                    "overall_verification": v_summary.overall_status,
                    "actions_successful_count": len(successful_actions),
                    "actions_failed_count": len(failed_actions),
                    "is_simulated": True,
                },
            )
        except Exception:
            pass

        await self.session.commit()
        await self.session.refresh(execution)
        return execution

