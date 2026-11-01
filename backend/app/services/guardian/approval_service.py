"""Human Approval Service managing the lifecycle of remediation plan approval requests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple
import uuid

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.agents.blue_guardian.approval_schemas import (
    ApprovalDecisionCreate,
    ApprovalDecisionResponse,
    ApprovalDecisionType,
    ApprovalRequestCreate,
    ApprovalRequestResponse,
    ApprovalStatus,
)
from app.models.guardian import (
    ApprovalDecision,
    ApprovalRequest,
    RemediationPlan,
)
from app.models.user import User, UserRole
from app.security.gateway import authorize_action
from app.services.audit_service import record_audit_log
from app.services.guardian.approval_policy import ApprovalPolicyEngine
from app.services.sandbox_service import get_sandbox_by_id, verify_sandbox_access

logger = logging.getLogger("aegismesh.guardian.approval_service")


class ApprovalService:
    """Orchestrates human-in-the-loop multi-person approval workflows."""

    def __init__(self, session: AsyncSession):
        self.session = session

    def _request_to_response(self, req: ApprovalRequest) -> ApprovalRequestResponse:
        decisions_resp = [
            ApprovalDecisionResponse(
                id=d.id,
                approval_request_id=d.approval_request_id,
                approver_id=d.approver_id,
                decision=d.decision,
                comments=d.comments,
                decided_at=d.decided_at,
            )
            for d in req.decisions
        ]
        approved_count = sum(1 for d in req.decisions if d.decision == "APPROVED")

        return ApprovalRequestResponse(
            id=req.id,
            remediation_plan_id=req.remediation_plan_id,
            sandbox_id=req.sandbox_id,
            plan_version=req.plan_version,
            requested_by=req.requested_by,
            approval_status=req.approval_status,
            required_approvals=req.required_approvals,
            approvals_received=approved_count,
            approval_policy_version=req.approval_policy_version,
            request_comments=req.request_comments,
            expires_at=req.expires_at,
            created_at=req.created_at,
            updated_at=req.updated_at,
            decisions=decisions_resp,
        )

    async def create_request(
        self,
        plan_id: uuid.UUID,
        user: User,
        payload: ApprovalRequestCreate,
    ) -> ApprovalRequestResponse:
        """Submits an existing RemediationPlan for human approval."""
        plan = await self.session.get(RemediationPlan, plan_id)
        if not plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"RemediationPlan '{plan_id}' not found.",
            )

        # Sandbox authorization
        sandbox = await get_sandbox_by_id(self.session, plan.sandbox_id)
        if not sandbox or not verify_sandbox_access(sandbox, user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to target sandbox environment.",
            )

        # OPA Authorization
        decision = await authorize_action(
            user=user,
            operation="guardian.approval_request",
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

        # Check for existing active pending approval request
        existing_res = await self.session.execute(
            select(ApprovalRequest).where(
                ApprovalRequest.remediation_plan_id == plan_id,
                ApprovalRequest.approval_status == ApprovalStatus.PENDING_APPROVAL.value,
            )
        )
        existing_pending = existing_res.scalar_one_or_none()
        if existing_pending:
            # Check if expired
            now = datetime.now(timezone.utc)
            exp = existing_pending.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if now <= exp:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="An active approval request is already pending for this remediation plan.",
                )
            else:
                existing_pending.approval_status = ApprovalStatus.EXPIRED.value
                await self.session.flush()

        # Determine required approvals from four-eyes policy
        required_approvals = ApprovalPolicyEngine.determine_required_approvals(plan)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=payload.expires_in_hours)

        approval_req = ApprovalRequest(
            id=uuid.uuid4(),
            remediation_plan_id=plan.id,
            sandbox_id=plan.sandbox_id,
            plan_version=plan.plan_version,
            requested_by=user.id,
            approval_status=ApprovalStatus.PENDING_APPROVAL.value,
            required_approvals=required_approvals,
            approval_policy_version=ApprovalPolicyEngine.version,
            request_comments=payload.request_comments,
            expires_at=expires_at,
        )
        self.session.add(approval_req)

        # Update remediation plan status
        plan.status = "pending_approval"
        await self.session.flush()

        # Record Audit Event
        try:
            await record_audit_log(
                session=self.session,
                event_type="guardian.approval_requested",
                action="guardian.approval_request",
                resource_type="remediation_plan",
                actor_id=user.id,
                actor_role=user.role,
                resource_id=str(plan.id),
                decision="PENDING",
                event_data={
                    "approval_request_id": str(approval_req.id),
                    "remediation_plan_id": str(plan.id),
                    "sandbox_id": str(plan.sandbox_id),
                    "plan_version": plan.plan_version,
                    "overall_priority": plan.overall_priority,
                    "required_approvals": required_approvals,
                    "expires_at": expires_at.isoformat(),
                },
            )
            await self.session.flush()
        except Exception as e:
            logger.warning("Audit log recording failed for approval request: %s", e)

        await self.session.commit()
        await self.session.refresh(approval_req, ["decisions"])
        return self._request_to_response(approval_req)

    async def record_decision(
        self,
        request_id: uuid.UUID,
        approver: User,
        payload: ApprovalDecisionCreate,
    ) -> ApprovalRequestResponse:
        """Records an approved or rejected decision from an authorized reviewer."""
        # Load request with decisions and approver relationships
        query = (
            select(ApprovalRequest)
            .options(selectinload(ApprovalRequest.decisions).selectinload(ApprovalDecision.approver))
            .where(ApprovalRequest.id == request_id)
        )
        res = await self.session.execute(query)
        req = res.scalar_one_or_none()
        if not req:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"ApprovalRequest '{request_id}' not found.",
            )

        plan = await self.session.get(RemediationPlan, req.remediation_plan_id)
        if not plan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Underlying RemediationPlan not found.",
            )

        # Sandbox authorization
        sandbox = await get_sandbox_by_id(self.session, req.sandbox_id)
        if not sandbox or not verify_sandbox_access(sandbox, approver):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied to target sandbox environment.",
            )

        # OPA Authorization
        decision_opa = await authorize_action(
            user=approver,
            operation="guardian.approval_decide",
            capability="remediation",
            resource_type="approval_request",
            resource_id=str(req.id),
            environment="sandbox",
            session=self.session,
        )
        if not decision_opa.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=decision_opa.reason,
            )

        # Check policy eligibility (self-approval, duplicate approval, expiry, plan modification)
        is_eligible, reason = ApprovalPolicyEngine.evaluate_decision_eligibility(
            request=req,
            approver=approver,
            plan=plan,
            decision=payload.decision.value,
        )
        if not is_eligible:
            # If invalid due to expiry or plan modification, update status
            now = datetime.now(timezone.utc)
            exp = req.expires_at if req.expires_at.tzinfo else req.expires_at.replace(tzinfo=timezone.utc)
            if now > exp or plan.plan_version != req.plan_version:
                req.approval_status = ApprovalStatus.EXPIRED.value
                await self.session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=reason,
            )

        # Record decision record
        decision_record = ApprovalDecision(
            id=uuid.uuid4(),
            approval_request_id=req.id,
            approver_id=approver.id,
            decision=payload.decision.value,
            comments=payload.comments,
        )
        self.session.add(decision_record)
        req.decisions.append(decision_record)

        # Evaluate resulting status
        if payload.decision == ApprovalDecisionType.REJECTED:
            req.approval_status = ApprovalStatus.REJECTED.value
            plan.status = "rejected"
            audit_event = "guardian.approval_rejected"
        else:
            # Count distinct approved decisions
            approved_count = sum(1 for d in req.decisions if d.decision == "APPROVED")
            if approved_count >= req.required_approvals:
                req.approval_status = ApprovalStatus.APPROVED.value
                plan.status = "approved"
                audit_event = "guardian.approval_granted"
            else:
                # Still pending second approval
                audit_event = "guardian.approval_granted"

        await self.session.flush()

        # Record Audit Event
        try:
            await record_audit_log(
                session=self.session,
                event_type=audit_event,
                action="guardian.approval_decide",
                resource_type="approval_request",
                actor_id=approver.id,
                actor_role=approver.role,
                resource_id=str(req.id),
                decision=payload.decision.value,
                event_data={
                    "approval_request_id": str(req.id),
                    "remediation_plan_id": str(plan.id),
                    "decision": payload.decision.value,
                    "comments": payload.comments,
                    "resulting_status": req.approval_status,
                },
            )
            await self.session.flush()
        except Exception as e:
            logger.warning("Audit log recording failed for approval decision: %s", e)

        await self.session.commit()
        await self.session.refresh(req, ["decisions"])
        return self._request_to_response(req)

    async def cancel_request(
        self,
        request_id: uuid.UUID,
        user: User,
        reason: Optional[str] = None,
    ) -> ApprovalRequestResponse:
        """Cancels an active approval request."""
        query = (
            select(ApprovalRequest)
            .options(selectinload(ApprovalRequest.decisions))
            .where(ApprovalRequest.id == request_id)
        )
        res = await self.session.execute(query)
        req = res.scalar_one_or_none()
        if not req:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"ApprovalRequest '{request_id}' not found.",
            )

        # Only requester or admin can cancel
        if user.role != UserRole.ADMIN and user.id != req.requested_by:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the original requester or an Administrator can cancel an approval request.",
            )

        if not ApprovalPolicyEngine.validate_transition(req.approval_status, ApprovalStatus.CANCELLED):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel request in status '{req.approval_status}'.",
            )

        req.approval_status = ApprovalStatus.CANCELLED.value
        plan = await self.session.get(RemediationPlan, req.remediation_plan_id)
        if plan and plan.status == "pending_approval":
            plan.status = "draft"

        await self.session.flush()

        try:
            await record_audit_log(
                session=self.session,
                event_type="guardian.approval_cancelled",
                action="guardian.approval_cancel",
                resource_type="approval_request",
                actor_id=user.id,
                actor_role=user.role,
                resource_id=str(req.id),
                decision="CANCEL",
                event_data={
                    "approval_request_id": str(req.id),
                    "reason": reason,
                },
            )
        except Exception as e:
            logger.warning("Audit logging failed for cancel_request: %s", e)

        await self.session.commit()
        await self.session.refresh(req, ["decisions"])
        return self._request_to_response(req)

    async def get_request(
        self,
        request_id: uuid.UUID,
        user: User,
    ) -> ApprovalRequestResponse:
        """Retrieves an approval request with decisions, checking expiration dynamically."""
        query = (
            select(ApprovalRequest)
            .options(selectinload(ApprovalRequest.decisions))
            .where(ApprovalRequest.id == request_id)
        )
        res = await self.session.execute(query)
        req = res.scalar_one_or_none()
        if not req:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"ApprovalRequest '{request_id}' not found.",
            )

        # Check expiration dynamically
        if req.approval_status == ApprovalStatus.PENDING_APPROVAL.value:
            now = datetime.now(timezone.utc)
            exp = req.expires_at if req.expires_at.tzinfo else req.expires_at.replace(tzinfo=timezone.utc)
            if now > exp:
                req.approval_status = ApprovalStatus.EXPIRED.value
                await self.session.commit()

        return self._request_to_response(req)

    async def list_requests(
        self,
        user: User,
        sandbox_id: Optional[uuid.UUID] = None,
        status_filter: Optional[str] = None,
        plan_id: Optional[uuid.UUID] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Tuple[List[ApprovalRequestResponse], int]:
        """Lists approval requests with filtering and pagination."""
        query = select(ApprovalRequest).options(selectinload(ApprovalRequest.decisions))
        count_query = select(func.count(ApprovalRequest.id))

        if sandbox_id:
            query = query.where(ApprovalRequest.sandbox_id == sandbox_id)
            count_query = count_query.where(ApprovalRequest.sandbox_id == sandbox_id)

        if status_filter:
            query = query.where(ApprovalRequest.approval_status == status_filter.upper())
            count_query = count_query.where(ApprovalRequest.approval_status == status_filter.upper())

        if plan_id:
            query = query.where(ApprovalRequest.remediation_plan_id == plan_id)
            count_query = count_query.where(ApprovalRequest.remediation_plan_id == plan_id)

        total = (await self.session.execute(count_query)).scalar_one()
        query = query.order_by(ApprovalRequest.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        rows = (await self.session.execute(query)).scalars().all()

        now = datetime.now(timezone.utc)
        items: List[ApprovalRequestResponse] = []
        needs_commit = False

        for r in rows:
            if r.approval_status == ApprovalStatus.PENDING_APPROVAL.value:
                exp = r.expires_at if r.expires_at.tzinfo else r.expires_at.replace(tzinfo=timezone.utc)
                if now > exp:
                    r.approval_status = ApprovalStatus.EXPIRED.value
                    needs_commit = True
            items.append(self._request_to_response(r))

        if needs_commit:
            await self.session.commit()

        return items, total

