"""Human Approval Policy and State Machine for Blue Guardian Remediation Plans."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set
import uuid

from app.agents.blue_guardian.approval_schemas import (
    ApprovalPolicyResponse,
    ApprovalPolicyRule,
    ApprovalStatus,
)
from app.models.guardian import ApprovalDecision, ApprovalRequest, RemediationPlan
from app.models.user import User, UserRole

logger = logging.getLogger("aegismesh.guardian.approval_policy")

# Supported strict state transitions
VALID_STATE_TRANSITIONS: Dict[ApprovalStatus, Set[ApprovalStatus]] = {
    ApprovalStatus.DRAFT: {
        ApprovalStatus.PENDING_APPROVAL,
        ApprovalStatus.CANCELLED,
    },
    ApprovalStatus.PENDING_APPROVAL: {
        ApprovalStatus.APPROVED,
        ApprovalStatus.REJECTED,
        ApprovalStatus.CANCELLED,
        ApprovalStatus.EXPIRED,
    },
    ApprovalStatus.APPROVED: {
        ApprovalStatus.EXECUTION_QUEUED,
        ApprovalStatus.CANCELLED,
        ApprovalStatus.EXPIRED,
    },
    ApprovalStatus.EXECUTION_QUEUED: {
        ApprovalStatus.EXECUTING,
        ApprovalStatus.FAILED,
    },
    ApprovalStatus.EXECUTING: {
        ApprovalStatus.VERIFYING,
        ApprovalStatus.FAILED,
    },
    ApprovalStatus.VERIFYING: {
        ApprovalStatus.VERIFIED,
        ApprovalStatus.VERIFICATION_FAILED,
        ApprovalStatus.FAILED,
    },
    # Terminal states have no further transitions
    ApprovalStatus.VERIFIED: set(),
    ApprovalStatus.VERIFICATION_FAILED: set(),
    ApprovalStatus.REJECTED: set(),
    ApprovalStatus.CANCELLED: set(),
    ApprovalStatus.EXPIRED: set(),
    ApprovalStatus.FAILED: set(),
}


@dataclass(frozen=True)
class PolicyTierConfig:
    priority_level: str
    required_approvals: int
    independent_approver_required: bool
    requires_admin_or_senior: bool
    description: str


CURRENT_APPROVAL_POLICY_VERSION = "1.0.0"

POLICY_TIERS: Dict[str, PolicyTierConfig] = {
    "P0": PolicyTierConfig(
        priority_level="P0",
        required_approvals=2,
        independent_approver_required=True,
        requires_admin_or_senior=True,
        description="Critical tier: Requires two distinct authorized approvers including at least one Administrator.",
    ),
    "P1": PolicyTierConfig(
        priority_level="P1",
        required_approvals=2,
        independent_approver_required=True,
        requires_admin_or_senior=False,
        description="High-risk tier: Requires two distinct independent authorized approvers.",
    ),
    "P2": PolicyTierConfig(
        priority_level="P2",
        required_approvals=1,
        independent_approver_required=True,
        requires_admin_or_senior=False,
        description="Medium tier: Requires one independent authorized security approver.",
    ),
    "P3": PolicyTierConfig(
        priority_level="P3",
        required_approvals=1,
        independent_approver_required=False,
        requires_admin_or_senior=False,
        description="Low/Advisory tier: Single authorized approver.",
    ),
}


class ApprovalPolicyEngine:
    """Evaluates four-eyes approval requirements and state machine transitions."""

    version = CURRENT_APPROVAL_POLICY_VERSION

    @classmethod
    def get_tier_for_priority(cls, priority: str) -> PolicyTierConfig:
        normalized = priority.upper().strip()
        return POLICY_TIERS.get(normalized, POLICY_TIERS["P2"])

    @classmethod
    def get_current_policy(cls) -> ApprovalPolicyResponse:
        return ApprovalPolicyResponse(
            policy_version=cls.version,
            name="AegisMesh Multi-Person Four-Eyes Remediation Governance Policy",
            rules=[
                ApprovalPolicyRule(
                    priority_level=tier.priority_level,
                    required_approvals=tier.required_approvals,
                    independent_approver_required=tier.independent_approver_required,
                    requires_admin_or_senior=tier.requires_admin_or_senior,
                    description=tier.description,
                )
                for tier in POLICY_TIERS.values()
            ],
            default_expiry_hours=24,
        )

    @classmethod
    def determine_required_approvals(cls, plan: RemediationPlan) -> int:
        tier = cls.get_tier_for_priority(plan.overall_priority)
        return tier.required_approvals

    @classmethod
    def validate_transition(cls, current_status: str, target_status: ApprovalStatus) -> bool:
        """Validates that a transition from current_status to target_status is permitted."""
        try:
            curr = ApprovalStatus(current_status)
        except ValueError:
            return False

        allowed = VALID_STATE_TRANSITIONS.get(curr, set())
        return target_status in allowed

    @classmethod
    def evaluate_decision_eligibility(
        cls,
        request: ApprovalRequest,
        approver: User,
        plan: RemediationPlan,
        decision: str,
    ) -> tuple[bool, Optional[str]]:
        """Verifies whether an approver is eligible to record a decision on the request."""
        # 1. Status must be PENDING_APPROVAL
        if request.approval_status != ApprovalStatus.PENDING_APPROVAL.value:
            return False, f"Request is in '{request.approval_status}' status; decisions can only be made on PENDING_APPROVAL requests."

        # 2. Check expiration
        now = datetime.now(timezone.utc)
        expires_at = request.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            return False, "Approval request has expired."

        # 3. Check plan version integrity
        if plan.plan_version != request.plan_version:
            return False, f"Remediation plan was modified to version '{plan.plan_version}' after approval request was created (version '{request.plan_version}'). Previous request is invalidated."

        # 4. Check role eligibility
        if approver.role == UserRole.VIEWER:
            return False, "Viewer role is not authorized to approve or reject remediation plans."

        tier = cls.get_tier_for_priority(plan.overall_priority)

        # 5. Prevent self-approval if independent approver is required
        if tier.independent_approver_required and approver.id == request.requested_by:
            return False, f"Four-eyes policy for {plan.overall_priority} requires independent approval; requester cannot approve their own request."

        # 6. Check for duplicate approval by the same user
        existing_approver_ids = {d.approver_id for d in request.decisions}
        if approver.id in existing_approver_ids:
            return False, "User has already submitted a decision on this approval request."

        # 7. Check critical tier requirement (P0 requires at least one admin among approvers)
        if tier.requires_admin_or_senior and decision == "APPROVED":
            # If this is the second approver and the first approver was not an admin, this one must be an admin
            # (or if this is the only approver, they must be admin)
            admin_already_approved = any(
                d.decision == "APPROVED" and getattr(d.approver, "role", None) == UserRole.ADMIN
                for d in request.decisions
            )
            # If this will complete the requirement, verify that at least one admin is present
            if (len(request.decisions) + 1 >= request.required_approvals) and not admin_already_approved:
                if approver.role != UserRole.ADMIN:
                    return False, "Critical tier (P0) requires at least one Administrator approval."

        return True, None

