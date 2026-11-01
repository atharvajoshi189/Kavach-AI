"""Pydantic v2 data contracts for Human Approval and Synthetic Regression Verification."""

from __future__ import annotations

from datetime import datetime, timezone
import enum
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ApprovalStatus(str, enum.Enum):
    """Lifecycle states for human approval of a remediation plan."""
    DRAFT = "DRAFT"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTION_QUEUED = "EXECUTION_QUEUED"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


class ApprovalDecisionType(str, enum.Enum):
    """Explicit human approval decision."""
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class VerificationStatus(str, enum.Enum):
    """Outcome of deterministic synthetic regression verification."""
    PASSED = "PASSED"
    PARTIALLY_PASSED = "PARTIALLY_PASSED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ExecutionStatus(str, enum.Enum):
    """Lifecycle statuses for synthetic remediation execution."""
    QUEUED = "queued"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL_FAILURE = "partial_failure"


# =============================================================================
# Request Schemas
# =============================================================================

class ApprovalRequestCreate(BaseModel):
    """Request payload to submit a RemediationPlan for human approval."""
    model_config = ConfigDict(extra="forbid")

    request_comments: Optional[str] = Field(None, max_length=1000, description="Context or justification for approval")
    expires_in_hours: int = Field(24, ge=1, le=168, description="Time until request expires in hours (1-168)")


class ApprovalDecisionCreate(BaseModel):
    """Request payload to register an approval or rejection decision."""
    model_config = ConfigDict(extra="forbid")

    decision: ApprovalDecisionType = Field(default=ApprovalDecisionType.APPROVED, description="APPROVED or REJECTED")
    comments: Optional[str] = Field(None, max_length=2000, description="Mandatory rationale for rejection or remarks for approval")


class ApprovalRequestCancel(BaseModel):
    """Request payload to cancel an active approval request."""
    model_config = ConfigDict(extra="forbid")

    reason: Optional[str] = Field(None, max_length=500, description="Cancellation rationale")


class SyntheticExecutionCreate(BaseModel):
    """Request payload to trigger approved synthetic execution."""
    model_config = ConfigDict(extra="ignore")

    force_sync: bool = Field(False, description="Run synchronously instead of queuing Celery background task")
    async_mode: Optional[bool] = Field(None, description="Run asynchronously via Celery")


# =============================================================================
# Response Schemas
# =============================================================================

class ApprovalDecisionResponse(BaseModel):
    """Individual human approval or rejection decision record."""
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    approval_request_id: UUID
    approver_id: UUID
    decision: str
    comments: Optional[str] = None
    decided_at: datetime


class ApprovalRequestResponse(BaseModel):
    """Complete approval request status and associated human decisions."""
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    remediation_plan_id: UUID
    sandbox_id: UUID
    plan_version: str
    requested_by: UUID
    approval_status: str
    required_approvals: int
    approvals_received: int = 0
    approval_policy_version: str
    request_comments: Optional[str] = None
    expires_at: datetime
    created_at: datetime
    updated_at: datetime
    decisions: List[ApprovalDecisionResponse] = Field(default_factory=list)


class ApprovalRequestListResponse(BaseModel):
    """Paginated collection of approval requests."""
    model_config = ConfigDict(extra="forbid")

    items: List[ApprovalRequestResponse]
    total: int
    page: int = 1
    page_size: int = 50


class ApprovalPolicyRule(BaseModel):
    """Descriptor schema for an approval requirement tier."""
    model_config = ConfigDict(extra="forbid")

    priority_level: str
    required_approvals: int
    independent_approver_required: bool
    requires_admin_or_senior: bool
    description: str


class ApprovalPolicyResponse(BaseModel):
    """Active four-eyes human approval governance policy."""
    model_config = ConfigDict(extra="forbid")

    policy_version: str
    name: str
    rules: List[ApprovalPolicyRule]
    default_expiry_hours: int


class SyntheticRemediationExecutionResponse(BaseModel):
    """State and progress of a synthetic remediation execution."""
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    approval_request_id: UUID
    remediation_plan_id: UUID
    sandbox_id: UUID
    execution_status: str
    is_simulated: bool
    simulation_only: bool
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_summary: Optional[str] = None
    execution_metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class SyntheticRemediationExecutionListResponse(BaseModel):
    """Paginated collection of synthetic remediation executions."""
    model_config = ConfigDict(extra="forbid")

    items: List[SyntheticRemediationExecutionResponse]
    total: int
    page: int = 1
    page_size: int = 50


class SyntheticStateSnapshotResponse(BaseModel):
    """Cryptographically verified before- or after-remediation synthetic state."""
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    execution_id: UUID
    sandbox_id: UUID
    snapshot_type: str
    snapshot_schema_version: str
    snapshot_data: Dict[str, Any]
    integrity_hash: str
    created_at: datetime


class SyntheticSnapshotComparisonResponse(BaseModel):
    """Differential analysis between before and after synthetic state snapshots."""
    model_config = ConfigDict(extra="forbid")

    execution_id: UUID
    before_snapshot: SyntheticStateSnapshotResponse
    after_snapshot: Optional[SyntheticStateSnapshotResponse] = None
    changes_detected: bool
    modified_assets: List[Dict[str, Any]]
    security_improvements: List[str]
    unresolved_risks: List[str]


class RemediationVerificationResponse(BaseModel):
    """Evidence-backed verification check for an executed remediation action."""
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    execution_id: UUID
    remediation_plan_action_id: UUID
    sandbox_id: UUID
    verification_status: str
    expected_condition: str
    actual_condition: str
    before_value: Dict[str, Any]
    after_value: Dict[str, Any]
    evidence_references: Dict[str, Any]
    failure_reason: Optional[str] = None
    verified_at: datetime


class RemediationVerificationSummaryResponse(BaseModel):
    """Comprehensive regression verification result across all plan actions."""
    model_config = ConfigDict(extra="forbid")

    execution_id: UUID
    remediation_plan_id: UUID
    sandbox_id: UUID
    overall_status: str
    total_checks: int
    passed_checks: int
    failed_checks: int
    inconclusive_checks: int
    verifications: List[RemediationVerificationResponse]
