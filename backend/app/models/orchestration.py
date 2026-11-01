"""SQLAlchemy model representing an end-to-end unified orchestration lifecycle execution."""

from __future__ import annotations

from datetime import datetime, timezone
import enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

if TYPE_CHECKING:
    from app.models.attack_path import AttackPath
    from app.models.attack_run import AttackRun
    from app.models.campaign import Campaign
    from app.models.guardian import (
        ApprovalRequest,
        GuardianExecution,
        RemediationPlan,
        RemediationVerification,
        SyntheticRemediationExecution,
    )
    from app.models.sandbox import SandboxEnvironment


class PipelineStage(str, enum.Enum):
    """Discrete sequential stages across the unified AegisMesh platform lifecycle."""
    INITIATED = "INITIATED"
    SANDBOX_CREATION = "SANDBOX_CREATION"
    ASSET_REGISTRATION = "ASSET_REGISTRATION"
    RED_TEAM_SIMULATION = "RED_TEAM_SIMULATION"
    ATTACK_PATH_EXECUTION = "ATTACK_PATH_EXECUTION"
    BLUE_GUARDIAN_ANALYSIS = "BLUE_GUARDIAN_ANALYSIS"
    THREAT_DETECTION = "THREAT_DETECTION"
    RISK_ASSESSMENT = "RISK_ASSESSMENT"
    DEFENSIVE_RECOMMENDATIONS = "DEFENSIVE_RECOMMENDATIONS"
    REMEDIATION_PLANNING = "REMEDIATION_PLANNING"
    INCIDENT_REPORT = "INCIDENT_REPORT"
    HUMAN_APPROVAL = "HUMAN_APPROVAL"
    SYNTHETIC_REMEDIATION = "SYNTHETIC_REMEDIATION"
    STATE_SNAPSHOTS = "STATE_SNAPSHOTS"
    REGRESSION_VERIFICATION = "REGRESSION_VERIFICATION"
    FINAL_AUDIT_SUMMARY = "FINAL_AUDIT_SUMMARY"
    COMPLETED = "COMPLETED"


class PipelineExecutionStatus(str, enum.Enum):
    """Durable lifecycle execution state for unified orchestration."""
    PENDING = "pending"
    RUNNING = "running"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL_FAILURE = "partial_failure"
    CANCELLED = "cancelled"


class OrchestrationExecution(Base):
    """Persisted end-to-end execution record tracking the complete platform lifecycle."""

    __tablename__ = "orchestration_executions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    campaign_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    simulation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    attack_path_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_paths.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    guardian_execution_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guardian_executions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    remediation_plan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_plans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    approval_request_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guardian_approval_requests.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    synthetic_execution_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("synthetic_remediation_executions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    verification_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_verifications.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    current_stage: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default=PipelineStage.INITIATED.value,
        index=True,
    )
    execution_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=PipelineExecutionStatus.PENDING.value,
        index=True,
    )
    failed_stage: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    retry_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    is_resumable: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )

    stage_metrics: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    execution_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")
    campaign: Mapped[Optional["Campaign"]] = relationship("Campaign")
    attack_run: Mapped[Optional["AttackRun"]] = relationship("AttackRun")
    attack_path: Mapped[Optional["AttackPath"]] = relationship("AttackPath")
    guardian_execution: Mapped[Optional["GuardianExecution"]] = relationship("GuardianExecution")
    remediation_plan: Mapped[Optional["RemediationPlan"]] = relationship("RemediationPlan")
    approval_request: Mapped[Optional["ApprovalRequest"]] = relationship("ApprovalRequest")
    synthetic_execution: Mapped[Optional["SyntheticRemediationExecution"]] = relationship("SyntheticRemediationExecution")
    verification: Mapped[Optional["RemediationVerification"]] = relationship("RemediationVerification")

    def __repr__(self) -> str:
        return f"<OrchestrationExecution {self.id} (stage={self.current_stage}, status={self.execution_status})>"

