"""SQLAlchemy models for Blue Guardian defensive ingestion and correlation."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym

from app.database.base import Base

if TYPE_CHECKING:
    from app.models.attack_path import AttackPath
    from app.models.attack_run import AttackRun
    from app.models.campaign import Campaign
    from app.models.sandbox import SandboxEnvironment
    from app.models.synthetic_asset import SyntheticAsset
    from app.models.user import User


class GuardianExecution(Base):
    """Execution session coordinating Blue Guardian defensive ingestion and correlation."""

    __tablename__ = "guardian_executions"

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
    attack_run_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_runs.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    attack_path_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_paths.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
        index=True,
    )
    events_ingested: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    correlation_groups_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    threat_detections_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    risk_assessments_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    max_risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    recommendations_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    remediation_plans_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    incident_reports_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
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
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    execution_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
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
    attack_run: Mapped[Optional["AttackRun"]] = relationship("AttackRun")
    attack_path: Mapped[Optional["AttackPath"]] = relationship("AttackPath")
    ingested_events: Mapped[list["DefensiveEventRecord"]] = relationship(
        "DefensiveEventRecord",
        back_populates="guardian_execution",
        passive_deletes="all",
        order_by="DefensiveEventRecord.original_timestamp",
    )
    correlated_groups: Mapped[list["CorrelatedEventGroup"]] = relationship(
        "CorrelatedEventGroup",
        back_populates="guardian_execution",
        passive_deletes="all",
        order_by="CorrelatedEventGroup.earliest_event_timestamp",
    )
    threat_detections: Mapped[list["ThreatDetection"]] = relationship(
        "ThreatDetection",
        back_populates="guardian_execution",
        passive_deletes="all",
        order_by="ThreatDetection.created_at",
    )
    risk_assessments: Mapped[list["ThreatRiskAssessment"]] = relationship(
        "ThreatRiskAssessment",
        back_populates="guardian_execution",
        passive_deletes="all",
        order_by="ThreatRiskAssessment.risk_score.desc()",
    )
    recommendations: Mapped[list["DefensiveRecommendation"]] = relationship(
        "DefensiveRecommendation",
        back_populates="guardian_execution",
        passive_deletes="all",
        order_by="DefensiveRecommendation.created_at",
    )
    remediation_plans: Mapped[list["RemediationPlan"]] = relationship(
        "RemediationPlan",
        back_populates="guardian_execution",
        passive_deletes="all",
        order_by="RemediationPlan.created_at.desc()",
    )
    incident_reports: Mapped[list["IncidentReport"]] = relationship(
        "IncidentReport",
        back_populates="guardian_execution",
        passive_deletes="all",
        order_by="IncidentReport.report_version.desc()",
    )

    def __repr__(self) -> str:
        return f"<GuardianExecution {self.id} (status={self.status}, sandbox={self.sandbox_id})>"


class DefensiveEventRecord(Base):
    """Persisted, immutable defensive event record ingested from synthetic Red Team evidence."""

    __tablename__ = "defensive_event_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    guardian_execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guardian_executions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    source_event_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    attack_run_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_runs.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    campaign_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    attack_path_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("attack_paths.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    scenario_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    source_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("synthetic_assets.id", ondelete="RESTRICT"),
        nullable=True,
    )
    destination_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("synthetic_assets.id", ondelete="RESTRICT"),
        nullable=True,
    )
    event_type: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    original_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    is_simulated: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    simulation_only: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    sha256_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    raw_payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    provenance_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        UniqueConstraint(
            "guardian_execution_id",
            "source_event_id",
            name="uq_defensive_event_exec_source",
        ),
        Index(
            "ix_defensive_events_sandbox_ts",
            "sandbox_id",
            "original_timestamp",
        ),
    )

    # Relationships
    guardian_execution: Mapped["GuardianExecution"] = relationship(
        "GuardianExecution",
        back_populates="ingested_events",
    )
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")
    attack_run: Mapped[Optional["AttackRun"]] = relationship("AttackRun")
    campaign: Mapped[Optional["Campaign"]] = relationship("Campaign")
    attack_path: Mapped[Optional["AttackPath"]] = relationship("AttackPath")
    source_asset: Mapped[Optional["SyntheticAsset"]] = relationship(
        "SyntheticAsset",
        foreign_keys=[source_asset_id],
    )
    destination_asset: Mapped[Optional["SyntheticAsset"]] = relationship(
        "SyntheticAsset",
        foreign_keys=[destination_asset_id],
    )

    def __repr__(self) -> str:
        return f"<DefensiveEventRecord {self.source_event_id} ({self.event_type})>"


class CorrelatedEventGroup(Base):
    """Deterministic cluster of related defensive events representing an attack stage or behavior."""

    __tablename__ = "correlated_event_groups"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    guardian_execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guardian_executions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    campaign_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    stage: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    correlation_basis: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    correlation_rule: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    member_event_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    root_cause_asset_id: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    impacted_asset_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    earliest_event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    latest_event_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    correlation_confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=1.0,
    )
    simulation_only: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    is_simulated: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    group_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        Index(
            "ix_correlated_groups_sandbox_stage",
            "sandbox_id",
            "stage",
        ),
    )

    # Relationships
    guardian_execution: Mapped["GuardianExecution"] = relationship(
        "GuardianExecution",
        back_populates="correlated_groups",
    )
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")
    campaign: Mapped[Optional["Campaign"]] = relationship("Campaign")
    threat_detections: Mapped[list["ThreatDetection"]] = relationship(
        "ThreatDetection",
        back_populates="correlated_group",
        passive_deletes="all",
    )

    def __repr__(self) -> str:
        return f"<CorrelatedEventGroup {self.title} (basis={self.correlation_basis})>"


class ThreatDetection(Base):
    """Structured, evidence-backed threat detection produced by Blue Guardian detection rules."""

    __tablename__ = "threat_detections"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    guardian_execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guardian_executions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    correlated_group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("correlated_event_groups.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    detection_code: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    rule_code: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    rule_version: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="1.0.0",
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    classification: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    confidence_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    mitre_techniques: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    mitre_tactics: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    affected_asset_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    evidence_references: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    detection_rationale: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="new",
        index=True,
    )
    is_simulated: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    simulation_only: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
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

    __table_args__ = (
        UniqueConstraint(
            "guardian_execution_id",
            "rule_code",
            "correlated_group_id",
            name="uq_threat_detection_exec_rule_group",
        ),
        Index(
            "ix_threat_detections_sandbox_severity",
            "sandbox_id",
            "severity",
        ),
        Index(
            "ix_threat_detections_sandbox_classification",
            "sandbox_id",
            "classification",
        ),
    )

    # Relationships
    guardian_execution: Mapped["GuardianExecution"] = relationship(
        "GuardianExecution",
        back_populates="threat_detections",
    )
    correlated_group: Mapped["CorrelatedEventGroup"] = relationship(
        "CorrelatedEventGroup",
        back_populates="threat_detections",
    )
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")
    risk_assessment: Mapped[Optional["ThreatRiskAssessment"]] = relationship(
        "ThreatRiskAssessment",
        back_populates="threat_detection",
        uselist=False,
        passive_deletes="all",
    )
    recommendations: Mapped[list["DefensiveRecommendation"]] = relationship(
        "DefensiveRecommendation",
        back_populates="threat_detection",
        passive_deletes="all",
    )

    # Synonyms
    affected_assets = synonym("affected_asset_ids")
    rule_name = synonym("title")
    detected_at = synonym("created_at")

    def __repr__(self) -> str:
        return f"<ThreatDetection {self.detection_code} ({self.classification}:{self.severity})>"


class ThreatRiskAssessment(Base):
    """Deterministic, multi-dimensional risk assessment computed for a ThreatDetection."""

    __tablename__ = "threat_risk_assessments"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    threat_detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_detections.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    guardian_execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guardian_executions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        index=True,
    )
    risk_category: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    asset_criticality_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    direct_impact_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    blast_radius_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    attack_stage_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    evidence_confidence_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    scoring_formula_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="1.0.0",
    )
    assessment_rationale: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    assessment_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="completed",
        index=True,
    )
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
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
    is_simulated: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    simulation_only: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "guardian_execution_id",
            "threat_detection_id",
            name="uq_risk_assessment_exec_detection",
        ),
        Index(
            "ix_threat_risk_assessments_sandbox_category",
            "sandbox_id",
            "risk_category",
        ),
        Index(
            "ix_threat_risk_assessments_sandbox_score",
            "sandbox_id",
            "risk_score",
        ),
    )

    # Relationships
    threat_detection: Mapped["ThreatDetection"] = relationship(
        "ThreatDetection",
        back_populates="risk_assessment",
    )
    guardian_execution: Mapped["GuardianExecution"] = relationship(
        "GuardianExecution",
        back_populates="risk_assessments",
    )
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")
    asset_impacts: Mapped[list["ThreatAssetImpact"]] = relationship(
        "ThreatAssetImpact",
        back_populates="risk_assessment",
        passive_deletes="all",
        order_by="ThreatAssetImpact.traversal_depth",
    )
    recommendations: Mapped[list["DefensiveRecommendation"]] = relationship(
        "DefensiveRecommendation",
        back_populates="risk_assessment",
        passive_deletes="all",
    )

    # Synonyms and convenience properties
    detection = synonym("threat_detection")
    impacts = synonym("asset_impacts")

    @property
    def directly_affected_count(self) -> int:
        if hasattr(self, "_directly_affected_count"):
            return self._directly_affected_count
        if "asset_impacts" in self.__dict__ and self.asset_impacts is not None:
            return sum(1 for imp in self.asset_impacts if imp.impact_type == "DIRECTLY_AFFECTED")
        return 0

    @property
    def blast_radius_size(self) -> int:
        if hasattr(self, "_blast_radius_size"):
            return self._blast_radius_size
        if "asset_impacts" in self.__dict__ and self.asset_impacts is not None:
            return sum(1 for imp in self.asset_impacts if imp.impact_type == "POTENTIALLY_EXPOSED")
        return 0

    @property
    def critical_asset_exposed(self) -> bool:
        if hasattr(self, "_critical_asset_exposed"):
            return self._critical_asset_exposed
        if "asset_impacts" in self.__dict__ and self.asset_impacts is not None:
            return any(
                getattr(imp, "_is_critical_cached", False)
                or ("asset" in imp.__dict__ and imp.asset and (getattr(imp.asset, "risk_level", None) or "").lower() == "critical")
                for imp in self.asset_impacts
            )
        return False

    @property
    def mitre_tactics(self) -> list[str]:
        if "threat_detection" in self.__dict__ and self.threat_detection and self.threat_detection.mitre_tactics:
            return list(self.threat_detection.mitre_tactics)
        return []

    @property
    def rationale(self) -> dict[str, Any]:
        return {"summary": self.assessment_rationale}

    def __repr__(self) -> str:
        return f"<ThreatRiskAssessment {self.id} (score={self.risk_score:.2f}, cat={self.risk_category})>"


class ThreatAssetImpact(Base):
    """Categorized impact and traversal record for an asset evaluated in a risk assessment."""

    __tablename__ = "threat_asset_impacts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    risk_assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_risk_assessments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("synthetic_assets.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    impact_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )  # DIRECTLY_AFFECTED, POTENTIALLY_EXPOSED, INFERRED_EXPOSURE
    impact_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    traversal_depth: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    relationship_path: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    impact_rationale: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    evidence_references: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "risk_assessment_id",
            "asset_id",
            name="uq_asset_impact_assessment_asset",
        ),
        Index(
            "ix_threat_asset_impacts_sandbox_type",
            "sandbox_id",
            "impact_type",
        ),
    )

    # Relationships
    risk_assessment: Mapped["ThreatRiskAssessment"] = relationship(
        "ThreatRiskAssessment",
        back_populates="asset_impacts",
    )
    asset: Mapped["SyntheticAsset"] = relationship("SyntheticAsset")
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")

    # Convenience properties
    @property
    def hop_distance(self) -> int:
        return self.traversal_depth

    @property
    def exposure_path(self) -> list[str]:
        return list(self.relationship_path or [])

    @property
    def asset_name(self) -> str:
        if hasattr(self, "_asset_name_cached"):
            return self._asset_name_cached
        return self.asset.name if self.asset else "Unknown"

    @property
    def asset_type(self) -> str:
        if hasattr(self, "_asset_type_cached"):
            return self._asset_type_cached
        return self.asset.asset_type if self.asset else "Unknown"

    @property
    def is_critical(self) -> bool:
        if hasattr(self, "_is_critical_cached"):
            return self._is_critical_cached
        return (getattr(self.asset, "risk_level", None) or "").lower() == "critical" if self.asset else False

    def __repr__(self) -> str:
        return f"<ThreatAssetImpact {self.asset_id} ({self.impact_type}, depth={self.traversal_depth})>"


class DefensiveRecommendation(Base):
    """Deterministic, actionable defensive recommendation generated from detections and impact analysis."""

    __tablename__ = "defensive_recommendations"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    guardian_execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guardian_executions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    threat_detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_detections.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    risk_assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_risk_assessments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    recommendation_code: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    priority: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True,
    )
    recommendation_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    playbook_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    playbook_version: Mapped[str] = mapped_column(
        String(16),
        default="1.0.0",
        nullable=False,
    )
    affected_asset_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    evidence_references: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    rationale: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    expected_outcome: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    verification_criteria: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    implementation_complexity: Mapped[str] = mapped_column(
        String(32),
        default="medium",
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="proposed",
        nullable=False,
        index=True,
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
    is_simulated: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    simulation_only: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "guardian_execution_id",
            "threat_detection_id",
            "playbook_id",
            name="uq_defensive_rec_exec_det_playbook",
        ),
    )

    # Relationships
    guardian_execution: Mapped["GuardianExecution"] = relationship(
        "GuardianExecution",
        back_populates="recommendations",
    )
    threat_detection: Mapped["ThreatDetection"] = relationship(
        "ThreatDetection",
        back_populates="recommendations",
    )
    risk_assessment: Mapped["ThreatRiskAssessment"] = relationship(
        "ThreatRiskAssessment",
        back_populates="recommendations",
    )
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")
    plan_actions: Mapped[list["RemediationPlanAction"]] = relationship(
        "RemediationPlanAction",
        back_populates="recommendation",
        passive_deletes="all",
    )

    # Synonyms & convenience
    affected_assets = synonym("affected_asset_ids")

    @property
    def priority_rank(self) -> int:
        mapping = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
        return mapping.get(self.priority.upper(), 99)

    @property
    def is_p0(self) -> bool:
        return self.priority.upper() == "P0"

    def __repr__(self) -> str:
        return f"<DefensiveRecommendation {self.recommendation_code} ({self.priority}:{self.playbook_id})>"


class RemediationPlan(Base):
    """Coordinated remediation plan bundling defensive actions for a Guardian execution."""

    __tablename__ = "remediation_plans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    guardian_execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guardian_executions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    overall_priority: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="draft",
        nullable=False,
        index=True,
    )
    plan_version: Mapped[str] = mapped_column(
        String(16),
        default="1.0.0",
        nullable=False,
    )
    target_asset_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    plan_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
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
    is_simulated: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    simulation_only: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )

    # Relationships
    guardian_execution: Mapped["GuardianExecution"] = relationship(
        "GuardianExecution",
        back_populates="remediation_plans",
    )
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")
    actions: Mapped[list["RemediationPlanAction"]] = relationship(
        "RemediationPlanAction",
        back_populates="remediation_plan",
        cascade="all, delete-orphan",
        order_by="RemediationPlanAction.sequence_order",
    )
    incident_reports: Mapped[list["IncidentReport"]] = relationship(
        "IncidentReport",
        back_populates="remediation_plan",
    )
    approval_requests: Mapped[list["ApprovalRequest"]] = relationship(
        "ApprovalRequest",
        back_populates="remediation_plan",
        cascade="all, delete-orphan",
        order_by="ApprovalRequest.created_at.desc()",
    )

    target_assets = synonym("target_asset_ids")

    @property
    def action_count(self) -> int:
        if "actions" in self.__dict__ and self.actions is not None:
            return len(self.actions)
        return 0

    def __repr__(self) -> str:
        return f"<RemediationPlan {self.id} ({self.overall_priority}:{self.status})>"


class RemediationPlanAction(Base):
    """Specific, ordered mitigation step within a RemediationPlan."""

    __tablename__ = "remediation_plan_actions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    remediation_plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_plans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    recommendation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("defensive_recommendations.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    action_code: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    sequence_order: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
        index=True,
    )
    priority: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    depends_on: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    target_asset_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    expected_outcome: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    verification_criteria: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    action_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        default="pending",
        nullable=False,
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
    remediation_plan: Mapped["RemediationPlan"] = relationship(
        "RemediationPlan",
        back_populates="actions",
    )
    recommendation: Mapped["DefensiveRecommendation"] = relationship(
        "DefensiveRecommendation",
        back_populates="plan_actions",
    )

    plan = synonym("remediation_plan")

    def __repr__(self) -> str:
        return f"<RemediationPlanAction {self.action_code} (seq={self.sequence_order}, status={self.status})>"


class IncidentReport(Base):
    """Immutable, versioned, evidence-backed security incident report."""

    __tablename__ = "incident_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    guardian_execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guardian_executions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    report_version: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    executive_summary: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    threat_classifications: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    max_risk_score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    risk_category: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    affected_asset_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    potentially_exposed_asset_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    blast_radius_nodes_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )
    mitre_techniques: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    event_timeline: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    detection_summaries: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    recommendation_summaries: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    remediation_plan_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_plans.id", ondelete="SET NULL"),
        nullable=True,
    )
    report_content: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    report_status: Mapped[str] = mapped_column(
        String(32),
        default="published",
        nullable=False,
        index=True,
    )
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "guardian_execution_id",
            "report_version",
            name="uq_incident_report_exec_version",
        ),
    )

    # Relationships
    guardian_execution: Mapped["GuardianExecution"] = relationship(
        "GuardianExecution",
        back_populates="incident_reports",
    )
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")
    remediation_plan: Mapped[Optional["RemediationPlan"]] = relationship(
        "RemediationPlan",
        back_populates="incident_reports",
    )

    version = synonym("report_version")
    affected_assets = synonym("affected_asset_ids")
    exposed_assets = synonym("potentially_exposed_asset_ids")

    def __repr__(self) -> str:
        return f"<IncidentReport v{self.report_version} ({self.title})>"


class ApprovalRequest(Base):
    """Human approval request gating execution of a RemediationPlan."""

    __tablename__ = "guardian_approval_requests"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    remediation_plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_plans.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    plan_version: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )
    requested_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    approval_status: Mapped[str] = mapped_column(
        String(32),
        default="PENDING_APPROVAL",
        nullable=False,
        index=True,
    )
    required_approvals: Mapped[int] = mapped_column(
        Integer,
        default=1,
        nullable=False,
    )
    approval_policy_version: Mapped[str] = mapped_column(
        String(16),
        default="1.0.0",
        nullable=False,
    )
    request_comments: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
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
    remediation_plan: Mapped["RemediationPlan"] = relationship(
        "RemediationPlan",
        back_populates="approval_requests",
    )
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")
    requester: Mapped["User"] = relationship("User", foreign_keys=[requested_by])
    decisions: Mapped[list["ApprovalDecision"]] = relationship(
        "ApprovalDecision",
        back_populates="approval_request",
        cascade="all, delete-orphan",
        order_by="ApprovalDecision.decided_at",
    )
    executions: Mapped[list["SyntheticRemediationExecution"]] = relationship(
        "SyntheticRemediationExecution",
        back_populates="approval_request",
    )

    def __repr__(self) -> str:
        return f"<ApprovalRequest {self.id} (status={self.approval_status}, plan={self.remediation_plan_id})>"


class ApprovalDecision(Base):
    """Immutable individual approval decision on an ApprovalRequest."""

    __tablename__ = "guardian_approval_decisions"
    __table_args__ = (
        UniqueConstraint("approval_request_id", "approver_id", name="uq_guardian_approval_request_approver"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    approval_request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guardian_approval_requests.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    approver_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    decision: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )  # APPROVED, REJECTED
    comments: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    approval_request: Mapped["ApprovalRequest"] = relationship(
        "ApprovalRequest",
        back_populates="decisions",
    )
    approver: Mapped["User"] = relationship("User", foreign_keys=[approver_id])

    def __repr__(self) -> str:
        return f"<ApprovalDecision {self.decision} (req={self.approval_request_id}, approver={self.approver_id})>"


class SyntheticRemediationExecution(Base):
    """Execution of approved synthetic remediation handlers in a sandbox."""

    __tablename__ = "synthetic_remediation_executions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    approval_request_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guardian_approval_requests.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    remediation_plan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_plans.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    execution_status: Mapped[str] = mapped_column(
        String(32),
        default="queued",
        nullable=False,
        index=True,
    )  # queued, executing, verifying, completed, failed, partial_failure
    is_simulated: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    simulation_only: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
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
    error_summary: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    execution_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
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
    approval_request: Mapped["ApprovalRequest"] = relationship(
        "ApprovalRequest",
        back_populates="executions",
    )
    remediation_plan: Mapped["RemediationPlan"] = relationship("RemediationPlan")
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")
    snapshots: Mapped[list["SyntheticStateSnapshot"]] = relationship(
        "SyntheticStateSnapshot",
        back_populates="execution",
        cascade="all, delete-orphan",
        order_by="SyntheticStateSnapshot.created_at",
    )
    verifications: Mapped[list["RemediationVerification"]] = relationship(
        "RemediationVerification",
        back_populates="execution",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<SyntheticRemediationExecution {self.id} (status={self.execution_status})>"


class SyntheticStateSnapshot(Base):
    """Immutable pre- and post-remediation synthetic state snapshot."""

    __tablename__ = "synthetic_state_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("synthetic_remediation_executions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    snapshot_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True,
    )  # BEFORE, AFTER
    snapshot_schema_version: Mapped[str] = mapped_column(
        String(16),
        default="1.0.0",
        nullable=False,
    )
    snapshot_data: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    integrity_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    execution: Mapped["SyntheticRemediationExecution"] = relationship(
        "SyntheticRemediationExecution",
        back_populates="snapshots",
    )
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")

    def __repr__(self) -> str:
        return f"<SyntheticStateSnapshot {self.snapshot_type} (exec={self.execution_id})>"


class RemediationVerification(Base):
    """Evidence-backed regression verification check for an executed remediation action."""

    __tablename__ = "remediation_verifications"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    execution_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("synthetic_remediation_executions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    remediation_plan_action_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("remediation_plan_actions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    verification_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )  # PASSED, PARTIALLY_PASSED, FAILED, INCONCLUSIVE
    expected_condition: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    actual_condition: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    before_value: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    after_value: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    evidence_references: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    failure_reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    execution: Mapped["SyntheticRemediationExecution"] = relationship(
        "SyntheticRemediationExecution",
        back_populates="verifications",
    )
    action: Mapped["RemediationPlanAction"] = relationship("RemediationPlanAction")
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")

    def __repr__(self) -> str:
        return f"<RemediationVerification {self.verification_status} (action={self.remediation_plan_action_id})>"




