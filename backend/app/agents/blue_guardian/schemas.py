"""Pydantic v2 data contracts for Blue Guardian Event Ingestion and Correlation."""

from __future__ import annotations

from datetime import datetime, timezone
import enum
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EpistemicClassification(str, enum.Enum):
    """Four-tier epistemic taxonomy distinguishing evidence from analysis."""
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    INFERRED = "INFERRED"
    ADVISORY = "ADVISORY"


class CorrelationBasis(str, enum.Enum):
    """Explicit justification basis for event correlation."""
    DIRECT = "DIRECT"
    RELATIONAL = "RELATIONAL"
    TEMPORAL = "TEMPORAL"
    INFERRED = "INFERRED"


class GuardianExecutionStatus(str, enum.Enum):
    """Lifecycle statuses for a Blue Guardian defensive analysis execution."""
    PENDING = "pending"
    INGESTING = "ingesting"
    CORRELATING = "correlating"
    DETECTING = "detecting"
    ANALYZING_RISK = "analyzing_risk"
    RECOMMENDING = "recommending"
    PLANNING = "planning"
    COMPLETED = "completed"
    FAILED = "failed"


# =============================================================================
# Ingested Telemetry Schemas
# =============================================================================

class DefensiveEventEnvelope(BaseModel):
    """Normalized, immutable envelope for ingested synthetic attack telemetry.
    
    Epistemic Classification: OBSERVED
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    envelope_id: UUID = Field(default_factory=uuid4, description="Unique envelope identifier")
    source_event_id: str = Field(..., min_length=1, max_length=128, description="Originating SimulationEvent ID")
    attack_run_id: Optional[UUID] = Field(None, description="Foreign key to originating AttackRun")
    attack_path_id: Optional[UUID] = Field(None, description="Foreign key to originating AttackPath")
    campaign_id: Optional[UUID] = Field(None, description="Foreign key to originating Campaign")
    sandbox_id: UUID = Field(..., description="Foreign key to originating SandboxEnvironment")
    scenario_id: Optional[str] = Field(None, max_length=255, description="Scenario identifier")
    timestamp: datetime = Field(..., description="Event timestamp in UTC")
    event_type: str = Field(..., min_length=1, max_length=128, description="Standardized event type")
    severity: str = Field(..., min_length=1, max_length=32, description="Severity: info, warning, high, critical")
    source_asset_id: Optional[UUID] = Field(None, description="Synthetic asset initiating action")
    destination_asset_id: Optional[UUID] = Field(None, description="Synthetic asset receiving action")
    raw_payload: Dict[str, Any] = Field(default_factory=dict, description="Raw synthetic telemetry payload")
    provenance_metadata: Dict[str, Any] = Field(default_factory=dict, description="Execution and origin context")
    is_simulated: Literal[True] = Field(True, description="Strict synthetic invariant")
    simulation_only: Literal[True] = Field(True, description="Strict synthetic invariant")
    sha256_hash: str = Field(..., min_length=64, max_length=64, description="Cryptographic integrity digest of payload")
    classification: Literal[EpistemicClassification.OBSERVED] = EpistemicClassification.OBSERVED

    @field_validator("sha256_hash")
    @classmethod
    def validate_sha256(cls, v: str) -> str:
        if not all(c in "0123456789abcdefABCDEF" for c in v):
            raise ValueError("sha256_hash must be a valid 64-character hexadecimal string")
        return v.lower()


class DefensiveEventRecordResponse(BaseModel):
    """API representation of a persisted defensive event record."""
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    guardian_execution_id: UUID
    sandbox_id: UUID
    source_event_id: str
    attack_run_id: Optional[UUID] = None
    campaign_id: Optional[UUID] = None
    attack_path_id: Optional[UUID] = None
    scenario_id: Optional[str] = None
    source_asset_id: Optional[UUID] = None
    destination_asset_id: Optional[UUID] = None
    event_type: str
    severity: str
    original_timestamp: datetime
    ingested_at: datetime
    is_simulated: bool
    simulation_only: bool
    sha256_hash: str
    raw_payload: Dict[str, Any]
    provenance_metadata: Dict[str, Any]


class DefensiveEventListResponse(BaseModel):
    """Paginated collection of ingested defensive events."""
    model_config = ConfigDict(extra="forbid")

    items: List[DefensiveEventRecordResponse]
    total: int
    page: int
    page_size: int


# =============================================================================
# Correlation Group Schemas
# =============================================================================

class CorrelatedGroupResponse(BaseModel):
    """API representation of a deterministic correlated event group."""
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    guardian_execution_id: UUID
    sandbox_id: UUID
    campaign_id: Optional[UUID] = None
    title: str
    stage: str
    correlation_basis: CorrelationBasis
    correlation_rule: str
    member_event_ids: List[str]
    root_cause_asset_id: Optional[str] = None
    impacted_asset_ids: List[str] = Field(default_factory=list)
    earliest_event_timestamp: datetime
    latest_event_timestamp: datetime
    correlation_confidence: float
    simulation_only: bool
    is_simulated: bool
    group_metadata: Dict[str, Any]
    created_at: datetime


class CorrelatedGroupDetailResponse(BaseModel):
    """Detailed view of a correlated group including its full source event records."""
    model_config = ConfigDict(extra="forbid")

    group: CorrelatedGroupResponse
    events: List[DefensiveEventRecordResponse]


class CorrelatedGroupListResponse(BaseModel):
    """Collection of correlated event groups."""
    model_config = ConfigDict(extra="forbid")

    items: List[CorrelatedGroupResponse]
    total: int


# =============================================================================
# Execution Orchestration Schemas
# =============================================================================

class GuardianExecutionCreateRequest(BaseModel):
    """Request payload to initiate defensive ingestion and correlation."""
    model_config = ConfigDict(extra="forbid")

    sandbox_id: UUID = Field(..., description="Target sandbox environment ID")
    attack_run_id: Optional[UUID] = Field(None, description="Target AttackRun ID (one of attack_run_id or attack_path_id required)")
    attack_path_id: Optional[UUID] = Field(None, description="Target AttackPath ID (one of attack_run_id or attack_path_id required)")
    correlation_window_seconds: int = Field(300, ge=10, le=86400, description="Sliding temporal window in seconds")

    @field_validator("attack_path_id")
    @classmethod
    def validate_targets(cls, v: Optional[UUID], info) -> Optional[UUID]:
        data = info.data
        run_id = data.get("attack_run_id")
        if not run_id and not v:
            raise ValueError("Either attack_run_id or attack_path_id must be provided")
        return v


class GuardianExecutionResponse(BaseModel):
    """Summary of a Blue Guardian defensive analysis execution."""
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    execution_id: UUID
    sandbox_id: UUID
    attack_run_id: Optional[UUID] = None
    attack_path_id: Optional[UUID] = None
    status: GuardianExecutionStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    events_ingested: int
    correlation_groups_count: int
    threat_detections_count: int = 0
    risk_assessments_count: int = 0
    max_risk_score: float = 0.0
    error_message: Optional[str] = None


class GuardianExecutionDetailResponse(BaseModel):
    """Detailed view of a Blue Guardian defensive analysis execution."""
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    execution_id: UUID
    sandbox_id: UUID
    attack_run_id: Optional[UUID] = None
    attack_path_id: Optional[UUID] = None
    status: GuardianExecutionStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    events_ingested: int
    correlation_groups_count: int
    threat_detections_count: int = 0
    risk_assessments_count: int = 0
    max_risk_score: float = 0.0
    error_message: Optional[str] = None
    execution_metadata: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


# =============================================================================
# Threat Detection Schemas
# =============================================================================

class ThreatDetectionResponse(BaseModel):
    """Structured, evidence-backed threat detection produced by Blue Guardian."""
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    guardian_execution_id: UUID
    correlated_group_id: UUID
    sandbox_id: UUID
    detection_code: str
    rule_code: str
    rule_version: str
    title: str
    description: str
    classification: str
    severity: str
    confidence_score: float
    mitre_techniques: List[Dict[str, Any]]
    mitre_tactics: List[str]
    affected_asset_ids: List[str]
    evidence_references: Dict[str, Any]
    detection_rationale: str
    status: str
    is_simulated: bool
    simulation_only: bool
    created_at: datetime
    updated_at: datetime


class ThreatDetectionListResponse(BaseModel):
    """Paginated collection of threat detections."""
    model_config = ConfigDict(extra="forbid")

    items: List[ThreatDetectionResponse]
    total: int
    page: int
    page_size: int


class ThreatDetectionSummaryResponse(BaseModel):
    """Aggregated threat metrics across detections for the SOC command center."""
    model_config = ConfigDict(extra="forbid")

    total_detections: int
    by_severity: Dict[str, int]
    by_classification: Dict[str, int]
    by_mitre_technique: Dict[str, int]
    affected_assets_count: int


class DetectionRuleMetadataResponse(BaseModel):
    """Descriptor schema for an active detection rule."""
    model_config = ConfigDict(extra="forbid")

    rule_code: str
    rule_version: str
    rule_name: str
    description: str
    enabled: bool
    severity: str
    confidence: float
    classification: str
    mitre_tactics: List[str]
    mitre_techniques: List[Dict[str, Any]]
    required_event_types: List[str]
    min_event_count: int
    false_positive_conditions: List[str]


class DetectionRuleListResponse(BaseModel):
    """Listing response of registered detection rules."""
    model_config = ConfigDict(extra="forbid")

    rules: List[DetectionRuleMetadataResponse]
    total: int


# =============================================================================
# Asset Impact & Risk Analysis Schemas
# =============================================================================

class AssetImpactType(str, enum.Enum):
    """Taxonomy of asset impact relationships evaluated by Blue Guardian."""
    DIRECTLY_AFFECTED = "DIRECTLY_AFFECTED"
    POTENTIALLY_EXPOSED = "POTENTIALLY_EXPOSED"
    INFERRED_EXPOSURE = "INFERRED_EXPOSURE"


class RiskCategory(str, enum.Enum):
    """Categorical risk tiers based on bounded risk score."""
    INFORMATIONAL = "Informational"  # 0.0 - 2.0
    LOW = "Low"                      # > 2.0 - 4.0
    MEDIUM = "Medium"                # > 4.0 - 6.0
    HIGH = "High"                    # > 6.0 - 8.0
    CRITICAL = "Critical"            # > 8.0 - 10.0


class ThreatAssetImpactResponse(BaseModel):
    """Details of asset impact resulting from a threat detection."""
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    risk_assessment_id: UUID
    asset_id: UUID
    sandbox_id: UUID
    impact_type: AssetImpactType
    impact_score: float
    traversal_depth: int
    relationship_path: List[str]
    impact_rationale: str
    evidence_references: Dict[str, Any]
    created_at: datetime


class ThreatRiskAssessmentResponse(BaseModel):
    """Summary of a multi-dimensional risk assessment for a threat detection."""
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    threat_detection_id: UUID
    guardian_execution_id: UUID
    sandbox_id: UUID
    risk_score: float
    risk_category: RiskCategory
    severity: str
    asset_criticality_score: float
    direct_impact_score: float
    blast_radius_score: float
    attack_stage_score: float
    evidence_confidence_score: float
    scoring_formula_version: str
    assessment_rationale: str
    assessment_status: str
    assessed_at: datetime
    created_at: datetime
    updated_at: datetime
    is_simulated: bool
    simulation_only: bool


class ThreatRiskAssessmentDetailResponse(BaseModel):
    """Comprehensive view of a risk assessment including associated asset impacts."""
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    assessment: ThreatRiskAssessmentResponse
    impacted_assets: List[ThreatAssetImpactResponse]


class ThreatRiskAssessmentListResponse(BaseModel):
    """Paginated collection of threat risk assessments."""
    model_config = ConfigDict(extra="forbid")

    items: List[ThreatRiskAssessmentResponse]
    total: int
    page: int
    page_size: int


class RiskSummaryResponse(BaseModel):
    """Aggregated risk metrics across the target sandbox or execution."""
    model_config = ConfigDict(extra="forbid")

    total_assessments: int
    max_risk_score: float
    average_risk_score: float
    by_category: Dict[str, int]
    by_severity: Dict[str, int]
    directly_affected_assets_count: int
    potentially_exposed_assets_count: int


class AssetRiskProfileResponse(BaseModel):
    """Risk summary and exposure profile for a specific synthetic asset."""
    model_config = ConfigDict(extra="forbid")

    asset_id: UUID
    sandbox_id: UUID
    asset_name: str
    asset_type: str
    criticality: str
    highest_risk_score: float
    highest_risk_category: RiskCategory
    direct_detections_count: int
    indirect_exposure_count: int
    total_assessments_count: int


class RiskPriorityItemResponse(BaseModel):
    """Ranked item in the threat prioritization list."""
    model_config = ConfigDict(extra="forbid")

    rank: int
    risk_assessment_id: UUID
    threat_detection_id: UUID
    detection_code: str
    title: str
    classification: str
    severity: str
    risk_score: float
    risk_category: RiskCategory
    critical_asset_exposed: bool
    directly_affected_asset_count: int
    detected_at: datetime


class RiskPrioritiesResponse(BaseModel):
    """Ordered collection of prioritized threats."""
    model_config = ConfigDict(extra="forbid")

    items: List[RiskPriorityItemResponse]
    total: int
    highest_risk_detection_id: Optional[UUID] = None
    highest_risk_asset_id: Optional[UUID] = None


# =============================================================================
# Step 09.2.3.5: Recommendations, Remediation Planning & Incident Report Schemas
# =============================================================================

class RecommendationPriority(str, enum.Enum):
    """Priority level for defensive recommendations and actions."""
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class RecommendationType(str, enum.Enum):
    """Category of defensive control."""
    PREVENTIVE = "preventive"
    DETECTIVE = "detective"
    CORRECTIVE = "corrective"
    COMPENSATING = "compensating"


class RecommendationStatus(str, enum.Enum):
    """Lifecycle status of a defensive recommendation."""
    PROPOSED = "proposed"
    PLANNED = "planned"
    APPLIED = "applied"
    DISMISSED = "dismissed"


class RemediationPlanStatus(str, enum.Enum):
    """Lifecycle status of a remediation plan."""
    DRAFT = "draft"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"


class ActionStatus(str, enum.Enum):
    """Execution status of an action step in a remediation plan."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class IncidentReportStatus(str, enum.Enum):
    """Publication status of an incident report."""
    DRAFT = "draft"
    PUBLISHED = "published"
    ARCHIVED = "archived"


# --- Playbook Schemas ---

class PlaybookResponse(BaseModel):
    """Defensive mitigation playbook blueprint."""
    model_config = ConfigDict(extra="ignore")

    playbook_id: str
    playbook_version: str = "1.0.0"
    title: str
    description: str
    category: str
    recommendation_type: RecommendationType
    target_threat_classes: List[str]
    mitre_techniques: List[str]
    default_priority: RecommendationPriority
    complexity: str
    rationale: str
    expected_outcome: str
    verification_criteria: List[str]
    action_templates: List[Dict[str, Any]]


class PlaybookListResponse(BaseModel):
    """Catalog of available mitigation playbooks."""
    model_config = ConfigDict(extra="ignore")

    playbooks: List[PlaybookResponse]
    total: int


# --- Recommendation Schemas ---

class DefensiveRecommendationResponse(BaseModel):
    """Defensive recommendation generated from detection and impact analysis."""
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    id: UUID
    guardian_execution_id: UUID
    threat_detection_id: UUID
    risk_assessment_id: UUID
    sandbox_id: UUID
    recommendation_code: str
    title: str
    description: str
    priority: RecommendationPriority
    recommendation_type: RecommendationType
    playbook_id: str
    playbook_version: str
    affected_asset_ids: List[str]
    evidence_references: Dict[str, Any]
    rationale: str
    expected_outcome: str
    verification_criteria: List[str]
    implementation_complexity: str
    status: RecommendationStatus
    created_at: datetime
    updated_at: datetime
    is_simulated: bool
    simulation_only: bool


class DefensiveRecommendationListResponse(BaseModel):
    """Collection of defensive recommendations."""
    model_config = ConfigDict(extra="ignore")

    items: List[DefensiveRecommendationResponse]
    total: int
    page: int = 1
    page_size: int = 50


# --- Remediation Plan Schemas ---

class RemediationPlanActionResponse(BaseModel):
    """Specific ordered action in a remediation plan."""
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    id: UUID
    remediation_plan_id: UUID
    recommendation_id: UUID
    action_code: str
    title: str
    description: str
    sequence_order: int
    priority: RecommendationPriority
    depends_on: List[str]
    target_asset_ids: List[str]
    expected_outcome: str
    verification_criteria: List[str]
    action_type: str
    status: ActionStatus
    created_at: datetime
    updated_at: datetime


class RemediationPlanResponse(BaseModel):
    """Structured remediation plan."""
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    id: UUID
    guardian_execution_id: UUID
    sandbox_id: UUID
    title: str
    description: str
    overall_priority: RecommendationPriority
    status: RemediationPlanStatus
    plan_version: str
    target_asset_ids: List[str]
    plan_metadata: Dict[str, Any]
    action_count: int = 0
    created_at: datetime
    updated_at: datetime
    is_simulated: bool
    simulation_only: bool


class RemediationPlanDetailResponse(RemediationPlanResponse):
    """Detailed remediation plan including ordered actions."""
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    actions: List[RemediationPlanActionResponse] = Field(default_factory=list)


class RemediationPlanListResponse(BaseModel):
    """Collection of remediation plans."""
    model_config = ConfigDict(extra="ignore")

    items: List[RemediationPlanResponse]
    total: int


# --- Incident Report Schemas ---

class IncidentReportResponse(BaseModel):
    """Summary of a generated incident report."""
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    id: UUID
    guardian_execution_id: UUID
    sandbox_id: UUID
    report_version: int
    title: str
    executive_summary: str
    threat_classifications: List[str]
    severity: str
    max_risk_score: float
    risk_category: str
    affected_asset_ids: List[str]
    potentially_exposed_asset_ids: List[str]
    blast_radius_nodes_count: int
    mitre_techniques: List[Dict[str, Any]]
    remediation_plan_id: Optional[UUID] = None
    report_status: IncidentReportStatus
    generated_at: datetime
    created_at: datetime


class IncidentReportDetailResponse(IncidentReportResponse):
    """Comprehensive incident report with evidence timeline and analysis."""
    model_config = ConfigDict(from_attributes=True, extra="ignore")

    event_timeline: List[Dict[str, Any]] = Field(default_factory=list)
    detection_summaries: List[Dict[str, Any]] = Field(default_factory=list)
    recommendation_summaries: List[Dict[str, Any]] = Field(default_factory=list)
    report_content: Dict[str, Any] = Field(default_factory=dict)


class IncidentReportListResponse(BaseModel):
    """Collection of incident reports for an execution."""
    model_config = ConfigDict(extra="ignore")

    items: List[IncidentReportResponse]
    total: int


class IncidentReportGenerateRequest(BaseModel):
    """Request payload to trigger incident report generation."""
    model_config = ConfigDict(extra="forbid")

    report_version: Optional[int] = None
    custom_title: Optional[str] = None
    include_ai_narrative: bool = True


# --- Executive Summary Schemas ---

class ExecutiveSummaryResponse(BaseModel):
    """Concise executive summary of security posture and top threats."""
    model_config = ConfigDict(extra="ignore")

    guardian_execution_id: UUID
    sandbox_id: UUID
    posture_rating: str
    executive_summary: str
    total_detections: int
    max_risk_score: float
    risk_category: str
    p0_recommendations_count: int
    total_recommendations: int
    affected_assets_count: int
    exposed_assets_count: int
    top_threats: List[Dict[str, Any]]
    immediate_priorities: List[str]
    residual_risks_and_uncertainties: List[str]
    ai_enriched: bool = False
    generated_at: datetime


# =============================================================================
# Step 09.2.3.6: Human Approval & Synthetic Regression Schemas
# =============================================================================

from app.agents.blue_guardian.approval_schemas import (
    ApprovalDecisionCreate,
    ApprovalDecisionResponse,
    ApprovalDecisionType,
    ApprovalPolicyResponse,
    ApprovalPolicyRule,
    ApprovalRequestCancel,
    ApprovalRequestCreate,
    ApprovalRequestListResponse,
    ApprovalRequestResponse,
    ApprovalStatus,
    ExecutionStatus,
    RemediationVerificationResponse,
    RemediationVerificationSummaryResponse,
    SyntheticExecutionCreate,
    SyntheticRemediationExecutionListResponse,
    SyntheticRemediationExecutionResponse,
    SyntheticSnapshotComparisonResponse,
    SyntheticStateSnapshotResponse,
    VerificationStatus,
)




