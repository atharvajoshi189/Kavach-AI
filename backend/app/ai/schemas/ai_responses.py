"""Strict Pydantic schemas for AI Intelligence Gateway responses.

Enforces schema contracts with extra='forbid' to ensure type safety,
forensic traceability, and evidence grounding across all generative capabilities.
"""

from datetime import datetime, timezone
from typing import Any, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class BaseAIAnalysisResponse(BaseModel):
    """Base Pydantic schema for all AI-generated analyses."""

    model_config = ConfigDict(extra="forbid")

    analysis_id: uuid.UUID = Field(
        default_factory=uuid.uuid4,
        description="Unique identifier for this AI analysis record",
    )
    analysis_type: str = Field(
        ...,
        description="Type of analysis performed (e.g. threat_explanation, risk_explanation)",
    )
    summary: str = Field(
        ...,
        max_length=4000,
        description="High-level contextual summary of the analysis",
    )
    key_findings: list[str] = Field(
        default_factory=list,
        description="Bullet points of key observations and analytical insights",
    )
    supporting_evidence_ids: list[str] = Field(
        default_factory=list,
        description="List of verified persisted evidence identifiers backing this analysis",
    )
    observed_facts: list[str] = Field(
        default_factory=list,
        description="Directly observed, verifiable facts extracted from persisted telemetry",
    )
    derived_conclusions: list[str] = Field(
        default_factory=list,
        description="Logical deductions drawn directly from the observed facts",
    )
    inferred_observations: list[str] = Field(
        default_factory=list,
        description="Analytical hypotheses and probabilistic patterns identified",
    )
    uncertainties: list[str] = Field(
        default_factory=list,
        description="Known limitations, missing telemetry, or ambiguous aspects",
    )
    suggested_actions: list[str] = Field(
        default_factory=list,
        description="Advisory defensive actions suggested for human evaluation",
    )
    provider: str = Field(
        ...,
        description="AI Provider used (e.g., 'gemini' or 'deterministic_fallback')",
    )
    model: str = Field(
        ...,
        description="Model identifier or template version used",
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the analysis was generated",
    )
    is_ai_generated: bool = Field(
        default=True,
        description="Marker indicating the analysis contains generative or heuristic content",
    )
    fallback_used: bool = Field(
        default=False,
        description="True if deterministic fallback template was used instead of live LLM",
    )
    fallback_reason: Optional[str] = Field(
        default=None,
        description="Operational reason why fallback was invoked, if applicable",
    )
    confidence_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence score in the analytical conclusions (0.0 to 1.0)",
    )


class ThreatExplanationResponse(BaseAIAnalysisResponse):
    """Schema for threat detection explanations."""

    detection_id: uuid.UUID = Field(
        ...,
        description="UUID of the ThreatDetection record analyzed",
    )
    mitre_attack_technique: Optional[str] = Field(
        default=None,
        description="MITRE ATT&CK technique identifier associated with the detection",
    )
    severity: str = Field(
        ...,
        description="Authoritative severity level of the detection",
    )
    target_asset_id: Optional[uuid.UUID] = Field(
        default=None,
        description="Target synthetic asset UUID",
    )
    attack_implications: list[str] = Field(
        default_factory=list,
        description="Potential operational consequences if the threat goes unmitigated",
    )
    recommended_investigation_steps: list[str] = Field(
        default_factory=list,
        description="Actionable diagnostic steps for a security analyst",
    )


class AttackPathAnalysisResponse(BaseAIAnalysisResponse):
    """Schema for multi-stage attack path progression analysis."""

    attack_path_id: uuid.UUID = Field(
        ...,
        description="UUID of the AttackPath analyzed",
    )
    progression_summary: str = Field(
        ...,
        description="Narrative explanation of how the attack progressed across stages",
    )
    critical_stages: list[dict[str, Any]] = Field(
        default_factory=list,
        description="High-leverage attack stages identified in the path",
    )
    transition_points: list[str] = Field(
        default_factory=list,
        description="Lateral movement or privilege escalation transition pivots",
    )
    affected_assets: list[uuid.UUID] = Field(
        default_factory=list,
        description="UUIDs of synthetic assets traversed or targeted",
    )
    defensive_intervention_points: list[str] = Field(
        default_factory=list,
        description="Points where defensive countermeasures would disrupt the kill-chain",
    )
    is_simulated: bool = Field(
        default=True,
        description="Guarantee that this attack path was strictly simulated",
    )


class RiskExplanationResponse(BaseAIAnalysisResponse):
    """Schema for explaining deterministic risk scores."""

    assessment_id: uuid.UUID = Field(
        ...,
        description="UUID of the ThreatRiskAssessment record",
    )
    authoritative_risk_score: float = Field(
        ...,
        description="The authoritative, deterministic risk score from Blue Guardian",
    )
    risk_level: str = Field(
        ...,
        description="Risk priority level (e.g. CRITICAL, HIGH, MEDIUM, LOW)",
    )
    score_factors_explanation: dict[str, str] = Field(
        default_factory=dict,
        description="Breakdown explaining the 6 risk dimensions (severity, criticality, impact, etc.)",
    )
    primary_risk_drivers: list[str] = Field(
        default_factory=list,
        description="Dominant contributing variables elevating the risk score",
    )
    defensive_focus_areas: list[str] = Field(
        default_factory=list,
        description="Prioritized security areas requiring immediate attention",
    )
    score_immutable_notice: str = Field(
        default="Deterministic risk score is authoritative and cannot be overridden by AI.",
        description="Safety declaration enforcing score immutability",
    )


class IncidentSummaryResponse(BaseAIAnalysisResponse):
    """Schema for comprehensive incident intelligence summaries."""

    report_id: uuid.UUID = Field(
        ...,
        description="UUID of the IncidentReport record",
    )
    incident_narrative: str = Field(
        ...,
        description="Synthesized operational narrative of the security incident",
    )
    timeline_highlights: list[str] = Field(
        default_factory=list,
        description="Key chronological milestones of defensive detections and events",
    )
    potential_consequences: list[str] = Field(
        default_factory=list,
        description="Projected blast radius and business disruption impact",
    )
    immediate_defensive_priorities: list[str] = Field(
        default_factory=list,
        description="Top defensive posture recommendations for mitigation",
    )


class RecommendationExplanationResponse(BaseAIAnalysisResponse):
    """Schema for defensive recommendation and playbook explanations."""

    recommendation_id: uuid.UUID = Field(
        ...,
        description="UUID of the DefensiveRecommendation record",
    )
    playbook_title: str = Field(
        ...,
        description="Title of the countermeasure playbook",
    )
    action_rationale: str = Field(
        ...,
        description="Technical justification for applying this specific remediation action",
    )
    expected_defensive_impact: str = Field(
        ...,
        description="Measurable defensive benefit anticipated upon execution",
    )
    operational_side_effects: list[str] = Field(
        default_factory=list,
        description="Potential operational friction or system dependencies affected",
    )
    verification_guidance: list[str] = Field(
        default_factory=list,
        description="Criteria for verifying successful countermeasure application",
    )
    requires_human_approval: bool = Field(
        default=True,
        description="Indicates that human governance sign-off is mandatory before execution",
    )


class ExecutiveBriefingResponse(BaseAIAnalysisResponse):
    """Schema for management and C-suite security posture briefings."""

    execution_id: uuid.UUID = Field(
        ...,
        description="UUID of the GuardianExecution or Orchestration run",
    )
    executive_overview: str = Field(
        ...,
        description="Non-technical executive summary of organizational security posture",
    )
    critical_risk_posture: str = Field(
        ...,
        description="Macro risk assessment summary",
    )
    top_findings: list[str] = Field(
        default_factory=list,
        description="Top priority findings requiring executive attention",
    )
    strategic_priorities: list[str] = Field(
        default_factory=list,
        description="Strategic security resource allocation recommendations",
    )
    remediation_governance_status: str = Field(
        ...,
        description="Current state of human approvals and remediation actions",
    )
    operational_limitations: list[str] = Field(
        default_factory=list,
        description="Explicit boundaries acknowledging the synthetic simulation context",
    )


class SecurityQAResponse(BaseAIAnalysisResponse):
    """Schema for context-grounded security Q&A responses."""

    execution_id: uuid.UUID = Field(
        ...,
        description="UUID of the contextual GuardianExecution",
    )
    question: str = Field(
        ...,
        max_length=1000,
        description="User-submitted natural language security question",
    )
    answer: str = Field(
        ...,
        max_length=4000,
        description="Evidence-grounded response answering the question",
    )
    grounded_facts: list[str] = Field(
        default_factory=list,
        description="Facts from persisted execution telemetry cited to answer the question",
    )


class AIAnalysisRecordResponse(BaseModel):
    """Pydantic representation of persisted AIAnalysisRecord for API consumers."""

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    sandbox_id: uuid.UUID
    guardian_execution_id: Optional[uuid.UUID]
    analysis_type: str
    source_entity_type: str
    source_entity_id: uuid.UUID
    source_version: Optional[str]
    provider: str
    model: str
    prompt_version: str
    response_content: dict[str, Any]
    evidence_references: list[str]
    fallback_used: bool
    fallback_reason: Optional[str]
    tokens_used: Optional[int]
    latency_ms: Optional[float]
    created_at: datetime
    created_by: Optional[uuid.UUID]


class AIAnalysisListResponse(BaseModel):
    """Paginated list of AI analysis records."""

    model_config = ConfigDict(extra="forbid")

    items: list[AIAnalysisRecordResponse]
    total: int
    page: int
    page_size: int


class AIUsageMetricsResponse(BaseModel):
    """Aggregated usage and observability metrics for the AI Gateway."""

    model_config = ConfigDict(extra="forbid")

    provider_status: str = Field(
        ...,
        description="Status of the primary provider: 'online', 'disabled', or 'fallback_only'",
    )
    gemini_enabled: bool
    gemini_model: str
    total_requests: int
    successful_requests: int
    failed_requests: int
    fallback_requests: int
    fallback_rate_pct: float
    total_tokens_used: int
    prompt_tokens: int
    completion_tokens: int
    average_latency_ms: float
    per_capability_counts: dict[str, int]
    recorded_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )


class AIHealthResponse(BaseModel):
    """Health check status for the AI Intelligence Gateway."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="'healthy', 'degraded', or 'disabled'")
    provider_configured: bool
    gemini_enabled: bool
    model: str
    fallback_ready: bool = True
    cache_ready: bool = True
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

