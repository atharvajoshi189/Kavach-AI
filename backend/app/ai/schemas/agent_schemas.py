"""Pydantic schemas for LangGraph Multi-Agent Orchestration layer.

Strictly enforces extra="forbid", EvidenceGuard integration, and advisory boundaries.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field


class AgentExecutionStatus(str, Enum):
    """Execution status for an individual agent."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    FALLBACK = "fallback"
    SKIPPED = "skipped"


class GraphExecutionStatus(str, Enum):
    """Composite status for the multi-agent graph."""

    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class GraphRequestType(str, Enum):
    """Scope of investigation requested from the multi-agent graph."""

    FULL_INVESTIGATION = "full_investigation"
    THREAT_FOCUS = "threat_focus"
    ATTACK_PATH_FOCUS = "attack_path_focus"
    RISK_FOCUS = "risk_focus"
    INCIDENT_FOCUS = "incident_focus"
    DEFENSE_FOCUS = "defense_focus"
    EXECUTIVE_BRIEFING = "executive_briefing"
    CUSTOM = "custom"


class AegisAgentOutput(BaseModel):
    """Structured execution contract returned by every specialized AI agent.

    Enforces strict observation/hypothesis separation, evidence grounding,
    and non-authoritative advisory status.
    """

    model_config = ConfigDict(extra="forbid")

    agent_name: str = Field(..., description="Unique canonical name of the executing agent")
    execution_status: str = Field(..., description="Status: completed, partial, failed, or fallback")
    summary: str = Field(..., min_length=5, description="High-level narrative synthesis from this agent")
    observations: list[str] = Field(default_factory=list, description="Directly observed synthetic facts from persisted records")
    supporting_evidence_ids: list[str] = Field(default_factory=list, description="UUIDs of verified evidence entities cited")
    derived_conclusions: list[str] = Field(default_factory=list, description="Reasoned deductions derived from observations")
    inferred_exposure: list[str] = Field(default_factory=list, description="Potential downstream risks or hypothetical exposures")
    uncertainty: list[str] = Field(default_factory=list, description="Known unknowns or confidence caveats")
    missing_information: list[str] = Field(default_factory=list, description="Telemetry or context that was unavailable")
    advisory_recommendations: list[str] = Field(default_factory=list, description="Non-binding recommendations for human operators")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Agent confidence score between 0.0 and 1.0")
    fallback_used: bool = Field(default=False, description="Whether deterministic template fallback was used")
    simulation_only: bool = Field(default=True, description="Safety invariant: must always be True")
    is_ai_generated: bool = Field(default=True, description="Safety marker: indicates AI-generated content")


class GraphExecutionRequest(BaseModel):
    """Request payload to initiate a multi-agent graph execution."""

    model_config = ConfigDict(extra="forbid")

    sandbox_id: uuid.UUID = Field(..., description="Target synthetic sandbox UUID")
    execution_id: Optional[uuid.UUID] = Field(None, description="Associated Guardian or Orchestration execution UUID")
    request_type: GraphRequestType = Field(
        default=GraphRequestType.FULL_INVESTIGATION,
        description="Type of security analysis requested",
    )
    selected_agents: Optional[list[str]] = Field(
        None,
        description="Explicit list of agents to invoke. If None, selected automatically based on request_type",
    )
    input_reference_ids: Optional[list[str]] = Field(
        None,
        description="Specific entity UUIDs (detections, attack paths, assets) to focus analysis on",
    )
    user_query: Optional[str] = Field(
        None,
        max_length=1000,
        description="Optional ad-hoc guidance or question from operator",
    )


class SingleAgentExecuteRequest(BaseModel):
    """Request payload to invoke a single specialized agent directly."""

    model_config = ConfigDict(extra="forbid")

    sandbox_id: uuid.UUID = Field(..., description="Target synthetic sandbox UUID")
    agent_name: str = Field(..., description="Canonical name of the agent to execute")
    execution_id: Optional[uuid.UUID] = Field(None, description="Associated Guardian execution UUID")
    input_reference_ids: Optional[list[str]] = Field(None, description="Specific entity UUIDs to analyze")
    user_query: Optional[str] = Field(None, max_length=1000, description="Optional ad-hoc question")


class GraphExecutionResponse(BaseModel):
    """Complete aggregated response from the LangGraph multi-agent orchestration."""

    model_config = ConfigDict(extra="forbid")

    graph_execution_id: uuid.UUID = Field(..., description="Unique graph execution session UUID")
    parent_execution_id: Optional[uuid.UUID] = Field(None, description="Guardian or Orchestration execution UUID")
    sandbox_id: uuid.UUID = Field(..., description="Target sandbox UUID")
    request_type: str = Field(..., description="The requested analysis type")
    selected_agents: list[str] = Field(default_factory=list, description="Agents selected for execution")
    individual_agent_statuses: dict[str, str] = Field(
        default_factory=dict,
        description="Execution status per agent (completed, fallback, failed, skipped)",
    )
    agent_outputs: dict[str, AegisAgentOutput] = Field(
        default_factory=dict,
        description="Individual structured agent outputs keyed by agent name",
    )
    synthesis_summary: str = Field(..., description="Unified narrative combining all agent findings")
    overall_confidence: float = Field(..., ge=0.0, le=1.0, description="Composite confidence score")
    execution_status: str = Field(..., description="Final graph status: completed, partial, failed")
    fallback_used: bool = Field(default=False, description="True if any agent or graph node used fallback")
    is_simulated: bool = Field(default=True, description="Safety invariant: must always be True")
    simulation_only: bool = Field(default=True, description="Safety invariant: must always be True")
    started_at: datetime = Field(..., description="Graph execution start timestamp")
    completed_at: datetime = Field(..., description="Graph execution completion timestamp")
    total_latency_ms: float = Field(..., description="Total wall-clock execution time in milliseconds")
    total_tokens: Optional[int] = Field(None, description="Total tokens consumed across all agent calls")
    disclaimer: str = Field(
        default="AI multi-agent outputs are strictly advisory. Deterministic risk scores, policies, and human approval remain authoritative.",
        description="Mandatory advisory disclaimer",
    )


class AgentMetadata(BaseModel):
    """Public specification of a registered specialized AI agent."""

    model_config = ConfigDict(extra="forbid")

    agent_name: str = Field(..., description="Canonical agent identifier")
    display_name: str = Field(..., description="Human-readable title")
    description: str = Field(..., description="Detailed description of responsibilities")
    responsibilities: list[str] = Field(..., description="List of primary security duties")
    supported_request_types: list[str] = Field(..., description="Request types that activate this agent")
    advisory_boundary: str = Field(..., description="Explicit constraint on what agent cannot do")


class AgentListResponse(BaseModel):
    """Response containing list of all registered specialized AI agents."""

    model_config = ConfigDict(extra="forbid")

    agents: list[AgentMetadata] = Field(..., description="Registered agents")
    total_agents: int = Field(..., description="Total number of agents available")


class GraphHealthResponse(BaseModel):
    """Health check for LangGraph Multi-Agent Orchestration layer."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="Health status: healthy, degraded, unavailable")
    langgraph_available: bool = Field(..., description="Whether LangGraph package is functional")
    gemini_provider_available: bool = Field(..., description="Whether Gemini provider is ready")
    active_registered_agents: list[str] = Field(..., description="List of registered agent names")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

