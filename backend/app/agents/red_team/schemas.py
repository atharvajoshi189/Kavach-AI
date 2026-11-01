"""Pydantic schemas for the Red Team Agent and Deterministic Simulation Engine."""

from datetime import datetime
from typing import Any, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field


class SimulationEvent(BaseModel):
    """Structured discrete event recorded during deterministic simulation."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime
    event_type: str
    scenario_id: Optional[str] = None
    campaign_id: Optional[str] = None
    attack_run_id: Optional[str] = None
    sandbox_id: Optional[str] = None
    source_asset_id: Optional[str] = None
    destination_asset_id: Optional[str] = None
    severity: str  # "info", "warning", "high", "critical"
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    event_metadata: dict[str, Any] = Field(default_factory=dict)
    is_simulated: bool = True
    simulation_only: bool = True


class SimulationEvidence(BaseModel):
    """Structured evidence record representing simulated observation proof."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scenario_id: str
    evidence_type: str
    synthetic_asset_references: list[str] = Field(default_factory=list)
    finding_description: str
    severity: str
    confidence: str = "high"  # Confidence in synthetic rule evaluation
    supporting_synthetic_metadata: dict[str, Any] = Field(default_factory=dict)
    is_simulated: bool = True
    simulation_only: bool = True


class SimulationFinding(BaseModel):
    """Actionable security finding discovered through simulated assessment."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    severity: str  # "low", "medium", "high", "critical"
    technique: str
    asset_id: str
    details: dict[str, Any] = Field(default_factory=dict)
    evidence: Optional[SimulationEvidence] = None
    remediation_recommendation: str
    is_simulated: bool = True
    simulation_only: bool = True


class SimulationResult(BaseModel):
    """Complete result package returned by a deterministic simulation handler."""

    model_config = ConfigDict(extra="forbid")

    scenario: str
    technique: str
    asset_id: str
    sandbox_id: str
    status: str  # "completed", "failed"
    risk_score: float
    events: list[SimulationEvent] = Field(default_factory=list)
    findings: list[SimulationFinding] = Field(default_factory=list)
    started_at: datetime
    completed_at: datetime
    simulation_only: bool = True
    error: Optional[str] = None


class ScenarioMetadataResponse(BaseModel):
    """Metadata describing a registered deterministic attack simulation scenario."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str
    name: str
    description: str
    category: str = "general"
    technique: str
    technique_id: str
    applicable_asset_types: list[str]
    parameters: dict[str, Any] = Field(default_factory=dict)
    mapping_type: str = "conceptual_scenario"  # "technique_emulation" vs "conceptual_scenario"
    is_synthetic: bool = True
    risk_classification: str = "medium"


class RedTeamRunCreateRequest(BaseModel):
    """Request payload to initiate a deterministic Red Team simulation run."""

    model_config = ConfigDict(extra="forbid")

    scenario: str
    asset_id: uuid.UUID
    parameters: Optional[dict[str, Any]] = Field(default=None)


class RedTeamRunResponse(BaseModel):
    """Summary of an initiated or completed Red Team simulation run."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    run_id: uuid.UUID
    campaign_id: uuid.UUID
    scenario: str
    technique: str
    outcome: str
    risk_score: Optional[float] = None
    created_at: datetime
    simulation_only: bool = True


class RedTeamRunDetailResponse(BaseModel):
    """Detailed view of a Red Team simulation run including execution metadata."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    run_id: uuid.UUID
    campaign_id: uuid.UUID
    scenario: str
    technique: str
    outcome: str
    risk_score: Optional[float] = None
    execution_metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    simulation_only: bool = True
