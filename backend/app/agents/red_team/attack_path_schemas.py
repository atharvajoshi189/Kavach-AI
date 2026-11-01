"""Pydantic schemas for attack path orchestration."""

from datetime import datetime
from typing import Any, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class AttackPathPlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    campaign_id: uuid.UUID
    source_asset_id: uuid.UUID
    destination_asset_id: Optional[uuid.UUID] = None
    execution_mode: str = "exploratory"  # exploratory or targeted
    max_stages: int = Field(default=6, ge=1, le=8)
    scenario_constraints: Optional[list[str]] = None  # whitelist of allowed scenario IDs


class AttackPathExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attack_path_id: uuid.UUID


class AttackPathNode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str
    asset_name: str
    asset_type: str
    sandbox_id: str
    status: str
    risk_level: str


class AttackPathEdge(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_asset_id: str
    destination_asset_id: str
    relationship_type: str  # "connected_asset", "lateral_movement", etc.
    scenario_reference: Optional[str] = None
    edge_status: str  # confirmed_relationship, completed_stage, failed_stage, skipped_stage, planned_only


class AttackPathStageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    attack_path_id: str
    sequence_number: int
    scenario_id: str
    source_asset_id: str
    destination_asset_id: Optional[str] = None
    status: str
    prerequisites: list[Any]
    attack_run_id: Optional[str] = None
    risk_score: Optional[float] = None
    stage_metadata: dict[str, Any]
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    simulation_only: bool
    is_simulated: bool


class AttackPathResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    campaign_id: str
    sandbox_id: str
    source_asset_id: str
    status: str
    execution_mode: str
    total_stages: int
    completed_stages: int
    failed_stages: int
    risk_score: Optional[float] = None
    path_metadata: dict[str, Any]
    execution_id: Optional[str] = None
    simulation_only: bool
    created_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    stages: list[AttackPathStageResponse] = []


class AttackPathPlanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attack_path: AttackPathResponse
    nodes: list[AttackPathNode]
    edges: list[AttackPathEdge]
    planning_explanation: list[str]
    rejected_candidates: list[dict[str, Any]]


class AttackPathGraphResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attack_path_id: str
    nodes: list[AttackPathNode]
    edges: list[AttackPathEdge]


class AttackPathReportResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attack_path_id: str
    campaign_id: str
    sandbox_id: str
    status: str
    execution_mode: str
    risk_score: Optional[float] = None
    total_stages: int
    completed_stages: int
    failed_stages: int
    nodes: list[AttackPathNode]
    edges: list[AttackPathEdge]
    correlated_events: list[dict[str, Any]]
    planning_explanation: list[str]
    created_at: datetime
    completed_at: Optional[datetime] = None


class AttackPathListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[AttackPathResponse]
    total: int
    skip: int
    limit: int


class AttackPathCancelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Optional[str] = None

