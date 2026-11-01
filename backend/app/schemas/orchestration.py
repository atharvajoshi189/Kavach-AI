"""Pydantic schemas for AegisMesh unified end-to-end orchestration and observability."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.orchestration import PipelineExecutionStatus, PipelineStage


class PipelineStartRequest(BaseModel):
    """Payload to trigger an end-to-end synthetic orchestration execution."""
    model_config = ConfigDict(extra="ignore")

    sandbox_id: UUID = Field(..., description="Target sandbox environment UUID")
    scenario_id: Optional[str] = Field("simulated_initial_access", description="Initial Red Team scenario to trigger")
    run_attack_path: bool = Field(False, description="Whether to execute multi-stage attack path instead of single run")
    auto_approve: bool = Field(False, description="Automated approval bypass for integration verification")
    correlation_window_seconds: int = Field(300, ge=30, le=3600, description="Defensive event correlation window in seconds")
    client_metadata: Dict[str, Any] = Field(default_factory=dict, description="Client context metadata")


class PipelineResumeRequest(BaseModel):
    """Payload to resume a paused or failed orchestration execution."""
    model_config = ConfigDict(extra="ignore")

    reason: Optional[str] = Field(None, max_length=500, description="Resume justification")


class OrchestrationExecutionResponse(BaseModel):
    """Durable state of a unified platform pipeline execution."""
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    sandbox_id: UUID
    campaign_id: Optional[UUID] = None
    simulation_id: Optional[UUID] = None
    attack_path_id: Optional[UUID] = None
    guardian_execution_id: Optional[UUID] = None
    remediation_plan_id: Optional[UUID] = None
    approval_request_id: Optional[UUID] = None
    synthetic_execution_id: Optional[UUID] = None
    verification_id: Optional[UUID] = None
    current_stage: str
    execution_status: str
    failed_stage: Optional[str] = None
    error_message: Optional[str] = None
    retry_count: int
    is_resumable: bool
    stage_metrics: Dict[str, Any] = Field(default_factory=dict)
    execution_metadata: Dict[str, Any] = Field(default_factory=dict)
    started_at: datetime
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class OrchestrationExecutionListResponse(BaseModel):
    """Paginated collection of orchestration executions."""
    model_config = ConfigDict(extra="forbid")

    items: List[OrchestrationExecutionResponse]
    total: int
    page: int = 1
    page_size: int = 50


class PipelineObservabilityMetrics(BaseModel):
    """Persisted observability metrics across all platform executions."""
    model_config = ConfigDict(extra="forbid")

    total_executions: int
    successful_executions: int
    failed_executions: int
    partial_failure_executions: int
    running_executions: int
    waiting_approval_executions: int
    average_stage_durations: Dict[str, float]
    average_approval_wait_seconds: float
    verification_outcomes: Dict[str, int]
    retry_counts_total: int

