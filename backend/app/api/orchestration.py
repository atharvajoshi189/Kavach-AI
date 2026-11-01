"""REST API endpoints for AegisMesh unified end-to-end platform orchestration and observability."""

from __future__ import annotations

import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import get_current_user
from app.database.session import get_db
from app.models.orchestration import OrchestrationExecution, PipelineExecutionStatus
from app.models.user import User
from app.schemas.orchestration import (
    OrchestrationExecutionListResponse,
    OrchestrationExecutionResponse,
    PipelineObservabilityMetrics,
    PipelineResumeRequest,
    PipelineStartRequest,
)
from app.security.gateway import authorize_action
from app.services.sandbox_service import get_sandbox_by_id, verify_sandbox_access
from app.services.unified_orchestrator import UnifiedOrchestrator
from app.workers.guardian_tasks import execute_unified_pipeline_task

logger = logging.getLogger("aegismesh.api.orchestration")

router = APIRouter(prefix="/orchestration", tags=["Unified Platform Orchestration"])


def _to_execution_response(ex: OrchestrationExecution) -> OrchestrationExecutionResponse:
    return OrchestrationExecutionResponse(
        id=ex.id,
        sandbox_id=ex.sandbox_id,
        campaign_id=ex.campaign_id,
        simulation_id=ex.simulation_id,
        attack_path_id=ex.attack_path_id,
        guardian_execution_id=ex.guardian_execution_id,
        remediation_plan_id=ex.remediation_plan_id,
        approval_request_id=ex.approval_request_id,
        synthetic_execution_id=ex.synthetic_execution_id,
        verification_id=ex.verification_id,
        current_stage=ex.current_stage,
        execution_status=ex.execution_status,
        failed_stage=ex.failed_stage,
        error_message=ex.error_message,
        retry_count=ex.retry_count,
        is_resumable=ex.is_resumable,
        stage_metrics=ex.stage_metrics or {},
        execution_metadata=ex.execution_metadata or {},
        started_at=ex.started_at,
        completed_at=ex.completed_at,
        created_at=ex.created_at,
        updated_at=ex.updated_at,
    )


@router.post(
    "/pipeline/start",
    response_model=OrchestrationExecutionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger Unified End-to-End Orchestration Pipeline",
)
async def start_unified_pipeline(
    payload: PipelineStartRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Executes or queues an end-to-end platform pipeline across Red Team and Blue Guardian."""
    orchestrator = UnifiedOrchestrator(db)
    execution = await orchestrator.start_pipeline(
        sandbox_id=payload.sandbox_id,
        user=current_user,
        scenario_id=payload.scenario_id or "simulated_initial_access",
        run_attack_path=payload.run_attack_path,
        auto_approve=payload.auto_approve,
        correlation_window_seconds=payload.correlation_window_seconds,
        client_metadata=payload.client_metadata,
    )
    return _to_execution_response(execution)


@router.get(
    "/pipeline",
    response_model=OrchestrationExecutionListResponse,
    summary="List Unified Pipeline Executions",
)
async def list_unified_pipelines(
    sandbox_id: Optional[uuid.UUID] = Query(None, description="Filter by sandbox ID"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by execution status"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Page size"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists unified orchestration executions with pagination and filtering."""
    query = select(OrchestrationExecution)
    count_query = select(func.count(OrchestrationExecution.id))

    if sandbox_id:
        query = query.where(OrchestrationExecution.sandbox_id == sandbox_id)
        count_query = count_query.where(OrchestrationExecution.sandbox_id == sandbox_id)

    if status_filter:
        query = query.where(OrchestrationExecution.execution_status == status_filter.lower())
        count_query = count_query.where(OrchestrationExecution.execution_status == status_filter.lower())

    total = (await db.execute(count_query)).scalar_one()
    query = query.order_by(OrchestrationExecution.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    rows = (await db.execute(query)).scalars().all()

    items = [_to_execution_response(r) for r in rows]
    return OrchestrationExecutionListResponse(items=items, total=total, page=page, page_size=page_size)


@router.get(
    "/pipeline/{execution_id}",
    response_model=OrchestrationExecutionResponse,
    summary="Get Pipeline Execution by ID",
)
async def get_unified_pipeline(
    execution_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves current stage, status, stage durations, and all linked entity IDs."""
    execution = await db.get(OrchestrationExecution, execution_id)
    if not execution:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OrchestrationExecution '{execution_id}' not found.",
        )

    sandbox = await get_sandbox_by_id(db, execution.sandbox_id)
    if not sandbox or not verify_sandbox_access(sandbox, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to target sandbox environment.",
        )

    decision = await authorize_action(
        user=current_user,
        operation="orchestration.read",
        capability="read",
        resource_type="orchestration_execution",
        resource_id=str(execution_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    return _to_execution_response(execution)


@router.post(
    "/pipeline/{execution_id}/resume",
    response_model=OrchestrationExecutionResponse,
    summary="Resume Waiting or Paused Pipeline Execution",
)
async def resume_unified_pipeline(
    execution_id: uuid.UUID,
    payload: PipelineResumeRequest = PipelineResumeRequest(),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Resumes an execution that was paused waiting for human approval."""
    orchestrator = UnifiedOrchestrator(db)
    execution = await orchestrator.resume_pipeline_after_approval(
        execution_id=execution_id,
        user=current_user,
    )
    return _to_execution_response(execution)


@router.get(
    "/metrics",
    response_model=PipelineObservabilityMetrics,
    summary="Get Persisted Pipeline Observability Metrics",
)
async def get_observability_metrics(
    sandbox_id: Optional[uuid.UUID] = Query(None, description="Optional sandbox filter"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns real persisted execution totals, average stage durations, retry counts, and outcomes."""
    decision = await authorize_action(
        user=current_user,
        operation="orchestration.metrics",
        capability="read",
        resource_type="observability_metrics",
        resource_id="global",
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    orchestrator = UnifiedOrchestrator(db)
    metrics_data = await orchestrator.get_observability_metrics(sandbox_id=sandbox_id)
    return PipelineObservabilityMetrics(**metrics_data)

