"""Attack Path Orchestration API endpoints."""

import logging
import uuid
from typing import Optional
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.red_team.attack_path_schemas import (
    AttackPathCancelRequest,
    AttackPathExecuteRequest,
    AttackPathGraphResponse,
    AttackPathListResponse,
    AttackPathPlanRequest,
    AttackPathPlanResponse,
    AttackPathReportResponse,
    AttackPathResponse,
    AttackPathStageResponse,
)
from app.database.session import get_db
from app.models.attack_path import AttackPath
from app.models.attack_path_stage import AttackPathStage
from app.models.synthetic_asset import SyntheticAsset
from app.models.user import User
from app.core.permissions import get_current_user
from app.security.gateway import authorize_action
from app.services.attack_path_correlation import correlate_attack_path_events
from app.services.attack_path_planner import plan_attack_path
from app.services.attack_path_reconstruction import reconstruct_attack_path_graph
from app.services.attack_path_coordinator import cancel_attack_path, execute_attack_path
from app.services.campaign_service import get_campaign_by_id
from app.services.sandbox_service import get_sandbox_by_id
from app.services.audit_service import record_audit_log

logger = logging.getLogger("aegismesh.api.attack_paths")

router = APIRouter(prefix="/attack-paths", tags=["Attack Path Orchestration"])


def _stage_to_response(stage: AttackPathStage) -> AttackPathStageResponse:
    return AttackPathStageResponse(
        id=str(stage.id),
        attack_path_id=str(stage.attack_path_id),
        sequence_number=stage.sequence_number,
        scenario_id=stage.scenario_id,
        source_asset_id=str(stage.source_asset_id),
        destination_asset_id=str(stage.destination_asset_id) if stage.destination_asset_id else None,
        status=stage.status,
        prerequisites=stage.prerequisites or [],
        attack_run_id=str(stage.attack_run_id) if stage.attack_run_id else None,
        risk_score=stage.risk_score,
        stage_metadata=stage.stage_metadata or {},
        started_at=stage.started_at,
        completed_at=stage.completed_at,
        error_message=stage.error_message,
        simulation_only=stage.simulation_only,
        is_simulated=stage.is_simulated,
    )


def _path_to_response(ap: AttackPath) -> AttackPathResponse:
    stages_result = []
    for s in (ap.stages or []):
        stages_result.append(_stage_to_response(s))
    return AttackPathResponse(
        id=str(ap.id),
        campaign_id=str(ap.campaign_id),
        sandbox_id=str(ap.sandbox_id),
        source_asset_id=str(ap.source_asset_id),
        status=ap.status,
        execution_mode=ap.execution_mode,
        total_stages=ap.total_stages,
        completed_stages=ap.completed_stages,
        failed_stages=ap.failed_stages,
        risk_score=ap.risk_score,
        path_metadata=ap.path_metadata or {},
        execution_id=str(ap.execution_id) if ap.execution_id else None,
        simulation_only=ap.simulation_only,
        created_at=ap.created_at,
        completed_at=ap.completed_at,
        error_message=ap.error_message,
        stages=stages_result,
    )


@router.post("/plan", response_model=AttackPathPlanResponse, status_code=status.HTTP_201_CREATED)
async def plan_attack_path_endpoint(
    request: AttackPathPlanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Plans a multi-stage synthetic attack path."""
    audit_role = current_user.role.value if hasattr(current_user.role, "value") else str(current_user.role)

    # Authorize
    decision = await authorize_action(
        user=current_user,
        operation="attackpath.plan",
        capability="scan",
        resource_type="attack_path",
        resource_id=str(request.campaign_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    # Validate campaign
    campaign = await get_campaign_by_id(db, request.campaign_id)
    if not campaign:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Campaign not found.")
    if campaign.environment != "sandbox":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Campaign must be in sandbox environment.")

    # Validate sandbox
    sandbox_id = campaign.sandbox_id
    if not sandbox_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Campaign has no associated sandbox.")
    sandbox = await get_sandbox_by_id(db, sandbox_id)
    if not sandbox:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Sandbox not found.")
    if sandbox.status == "archived":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Sandbox is archived.")

    # Validate source asset
    source_asset = await db.get(SyntheticAsset, request.source_asset_id)
    if not source_asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source asset not found.")
    if source_asset.sandbox_id != sandbox.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Source asset does not belong to campaign sandbox.")
    if source_asset.status == "archived":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Source asset is archived.")

    # Validate destination asset if provided
    if request.destination_asset_id:
        dest_asset = await db.get(SyntheticAsset, request.destination_asset_id)
        if not dest_asset:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Destination asset not found.")
        if dest_asset.sandbox_id != sandbox.id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Destination asset does not belong to campaign sandbox.")
        if dest_asset.status == "archived":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Destination asset is archived.")

    try:
        attack_path, explanation, rejected = await plan_attack_path(
            session=db,
            campaign=campaign,
            sandbox=sandbox,
            source_asset=source_asset,
            destination_asset_id=request.destination_asset_id,
            execution_mode=request.execution_mode,
            scenario_constraints=request.scenario_constraints,
            max_stages=request.max_stages,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    await record_audit_log(
        session=db,
        event_type="attackpath.planned",
        action="attackpath.plan",
        resource_type="attack_path",
        actor_id=current_user.id,
        actor_role=audit_role,
        resource_id=str(attack_path.id),
        decision="ALLOW",
        event_data={
            "attack_path_id": str(attack_path.id),
            "campaign_id": str(campaign.id),
            "total_stages": attack_path.total_stages,
            "simulation_only": True,
        },
    )
    await db.commit()

    # Reload stages
    stages_result = await db.execute(
        select(AttackPathStage).where(AttackPathStage.attack_path_id == attack_path.id).order_by(AttackPathStage.sequence_number)
    )
    attack_path.stages = list(stages_result.scalars().all())

    # Build graph for response
    nodes, edges = await reconstruct_attack_path_graph(session=db, attack_path=attack_path)

    return AttackPathPlanResponse(
        attack_path=_path_to_response(attack_path),
        nodes=nodes,
        edges=edges,
        planning_explanation=explanation,
        rejected_candidates=rejected,
    )


@router.post("/{attack_path_id}/execute", response_model=AttackPathResponse)
async def execute_attack_path_endpoint(
    attack_path_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Executes a planned attack path sequentially."""
    decision = await authorize_action(
        user=current_user,
        operation="attackpath.execute",
        capability="scan",
        resource_type="attack_path",
        resource_id=str(attack_path_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    # Verify attack path exists
    ap = await db.get(AttackPath, attack_path_id)
    if not ap:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attack path not found.")

    try:
        result = await execute_attack_path(session=db, attack_path_id=attack_path_id, user=current_user)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

    # Load stages for response
    stages_result = await db.execute(
        select(AttackPathStage).where(AttackPathStage.attack_path_id == result.id).order_by(AttackPathStage.sequence_number)
    )
    result.stages = list(stages_result.scalars().all())

    return _path_to_response(result)


@router.get("", response_model=AttackPathListResponse)
async def list_attack_paths(
    campaign_id: Optional[uuid.UUID] = None,
    status: Optional[str] = None,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists attack paths with optional filtering."""
    decision = await authorize_action(
        user=current_user,
        operation="attackpath.read",
        capability="read",
        resource_type="attack_path",
        resource_id="*",
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    query = select(AttackPath)
    if campaign_id:
        query = query.where(AttackPath.campaign_id == campaign_id)
    if status:
        query = query.where(AttackPath.status == status)
    query = query.order_by(AttackPath.created_at.desc()).offset(skip).limit(limit)

    result = await db.execute(query)
    items = list(result.scalars().all())

    for item in items:
        stages_r = await db.execute(
            select(AttackPathStage).where(AttackPathStage.attack_path_id == item.id).order_by(AttackPathStage.sequence_number)
        )
        item.stages = list(stages_r.scalars().all())

    return AttackPathListResponse(
        items=[_path_to_response(ap) for ap in items],
        total=len(items),
        skip=skip,
        limit=limit,
    )


@router.get("/{attack_path_id}", response_model=AttackPathResponse)
async def get_attack_path(
    attack_path_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves a specific attack path."""
    decision = await authorize_action(
        user=current_user,
        operation="attackpath.read",
        capability="read",
        resource_type="attack_path",
        resource_id=str(attack_path_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    ap = await db.get(AttackPath, attack_path_id)
    if not ap:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attack path not found.")

    stages_r = await db.execute(
        select(AttackPathStage).where(AttackPathStage.attack_path_id == ap.id).order_by(AttackPathStage.sequence_number)
    )
    ap.stages = list(stages_r.scalars().all())

    return _path_to_response(ap)


@router.get("/{attack_path_id}/graph", response_model=AttackPathGraphResponse)
async def get_attack_path_graph(
    attack_path_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns the graph representation of an attack path."""
    decision = await authorize_action(
        user=current_user,
        operation="attackpath.read",
        capability="read",
        resource_type="attack_path",
        resource_id=str(attack_path_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    ap = await db.get(AttackPath, attack_path_id)
    if not ap:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attack path not found.")

    stages_r = await db.execute(
        select(AttackPathStage).where(AttackPathStage.attack_path_id == ap.id).order_by(AttackPathStage.sequence_number)
    )
    ap.stages = list(stages_r.scalars().all())

    nodes, edges = await reconstruct_attack_path_graph(session=db, attack_path=ap)

    return AttackPathGraphResponse(
        attack_path_id=str(ap.id),
        nodes=nodes,
        edges=edges,
    )


@router.get("/{attack_path_id}/report", response_model=AttackPathReportResponse)
async def get_attack_path_report(
    attack_path_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns a full forensic report for a completed attack path."""
    decision = await authorize_action(
        user=current_user,
        operation="attackpath.read",
        capability="read",
        resource_type="attack_path",
        resource_id=str(attack_path_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    ap = await db.get(AttackPath, attack_path_id)
    if not ap:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attack path not found.")

    stages_r = await db.execute(
        select(AttackPathStage).where(AttackPathStage.attack_path_id == ap.id).order_by(AttackPathStage.sequence_number)
    )
    ap.stages = list(stages_r.scalars().all())

    nodes, edges = await reconstruct_attack_path_graph(session=db, attack_path=ap)
    events = await correlate_attack_path_events(session=db, attack_path=ap)
    explanation = (ap.path_metadata or {}).get("planning_explanation", [])

    return AttackPathReportResponse(
        attack_path_id=str(ap.id),
        campaign_id=str(ap.campaign_id),
        sandbox_id=str(ap.sandbox_id),
        status=ap.status,
        execution_mode=ap.execution_mode,
        risk_score=ap.risk_score,
        total_stages=ap.total_stages,
        completed_stages=ap.completed_stages,
        failed_stages=ap.failed_stages,
        nodes=nodes,
        edges=edges,
        correlated_events=events,
        planning_explanation=explanation,
        created_at=ap.created_at,
        completed_at=ap.completed_at,
    )


@router.get("/{attack_path_id}/stages", response_model=list[AttackPathStageResponse])
async def get_attack_path_stages(
    attack_path_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns all stages for an attack path."""
    decision = await authorize_action(
        user=current_user,
        operation="attackpath.read",
        capability="read",
        resource_type="attack_path",
        resource_id=str(attack_path_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    ap = await db.get(AttackPath, attack_path_id)
    if not ap:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attack path not found.")

    stages_r = await db.execute(
        select(AttackPathStage).where(AttackPathStage.attack_path_id == ap.id).order_by(AttackPathStage.sequence_number)
    )
    stages = list(stages_r.scalars().all())
    return [_stage_to_response(s) for s in stages]


@router.post("/{attack_path_id}/cancel", response_model=AttackPathResponse)
async def cancel_attack_path_endpoint(
    attack_path_id: uuid.UUID,
    request: AttackPathCancelRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Cancels a planned or running attack path."""
    decision = await authorize_action(
        user=current_user,
        operation="attackpath.cancel",
        capability="scan",
        resource_type="attack_path",
        resource_id=str(attack_path_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

    try:
        ap = await cancel_attack_path(
            session=db,
            attack_path_id=attack_path_id,
            user=current_user,
            reason=request.reason or "",
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

    stages_r = await db.execute(
        select(AttackPathStage).where(AttackPathStage.attack_path_id == ap.id).order_by(AttackPathStage.sequence_number)
    )
    ap.stages = list(stages_r.scalars().all())

    return _path_to_response(ap)

