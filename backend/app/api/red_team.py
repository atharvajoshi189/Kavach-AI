"""API endpoints for Red Team deterministic attack simulation operations."""

import logging
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.red_team.agent import red_team_agent
from app.agents.red_team.schemas import (
    RedTeamRunCreateRequest,
    RedTeamRunDetailResponse,
    RedTeamRunResponse,
    ScenarioMetadataResponse,
)
from app.core.permissions import get_current_user
from app.database.session import get_db
from app.models.user import User
from app.security.gateway import authorize_action
from app.services.campaign_service import get_attack_run_by_id
from app.services.simulation_engine import simulation_engine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/red-team", tags=["Red Team Simulation"])


@router.get(
    "/scenarios",
    response_model=list[ScenarioMetadataResponse],
    status_code=status.HTTP_200_OK,
    summary="List Red Team Scenarios",
    description="Retrieves metadata for all registered deterministic Red Team simulation scenarios.",
)
async def list_scenarios(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[ScenarioMetadataResponse]:
    """Lists available Red Team scenarios, subject to Security Gateway policy authorization."""
    decision = await authorize_action(
        user=current_user,
        operation="redteam.scenario_list",
        capability="read",
        resource_type="scenario",
        resource_id="all",
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Security Gateway authorization denied: {decision.reason}",
        )

    return simulation_engine.list_available_scenarios()


@router.post(
    "/campaigns/{campaign_id}/runs",
    response_model=RedTeamRunResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Execute Red Team Simulation Run",
    description="Triggers a deterministic attack simulation run within an authorized campaign against a synthetic asset.",
)
async def execute_run(
    campaign_id: uuid.UUID,
    payload: RedTeamRunCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> RedTeamRunResponse:
    """Executes a deterministic Red Team simulation under the specified campaign."""
    run = await red_team_agent.execute_run(
        session=db,
        campaign_id=campaign_id,
        scenario_id=payload.scenario,
        asset_id=payload.asset_id,
        user=current_user,
        parameters=payload.parameters,
    )
    return RedTeamRunResponse(
        run_id=run.id,
        campaign_id=run.campaign_id,
        scenario=run.scenario,
        technique=run.technique,
        outcome=run.outcome,
        risk_score=run.risk_score,
        created_at=run.created_at,
        simulation_only=True,
    )


@router.get(
    "/runs/{run_id}",
    response_model=RedTeamRunDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Simulation Run Details",
    description="Retrieves execution metadata, events, and findings for a specific Red Team simulation run.",
)
async def get_run_details(
    run_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> RedTeamRunDetailResponse:
    """Retrieves detailed simulation run metadata including events and findings."""
    decision = await authorize_action(
        user=current_user,
        operation="redteam.run_read",
        capability="read",
        resource_type="attack_run",
        resource_id=str(run_id),
        environment="sandbox",
        session=db,
    )
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Security Gateway authorization denied: {decision.reason}",
        )

    run = await get_attack_run_by_id(session=db, run_id=run_id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Attack simulation run with ID '{run_id}' not found.",
        )

    return RedTeamRunDetailResponse(
        run_id=run.id,
        campaign_id=run.campaign_id,
        scenario=run.scenario,
        technique=run.technique,
        outcome=run.outcome,
        risk_score=run.risk_score,
        execution_metadata=run.execution_metadata or {},
        created_at=run.created_at,
        simulation_only=True,
    )

