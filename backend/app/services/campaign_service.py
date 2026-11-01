"""Data access and repository services for Campaigns, AttackRuns, ToolActions, and Evaluations."""

from datetime import datetime, timezone
from typing import Any, Optional
import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.attack_run import AttackRun
from app.models.campaign import Campaign
from app.models.evaluation import Evaluation
from app.models.tool_action import ToolAction


# --- Campaigns ---

async def create_campaign(
    session: AsyncSession,
    name: str,
    trigger_type: str,
    agent_id: Optional[uuid.UUID] = None,
    environment: str = "sandbox",
    configuration: Optional[dict[str, Any]] = None,
    sandbox_id: Optional[uuid.UUID] = None,
) -> Campaign:
    """Creates a new campaign execution record."""
    config = dict(configuration or {})
    if sandbox_id is not None:
        config["sandbox_id"] = str(sandbox_id)

    campaign = Campaign(
        name=name,
        trigger_type=trigger_type,
        agent_id=agent_id,
        environment=environment,
        configuration=config,
        status="pending",
    )
    session.add(campaign)
    await session.flush()
    return campaign


async def get_campaign_by_id(session: AsyncSession, campaign_id: uuid.UUID) -> Optional[Campaign]:
    """Retrieves a Campaign by UUID.
    
    If not found directly, checks if campaign_id corresponds to a valid SandboxEnvironment,
    and returns (or auto-provisions) an active simulation campaign scoped to that sandbox.
    """
    result = await session.execute(select(Campaign).where(Campaign.id == campaign_id))
    camp = result.scalar_one_or_none()
    if camp:
        return camp

    try:
        from app.models.sandbox import SandboxEnvironment
        sb_res = await session.execute(select(SandboxEnvironment).where(SandboxEnvironment.id == campaign_id))
        sb = sb_res.scalar_one_or_none()
        if sb:
            new_camp = Campaign(
                id=campaign_id,
                name=f"Autonomous Simulation Campaign - {sb.name}",
                trigger_type="manual",
                status="active",
                environment="sandbox",
                configuration={"sandbox_id": str(sb.id), "auto_created": True},
            )
            session.add(new_camp)
            await session.flush()
            return new_camp
    except Exception:
        pass

    return None


async def get_active_campaign_for_sandbox(session: AsyncSession, sandbox_id: uuid.UUID) -> Campaign:
    """Finds an existing active campaign for the sandbox or auto-provisions one."""
    camp = await get_campaign_by_id(session, sandbox_id)
    if camp:
        return camp

    # Query by configuration sandbox_id
    query = select(Campaign).where(Campaign.environment == "sandbox")
    camps = (await session.execute(query)).scalars().all()
    for c in camps:
        if c.sandbox_id == sandbox_id and c.status != "completed":
            return c

    # Create new campaign
    from app.models.sandbox import SandboxEnvironment
    sb = await session.get(SandboxEnvironment, sandbox_id)
    sb_name = sb.name if sb else str(sandbox_id)[:8]
    return await create_campaign(
        session=session,
        name=f"Campaign-{sb_name}",
        trigger_type="manual",
        environment="sandbox",
        sandbox_id=sandbox_id,
    )


async def list_campaigns(
    session: AsyncSession,
    environment: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
) -> list[Campaign]:
    """Lists campaigns with optional filtering."""
    query = select(Campaign)
    if environment:
        query = query.where(Campaign.environment == environment)
    if status:
        query = query.where(Campaign.status == status)
    query = query.order_by(Campaign.created_at.desc()).offset(skip).limit(limit)
    result = await session.execute(query)
    return list(result.scalars().all())


async def update_campaign_status(
    session: AsyncSession,
    campaign_id: uuid.UUID,
    status: str,
    started_at: Optional[datetime] = None,
    completed_at: Optional[datetime] = None,
) -> Optional[Campaign]:
    """Updates status and execution timestamps for a Campaign."""
    campaign = await get_campaign_by_id(session, campaign_id)
    if not campaign:
        return None
    campaign.status = status
    if started_at:
        campaign.started_at = started_at
    if completed_at:
        campaign.completed_at = completed_at
    await session.flush()
    return campaign


# --- AttackRuns ---

async def record_attack_run(
    session: AsyncSession,
    campaign_id: uuid.UUID,
    technique: str,
    scenario: str,
    outcome: str,
    risk_score: Optional[float] = None,
    execution_metadata: Optional[dict[str, Any]] = None,
) -> AttackRun:
    """Persists a specific offensive technique execution run."""
    run = AttackRun(
        campaign_id=campaign_id,
        technique=technique,
        scenario=scenario,
        outcome=outcome,
        risk_score=risk_score,
        execution_metadata=execution_metadata or {},
    )
    session.add(run)
    await session.flush()
    return run


async def get_attack_runs_by_campaign(
    session: AsyncSession,
    campaign_id: uuid.UUID,
) -> list[AttackRun]:
    """Retrieves all attack execution runs for a given campaign."""
    query = (
        select(AttackRun)
        .where(AttackRun.campaign_id == campaign_id)
        .order_by(AttackRun.created_at.asc())
    )
    result = await session.execute(query)
    return list(result.scalars().all())


async def get_attack_run_by_id(
    session: AsyncSession,
    run_id: uuid.UUID,
) -> Optional[AttackRun]:
    """Retrieves an attack execution run by primary key UUID."""
    result = await session.execute(select(AttackRun).where(AttackRun.id == run_id))
    return result.scalar_one_or_none()


# --- ToolActions ---

async def record_tool_action(
    session: AsyncSession,
    action_name: str,
    resource: str,
    decision: str,
    executed: bool = False,
    agent_id: Optional[uuid.UUID] = None,
    campaign_id: Optional[uuid.UUID] = None,
    reason: Optional[str] = None,
    environment: str = "sandbox",
) -> ToolAction:
    """Records an attempted or executed tool capability action."""
    action = ToolAction(
        action_name=action_name,
        resource=resource,
        decision=decision,
        executed=executed,
        agent_id=agent_id,
        campaign_id=campaign_id,
        reason=reason,
        environment=environment,
    )
    session.add(action)
    await session.flush()
    return action


async def get_tool_actions_by_campaign(
    session: AsyncSession,
    campaign_id: uuid.UUID,
) -> list[ToolAction]:
    """Retrieves tool actions performed within a campaign."""
    query = (
        select(ToolAction)
        .where(ToolAction.campaign_id == campaign_id)
        .order_by(ToolAction.created_at.asc())
    )
    result = await session.execute(query)
    return list(result.scalars().all())


# --- Evaluations ---

async def record_evaluation(
    session: AsyncSession,
    campaign_id: uuid.UUID,
    detection_rate: Optional[float] = None,
    attack_success_rate: Optional[float] = None,
    false_positive_rate: Optional[float] = None,
    false_negative_rate: Optional[float] = None,
    utility_rate: Optional[float] = None,
    mean_latency_ms: Optional[float] = None,
    metrics: Optional[dict[str, Any]] = None,
) -> Evaluation:
    """Records security benchmarks and calculated evaluation rates."""
    evaluation = Evaluation(
        campaign_id=campaign_id,
        detection_rate=detection_rate,
        attack_success_rate=attack_success_rate,
        false_positive_rate=false_positive_rate,
        false_negative_rate=false_negative_rate,
        utility_rate=utility_rate,
        mean_latency_ms=mean_latency_ms,
        metrics=metrics or {},
    )
    session.add(evaluation)
    await session.flush()
    return evaluation


async def get_evaluations_by_campaign(
    session: AsyncSession,
    campaign_id: uuid.UUID,
) -> list[Evaluation]:
    """Retrieves evaluation metric records for a campaign."""
    query = (
        select(Evaluation)
        .where(Evaluation.campaign_id == campaign_id)
        .order_by(Evaluation.created_at.desc())
    )
    result = await session.execute(query)
    return list(result.scalars().all())

