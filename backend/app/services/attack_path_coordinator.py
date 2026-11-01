"""Execution coordinator for multi-stage attack path execution."""

from datetime import datetime, timezone
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.red_team.agent import red_team_agent
from app.models.attack_path import AttackPath
from app.models.attack_path_stage import AttackPathStage
from app.models.synthetic_asset import SyntheticAsset
from app.models.user import User
from app.services.audit_service import record_audit_log
from app.services.attack_path_risk import calculate_path_risk
from app.services.sandbox_service import get_sandbox_by_id
from app.services.campaign_service import get_campaign_by_id

logger = logging.getLogger("aegismesh.services.attack_path_coordinator")

TERMINAL_STATUSES = {"completed", "partially_completed", "failed", "cancelled"}


async def _load_attack_path(session: AsyncSession, attack_path_id: uuid.UUID) -> AttackPath | None:
    """Loads AttackPath with a row-level lock and its stages."""
    result = await session.execute(
        select(AttackPath).where(AttackPath.id == attack_path_id).with_for_update()
    )
    return result.scalar_one_or_none()


async def execute_attack_path(
    session: AsyncSession,
    attack_path_id: uuid.UUID,
    user: User,
) -> AttackPath:
    """
    Executes a planned attack path stage by stage.

    Each stage calls RedTeamAgent.execute_run() which does its own commit.
    After each stage, we re-fetch from DB to get updated state.
    """
    audit_role = user.role.value if hasattr(user.role, "value") else str(user.role)

    # Load attack path with lock
    attack_path = await _load_attack_path(session, attack_path_id)
    if not attack_path:
        raise ValueError(f"Attack path '{attack_path_id}' not found.")

    # Idempotency check
    if attack_path.status in TERMINAL_STATUSES:
        raise ValueError(f"Attack path '{attack_path_id}' is already in terminal status '{attack_path.status}'.")
    if attack_path.status == "running":
        raise ValueError(f"Attack path '{attack_path_id}' is already running.")

    # Validate campaign and sandbox
    campaign = await get_campaign_by_id(session, attack_path.campaign_id)
    if not campaign or campaign.environment != "sandbox":
        raise ValueError("Campaign not found or not in sandbox environment.")

    sandbox = await get_sandbox_by_id(session, attack_path.sandbox_id)
    if not sandbox or sandbox.status == "archived":
        raise ValueError("Sandbox not found or is archived.")

    # Set execution ID and status
    execution_id = uuid.uuid4()
    attack_path.execution_id = execution_id
    attack_path.status = "running"
    await session.flush()

    # Audit: path execution started
    await record_audit_log(
        session=session,
        event_type="attackpath.execution_started",
        action="attackpath.execute",
        resource_type="attack_path",
        actor_id=user.id,
        actor_role=audit_role,
        resource_id=str(attack_path.id),
        decision="ALLOW",
        event_data={
            "attack_path_id": str(attack_path.id),
            "campaign_id": str(attack_path.campaign_id),
            "sandbox_id": str(attack_path.sandbox_id),
            "execution_id": str(execution_id),
            "total_stages": attack_path.total_stages,
            "simulation_only": True,
        },
    )
    await session.commit()

    # Execute stages sequentially
    # After commit, reload the path
    attack_path_id_val = attack_path_id
    completed_stage_risks: list[float] = []
    all_stage_risks: list[float] = []
    asset_risk_levels: list[str] = []
    completed_count = 0
    failed_count = 0

    # Get stages from DB again
    stages_result = await session.execute(
        select(AttackPathStage)
        .where(AttackPathStage.attack_path_id == attack_path_id_val)
        .order_by(AttackPathStage.sequence_number)
    )
    stages = list(stages_result.scalars().all())

    failed_stages_occurred = False

    for stage in stages:
        all_stage_risks.append(stage.risk_score or 0.0)

        if failed_stages_occurred:
            # Skip all subsequent stages
            stage.status = "skipped"
            stage.stage_metadata["skip_reason"] = "Upstream stage failed"
            await session.flush()
            continue

        # Set stage running
        stage.status = "running"
        stage.started_at = datetime.now(timezone.utc)
        await session.flush()
        await session.commit()

        try:
            # Build parameters for this stage
            parameters: dict = {}
            if stage.destination_asset_id:
                parameters["destination_asset_id"] = str(stage.destination_asset_id)

            # Re-fetch campaign_id from the attack_path
            ap_fresh = await session.get(AttackPath, attack_path_id_val)
            campaign_id_val = ap_fresh.campaign_id if ap_fresh else attack_path.campaign_id

            # Execute via RedTeamAgent — this will commit internally
            run = await red_team_agent.execute_run(
                session=session,
                campaign_id=campaign_id_val,
                scenario_id=stage.scenario_id,
                asset_id=stage.source_asset_id,
                user=user,
                parameters=parameters if parameters else None,
            )

            # After execute_run commits, update stage
            stage_fresh = await session.get(AttackPathStage, stage.id)
            if stage_fresh:
                stage_fresh.status = "completed"
                stage_fresh.completed_at = datetime.now(timezone.utc)
                stage_fresh.attack_run_id = run.id
                stage_fresh.risk_score = run.risk_score or stage.risk_score
                stage_fresh.stage_metadata = {
                    "attack_run_id": str(run.id),
                    "outcome": run.outcome,
                    "simulation_only": True,
                    "is_simulated": True,
                }
                await session.flush()
                await session.commit()
                completed_stage_risks.append(stage_fresh.risk_score or 0.0)
                completed_count += 1

                # Track asset risk level
                src_asset = await session.get(SyntheticAsset, stage.source_asset_id)
                if src_asset:
                    asset_risk_levels.append(src_asset.risk_level)

        except Exception as exc:
            logger.error("Stage %d failed: %s", stage.sequence_number, exc, exc_info=True)
            # Mark stage failed
            stage_fresh = await session.get(AttackPathStage, stage.id)
            if stage_fresh:
                stage_fresh.status = "failed"
                stage_fresh.completed_at = datetime.now(timezone.utc)
                stage_fresh.error_message = str(exc)
                stage_fresh.stage_metadata = {"error": str(exc), "simulation_only": True}
                await session.flush()
                await session.commit()
            failed_count += 1
            failed_stages_occurred = True

    # Final: update attack path status and risk score
    ap_final = await session.get(AttackPath, attack_path_id_val)
    if ap_final:
        total_s = ap_final.total_stages or len(stages)
        if failed_count == 0:
            ap_final.status = "completed"
        elif completed_count > 0:
            ap_final.status = "partially_completed"
        else:
            ap_final.status = "failed"

        ap_final.completed_stages = completed_count
        ap_final.failed_stages = failed_count
        ap_final.completed_at = datetime.now(timezone.utc)

        ap_final.risk_score = calculate_path_risk(
            completed_stage_risk_scores=completed_stage_risks,
            all_stage_risk_scores=all_stage_risks,
            asset_risk_levels=asset_risk_levels,
            total_stages=total_s,
            completed_stages=completed_count,
        )

        await session.flush()

        # Audit: path execution completed
        await record_audit_log(
            session=session,
            event_type="attackpath.execution_completed",
            action="attackpath.execute",
            resource_type="attack_path",
            actor_id=user.id,
            actor_role=audit_role,
            resource_id=str(ap_final.id),
            decision="ALLOW",
            event_data={
                "attack_path_id": str(ap_final.id),
                "status": ap_final.status,
                "completed_stages": ap_final.completed_stages,
                "failed_stages": ap_final.failed_stages,
                "risk_score": ap_final.risk_score,
                "simulation_only": True,
            },
        )
        await session.commit()
        return ap_final

    return ap_fresh


async def cancel_attack_path(
    session: AsyncSession,
    attack_path_id: uuid.UUID,
    user: User,
    reason: str = "",
) -> AttackPath:
    """Cancels a planned or running attack path."""
    audit_role = user.role.value if hasattr(user.role, "value") else str(user.role)

    result = await session.execute(
        select(AttackPath).where(AttackPath.id == attack_path_id).with_for_update()
    )
    attack_path = result.scalar_one_or_none()
    if not attack_path:
        raise ValueError(f"Attack path '{attack_path_id}' not found.")

    if attack_path.status in {"completed", "partially_completed", "failed", "cancelled"}:
        raise ValueError(f"Cannot cancel attack path in terminal status '{attack_path.status}'.")

    attack_path.status = "cancelled"
    attack_path.completed_at = datetime.now(timezone.utc)
    attack_path.error_message = reason or "Cancelled by user"
    await session.flush()

    # Cancel pending stages
    stages_result = await session.execute(
        select(AttackPathStage).where(
            AttackPathStage.attack_path_id == attack_path_id,
            AttackPathStage.status == "pending",
        )
    )
    for stage in stages_result.scalars().all():
        stage.status = "skipped"
        stage.stage_metadata["skip_reason"] = "Path cancelled"

    await session.flush()

    await record_audit_log(
        session=session,
        event_type="attackpath.cancelled",
        action="attackpath.cancel",
        resource_type="attack_path",
        actor_id=user.id,
        actor_role=audit_role,
        resource_id=str(attack_path.id),
        decision="ALLOW",
        event_data={
            "attack_path_id": str(attack_path.id),
            "reason": reason,
            "simulation_only": True,
        },
    )
    await session.commit()
    return attack_path
