"""Red Team Agent orchestrating deterministic simulation execution, state, and audit.

Coordinates simulation runs under campaigns against synthetic assets inside sandbox environments.
Guarantees strict isolation, role-based authorization, database-level concurrency safety,
and complete fail-closed SHA-256 chained audit persistence.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Optional
import uuid

from fastapi import HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.red_team.scenario_registry import (
    RedTeamScenarioNotFoundError,
    ScenarioAssetIncompatibleError,
    registry,
)
from app.agents.red_team.schemas import SimulationResult
from app.models.attack_run import AttackRun
from app.models.campaign import Campaign
from app.models.user import User
from app.security.gateway import authorize_action
from app.services.audit_service import record_audit_log
from app.services.campaign_service import get_campaign_by_id, record_attack_run
from app.services.sandbox_service import (
    get_asset_by_id,
    get_sandbox_by_id,
    verify_sandbox_access,
)

logger = logging.getLogger("aegismesh.agents.red_team")


class RedTeamExecutionError(Exception):
    """Raised when an unrecoverable error occurs during Red Team execution."""
    pass


class RedTeamAgent:
    """Autonomous agent orchestrating deterministic Red Team simulation execution."""

    def __init__(self) -> None:
        self.registry = registry

    @property
    def engine(self):
        """Lazily access simulation engine to prevent circular imports."""
        from app.services.simulation_engine import simulation_engine
        return simulation_engine

    async def execute_run(
        self,
        session: AsyncSession,
        campaign_id: uuid.UUID,
        scenario_id: str,
        asset_id: uuid.UUID,
        user: User,
        parameters: Optional[dict[str, Any]] = None,
        run_id: Optional[uuid.UUID] = None,
    ) -> AttackRun:
        """Executes a deterministic attack simulation run within a campaign.

        Lifecycle:
        1. Record Audit: red_team.simulation_requested (fail-closed)
        2. Authorize via Security Gateway (OPA: redteam.simulate, sandbox only, admin/operator)
        3. Record Audit: red_team.authorization_passed (fail-closed)
        4. Validate Campaign, Sandbox, and Synthetic Asset boundaries
        5. Database-Level Concurrency Control: PostgreSQL advisory lock & duplicate run check
        6. Initialize AttackRun (pending -> running) and Record Audit: red_team.simulation_started
        7. Execute deterministic simulation via SimulationEngine
        8. On Success: complete AttackRun, Record Audit: red_team.simulation_completed, and commit
        9. On Failure: mark AttackRun failed, Record Audit: red_team.simulation_failed, and commit forensic evidence
        """
        audit_role = user.role.value if hasattr(user.role, "value") else str(user.role)

        # -----------------------------------------------------------------
        # Stage 1: Audit red_team.simulation_requested (Fail-Closed)
        # -----------------------------------------------------------------
        try:
            await record_audit_log(
                session=session,
                event_type="red_team.simulation_requested",
                action="redteam.simulate",
                resource_type="campaign",
                actor_id=user.id,
                actor_role=audit_role,
                resource_id=str(campaign_id),
                decision="REQUEST",
                event_data={
                    "campaign_id": str(campaign_id),
                    "scenario": scenario_id,
                    "asset_id": str(asset_id),
                    "simulation_only": True,
                },
            )
            await session.flush()
        except Exception as audit_err:
            logger.critical("Audit persistence failed at simulation_requested: %s", audit_err)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Security audit persistence failed; simulation execution aborted.",
            ) from audit_err

        # -----------------------------------------------------------------
        # Stage 2: Authorize action via Security Gateway
        # -----------------------------------------------------------------
        decision = await authorize_action(
            user=user,
            operation="redteam.simulate",
            capability="scan",
            resource_type="campaign",
            resource_id=str(campaign_id),
            environment="sandbox",
            risk_level="medium",
            session=session,
        )

        if not decision.allowed:
            logger.warning(
                "Red Team simulation execution denied for user '%s': %s",
                user.username,
                decision.reason,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Security Gateway authorization denied: {decision.reason}",
            )

        # -----------------------------------------------------------------
        # Stage 3: Audit red_team.authorization_passed (Fail-Closed)
        # -----------------------------------------------------------------
        try:
            await record_audit_log(
                session=session,
                event_type="red_team.authorization_passed",
                action="redteam.simulate",
                resource_type="campaign",
                actor_id=user.id,
                actor_role=audit_role,
                resource_id=str(campaign_id),
                decision="ALLOW",
                event_data={
                    "campaign_id": str(campaign_id),
                    "scenario": scenario_id,
                    "asset_id": str(asset_id),
                    "reason": decision.reason,
                    "simulation_only": True,
                },
            )
            await session.flush()
        except Exception as audit_err:
            logger.critical("Audit persistence failed at authorization_passed: %s", audit_err)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Security audit persistence failed; simulation execution aborted.",
            ) from audit_err

        # -----------------------------------------------------------------
        # Stage 4: Validate Campaign, Sandbox, Asset, and Scenario Compatibility
        # -----------------------------------------------------------------
        campaign = await get_campaign_by_id(session, campaign_id)
        if not campaign:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Campaign with ID '{campaign_id}' was not found.",
            )

        if campaign.environment != "sandbox":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Red Team simulation runs are strictly restricted to the 'sandbox' environment.",
            )

        sandbox_id = campaign.sandbox_id
        if not sandbox_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Campaign is not configured with an associated sandbox_id.",
            )

        sandbox = await get_sandbox_by_id(session, sandbox_id)
        if not sandbox:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Associated sandbox environment '{sandbox_id}' not found.",
            )

        if sandbox.status == "archived":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Associated sandbox environment '{sandbox.name}' is archived. Simulations cannot execute on archived environments.",
            )

        if not verify_sandbox_access(sandbox, user):
            logger.warning(
                "User '%s' is not authorized to execute simulations in sandbox '%s'",
                user.username,
                sandbox.id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: user is not authorized to interact with this sandbox environment.",
            )

        asset = await get_asset_by_id(session, asset_id)
        if not asset:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Target synthetic asset '{asset_id}' not found.",
            )

        if asset.sandbox_id != sandbox.id:
            logger.warning(
                "Cross-sandbox attack attempt: Asset '%s' (sandbox %s) does not belong to campaign sandbox %s",
                asset.id,
                asset.sandbox_id,
                sandbox.id,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cross-sandbox target asset access rejected. Asset does not belong to the campaign sandbox.",
            )

        try:
            scenario_def = self.registry.get(scenario_id)
        except RedTeamScenarioNotFoundError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            ) from e

        try:
            self.registry.validate_asset_compatibility(scenario_id, asset.asset_type)
        except ScenarioAssetIncompatibleError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(e),
            ) from e

        # -----------------------------------------------------------------
        # Stage 5: Database-Level Concurrency Control & Duplicate Prevention
        # -----------------------------------------------------------------
        # 5a. If an existing run_id was provided, enforce row-level lock and prevent re-execution
        existing_run: Optional[AttackRun] = None
        if run_id is not None:
            existing_run = (
                await session.execute(
                    select(AttackRun).where(AttackRun.id == run_id).with_for_update()
                )
            ).scalar_one_or_none()
            if not existing_run:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Attack run with ID '{run_id}' was not found.",
                )
            if existing_run.outcome in ["running", "completed"]:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Attack run '{run_id}' cannot be executed again (current outcome: '{existing_run.outcome}').",
                )

        # 5b. Acquire PostgreSQL transaction-level advisory lock on (campaign_id, scenario_id)
        bind = session.get_bind()
        dialect_name = bind.dialect.name if bind else "postgresql"
        if dialect_name == "postgresql":
            try:
                lock_res = await session.execute(
                    text("SELECT pg_try_advisory_xact_lock(hashtext(:c), hashtext(:s));"),
                    {"c": str(campaign.id), "s": str(scenario_id)},
                )
                lock_acquired = lock_res.scalar()
                if not lock_acquired:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=f"A simulation run is already actively running for scenario '{scenario_id}' in this campaign.",
                    )
            except HTTPException:
                raise
            except Exception as lock_err:
                logger.error("Advisory lock acquisition error: %s", lock_err)

        # 5c. Query active 'running' runs for this campaign and scenario
        active_run_query = select(AttackRun).where(
            AttackRun.campaign_id == campaign.id,
            AttackRun.outcome == "running",
            AttackRun.scenario == scenario_id,
        )
        existing_active = (await session.execute(active_run_query)).scalar_one_or_none()
        if existing_active:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"A simulation run is already actively running for scenario '{scenario_id}' in this campaign.",
            )

        # -----------------------------------------------------------------
        # Stage 6: Initialize AttackRun & Record Audit: red_team.simulation_started
        # -----------------------------------------------------------------
        if existing_run:
            run = existing_run
            run.outcome = "running"
            run.execution_metadata["status"] = "running"
            run.execution_metadata["started_at"] = datetime.now(timezone.utc).isoformat()
        else:
            run = await record_attack_run(
                session=session,
                campaign_id=campaign.id,
                technique=scenario_def.technique,
                scenario=scenario_id,
                outcome="running",
                risk_score=None,
                execution_metadata={
                    "status": "running",
                    "asset_id": str(asset.id),
                    "asset_name": asset.name,
                    "sandbox_id": str(sandbox.id),
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "simulation_only": True,
                },
            )

        if campaign.status == "pending":
            campaign.status = "in_progress"
            if not campaign.started_at:
                campaign.started_at = datetime.now(timezone.utc)

        await session.flush()

        try:
            await record_audit_log(
                session=session,
                event_type="red_team.simulation_started",
                action="redteam.simulate",
                resource_type="attack_run",
                actor_id=user.id,
                actor_role=audit_role,
                resource_id=str(run.id),
                decision="ALLOW",
                event_data={
                    "campaign_id": str(campaign.id),
                    "sandbox_id": str(sandbox.id),
                    "asset_id": str(asset.id),
                    "scenario": scenario_id,
                    "technique": scenario_def.technique,
                    "run_id": str(run.id),
                    "simulation_only": True,
                },
            )
            # Commit Phase 1: running status and started audit log are durably committed
            # This releases the global audit lock and registers the active run in DB
            await session.commit()
        except Exception as audit_err:
            logger.critical("Audit persistence failed at simulation_started: %s", audit_err)
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Security audit persistence failed; simulation run aborted and rolled back.",
            ) from audit_err

        # Re-fetch run into session after commit
        run = await session.get(AttackRun, run.id)

        # -----------------------------------------------------------------
        # Stage 7 & 8/9: Execute Simulation and Handle Completion or Failure
        # -----------------------------------------------------------------
        try:
            sim_result: SimulationResult = await self.engine.execute_simulation(
                scenario_id=scenario_id,
                asset=asset,
                parameters=parameters,
                session=session,
            )

            # Ensure event metadata fields are consistently populated
            for ev in sim_result.events:
                if not ev.scenario_id:
                    ev.scenario_id = scenario_id
                if not ev.campaign_id:
                    ev.campaign_id = str(campaign.id)
                if not ev.sandbox_id:
                    ev.sandbox_id = str(sandbox.id)
                if not ev.attack_run_id:
                    ev.attack_run_id = str(run.id)
                if not ev.source_asset_id:
                    ev.source_asset_id = str(asset.id)
                if not ev.event_metadata:
                    ev.event_metadata = dict(ev.details)

            # Stage 8: Success Lifecycle Transition & Audit
            run.outcome = "completed"
            run.risk_score = sim_result.risk_score
            run.execution_metadata = sim_result.model_dump(mode="json")
            await session.flush()

            await record_audit_log(
                session=session,
                event_type="red_team.simulation_completed",
                action="redteam.simulate",
                resource_type="attack_run",
                actor_id=user.id,
                actor_role=audit_role,
                resource_id=str(run.id),
                decision="ALLOW",
                event_data={
                    "campaign_id": str(campaign.id),
                    "sandbox_id": str(sandbox.id),
                    "asset_id": str(asset.id),
                    "scenario": scenario_id,
                    "technique": scenario_def.technique,
                    "risk_score": run.risk_score,
                    "findings_count": len(sim_result.findings),
                    "simulation_only": True,
                    "is_simulated": True,
                },
            )
            await session.commit()
            return run

        except HTTPException:
            raise

        except Exception as sim_err:
            logger.error("Simulation execution failure: %s", sim_err, exc_info=True)
            # Stage 9: Failure Lifecycle Transition & Forensic Audit Persistence
            # Ensure failed status and failure evidence are durably committed wherever DB is reachable
            try:
                run.outcome = "failed"
                run.execution_metadata = {
                    "status": "failed",
                    "error": str(sim_err),
                    "failed_at": datetime.now(timezone.utc).isoformat(),
                    "simulation_only": True,
                }
                await session.flush()

                await record_audit_log(
                    session=session,
                    event_type="red_team.simulation_failed",
                    action="redteam.simulate",
                    resource_type="attack_run",
                    actor_id=user.id,
                    actor_role=audit_role,
                    resource_id=str(run.id),
                    decision="DENY",
                    event_data={
                        "campaign_id": str(campaign.id),
                        "sandbox_id": str(sandbox.id),
                        "asset_id": str(asset.id),
                        "scenario": scenario_id,
                        "technique": scenario_def.technique,
                        "error": str(sim_err),
                        "simulation_only": True,
                    },
                )
                await session.commit()
            except Exception as persist_err:
                logger.critical("Failed to commit failure state for AttackRun %s: %s", run.id, persist_err)
                await session.rollback()

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Simulation execution failed: {sim_err}",
            ) from sim_err


# Singleton RedTeamAgent instance
red_team_agent = RedTeamAgent()
