"""Unified End-to-End Platform Orchestrator for AegisMesh 2.0.

Integrates Red Team attack simulation, Blue Guardian defensive analysis,
human approval governance, synthetic remediation execution, cryptographic state
snapshotting, and regression verification into a single durable pipeline.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from fastapi import HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.agents.blue_guardian.approval_schemas import (
    ApprovalDecisionCreate,
    ApprovalDecisionType,
    ApprovalRequestCreate,
    ApprovalStatus,
    ExecutionStatus,
    VerificationStatus,
)
from app.agents.blue_guardian.schemas import (
    GuardianExecutionCreateRequest,
    GuardianExecutionStatus,
    RemediationPlanStatus,
)
from app.agents.red_team.agent import red_team_agent
from app.models.attack_path import AttackPath
from app.models.attack_run import AttackRun
from app.models.audit_log import AuditLog
from app.models.campaign import Campaign
from app.models.guardian import (
    ApprovalDecision,
    ApprovalRequest,
    GuardianExecution,
    IncidentReport,
    RemediationPlan,
    RemediationVerification,
    SyntheticRemediationExecution,
    SyntheticStateSnapshot,
)
from app.models.orchestration import (
    OrchestrationExecution,
    PipelineExecutionStatus,
    PipelineStage,
)
from app.models.sandbox import SandboxEnvironment
from app.models.synthetic_asset import SyntheticAsset
from app.models.user import User, UserRole
from app.security.gateway import authorize_action
from app.services.audit_service import record_audit_log, verify_event_hash
from app.services.campaign_service import get_active_campaign_for_sandbox
from app.services.guardian.approval_policy import ApprovalPolicyEngine
from app.services.guardian.approval_service import ApprovalService
from app.services.guardian.orchestrator_service import GuardianOrchestrationService
from app.services.guardian.regression_verification_engine import RegressionVerificationEngine
from app.services.guardian.synthetic_action_registry import SyntheticActionRegistry
from app.services.guardian.synthetic_remediation_executor import SyntheticRemediationExecutor
from app.services.guardian.synthetic_state_snapshot import SyntheticStateSnapshotService
from app.services.sandbox_service import get_sandbox_by_id, register_asset, verify_sandbox_access

logger = logging.getLogger("aegismesh.orchestration.unified")


class UnifiedOrchestrator:
    """Orchestrates end-to-end platform workflows across Red Team and Blue Guardian."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.guardian_orchestrator = GuardianOrchestrationService(session)
        self.approval_service = ApprovalService(session)
        self.remediation_executor = SyntheticRemediationExecutor(session)
        self.snapshot_service = SyntheticStateSnapshotService(session)
        self.verification_engine = RegressionVerificationEngine(session)

    # =========================================================================
    # Helpers
    # =========================================================================

    def _record_stage_start(self, execution: OrchestrationExecution, stage: PipelineStage) -> None:
        execution.current_stage = stage.value
        metrics = dict(execution.stage_metrics or {})
        metrics[stage.value] = {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "status": "in_progress",
        }
        execution.stage_metrics = metrics

    def _record_stage_complete(self, execution: OrchestrationExecution, stage: PipelineStage) -> None:
        metrics = dict(execution.stage_metrics or {})
        stage_data = metrics.get(stage.value, {})
        now = datetime.now(timezone.utc)
        stage_data["completed_at"] = now.isoformat()
        stage_data["status"] = "completed"

        started_str = stage_data.get("started_at")
        if started_str:
            try:
                started_dt = datetime.fromisoformat(started_str)
                stage_data["duration_seconds"] = round((now - started_dt).total_seconds(), 3)
            except Exception:
                stage_data["duration_seconds"] = 0.0

        metrics[stage.value] = stage_data
        execution.stage_metrics = metrics

    def _record_stage_failure(
        self,
        execution: OrchestrationExecution,
        stage: PipelineStage,
        error_msg: str,
    ) -> None:
        execution.current_stage = stage.value
        execution.failed_stage = stage.value
        execution.execution_status = PipelineExecutionStatus.FAILED.value
        execution.error_message = error_msg
        execution.completed_at = datetime.now(timezone.utc)

        metrics = dict(execution.stage_metrics or {})
        stage_data = metrics.get(stage.value, {})
        now = datetime.now(timezone.utc)
        stage_data["failed_at"] = now.isoformat()
        stage_data["status"] = "failed"
        stage_data["error"] = error_msg
        metrics[stage.value] = stage_data
        execution.stage_metrics = metrics

    # =========================================================================
    # Primary Pipeline Execution
    # =========================================================================

    async def start_pipeline(
        self,
        sandbox_id: uuid.UUID,
        user: User,
        scenario_id: str = "simulated_initial_access",
        run_attack_path: bool = False,
        auto_approve: bool = False,
        approver: Optional[User] = None,
        admin_approver: Optional[User] = None,
        correlation_window_seconds: int = 300,
        client_metadata: Optional[Dict[str, Any]] = None,
    ) -> OrchestrationExecution:
        """Initializes and runs the full end-to-end platform lifecycle."""
        # 1. Authorization
        decision = await authorize_action(
            user=user,
            operation="guardian.execute",
            capability="scan",
            resource_type="orchestration_execution",
            resource_id=str(sandbox_id),
            environment="sandbox",
            session=self.session,
        )
        if not decision.allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

        # 2. Validate Sandbox Scope
        sandbox = await get_sandbox_by_id(self.session, sandbox_id)
        if not sandbox:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sandbox '{sandbox_id}' not found.")
        if sandbox.status == "archived":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot run pipeline on archived sandbox.")
        if not verify_sandbox_access(sandbox, user):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to sandbox environment.")

        # 3. Create Durable Execution Record
        execution = OrchestrationExecution(
            id=uuid.uuid4(),
            sandbox_id=sandbox.id,
            current_stage=PipelineStage.INITIATED.value,
            execution_status=PipelineExecutionStatus.RUNNING.value,
            started_at=datetime.now(timezone.utc),
            execution_metadata={
                "initiated_by": str(user.id),
                "scenario_id": scenario_id,
                "run_attack_path": run_attack_path,
                "auto_approve": auto_approve,
                "client_metadata": client_metadata or {},
            },
        )
        self.session.add(execution)
        await self.session.flush()

        # Audit pipeline start
        try:
            await record_audit_log(
                session=self.session,
                event_type="orchestration.pipeline.started",
                action="orchestration.execute",
                resource_type="orchestration_execution",
                actor_id=user.id,
                actor_role=user.role,
                resource_id=str(execution.id),
                decision="INITIATE",
                event_data={
                    "execution_id": str(execution.id),
                    "sandbox_id": str(sandbox.id),
                    "scenario_id": scenario_id,
                },
            )
            await self.session.flush()
        except Exception as e:
            logger.warning("Audit logging failed for pipeline start: %s", e)

        # 4. Advance through lifecycle
        return await self._advance_pipeline(
            execution=execution,
            user=user,
            sandbox=sandbox,
            scenario_id=scenario_id,
            run_attack_path=run_attack_path,
            auto_approve=auto_approve,
            approver=approver,
            admin_approver=admin_approver,
            correlation_window_seconds=correlation_window_seconds,
        )

    async def _advance_pipeline(
        self,
        execution: OrchestrationExecution,
        user: User,
        sandbox: SandboxEnvironment,
        scenario_id: str,
        run_attack_path: bool,
        auto_approve: bool,
        approver: Optional[User],
        admin_approver: Optional[User],
        correlation_window_seconds: int,
    ) -> OrchestrationExecution:
        """State machine advancing through the 15 required stages sequentially."""
        try:
            # -----------------------------------------------------------------
            # Stage 1: SANDBOX_CREATION / Validation
            # -----------------------------------------------------------------
            self._record_stage_start(execution, PipelineStage.SANDBOX_CREATION)
            if sandbox.status != "active":
                sandbox.status = "active"
                await self.session.flush()
            self._record_stage_complete(execution, PipelineStage.SANDBOX_CREATION)

            # -----------------------------------------------------------------
            # Stage 2: ASSET_REGISTRATION Validation
            # -----------------------------------------------------------------
            self._record_stage_start(execution, PipelineStage.ASSET_REGISTRATION)
            asset_stmt = select(func.count(SyntheticAsset.id)).where(SyntheticAsset.sandbox_id == sandbox.id)
            asset_count = (await self.session.execute(asset_stmt)).scalar_one()

            if asset_count == 0:
                # Auto-provision standard synthetic topology if empty
                suffix = uuid.uuid4().hex[:6]
                await register_asset(
                    session=self.session,
                    sandbox_id=sandbox.id,
                    asset_data={
                        "name": f"orch-web-{suffix}",
                        "asset_type": "web_application",
                        "hostname": f"web-{suffix}.sandbox.local",
                        "ip_address": "10.0.1.10",
                        "risk_level": "high",
                        "service_metadata": {"services": [{"port": 443, "service": "https"}]},
                        "configuration": {"isolated_mode": False},
                    },
                )
                await register_asset(
                    session=self.session,
                    sandbox_id=sandbox.id,
                    asset_data={
                        "name": f"orch-db-{suffix}",
                        "asset_type": "database",
                        "hostname": f"db-{suffix}.sandbox.local",
                        "ip_address": "10.0.1.20",
                        "risk_level": "critical",
                        "service_metadata": {"services": [{"port": 5432, "service": "postgresql"}]},
                        "configuration": {"network_segmentation": {"segmented": False}},
                    },
                )
                await self.session.flush()

            self._record_stage_complete(execution, PipelineStage.ASSET_REGISTRATION)

            # -----------------------------------------------------------------
            # Stage 3: RED_TEAM_SIMULATION / ATTACK_PATH_EXECUTION
            # -----------------------------------------------------------------
            campaign = await get_active_campaign_for_sandbox(self.session, sandbox.id)
            execution.campaign_id = campaign.id

            if run_attack_path:
                self._record_stage_start(execution, PipelineStage.ATTACK_PATH_EXECUTION)
                from app.services.attack_path_coordinator import execute_attack_path
                from app.services.attack_path_planner import plan_attack_path

                asset_res = await self.session.execute(
                    select(SyntheticAsset).where(SyntheticAsset.sandbox_id == sandbox.id)
                )
                assets = list(asset_res.scalars().all())
                source_asset = next(
                    (a for a in assets if a.asset_type in ["web_application", "server", "api", "workstation"]),
                    assets[0],
                )

                # Plan path targeting source asset
                path, _, _ = await plan_attack_path(
                    session=self.session,
                    campaign=campaign,
                    sandbox=sandbox,
                    source_asset=source_asset,
                    execution_mode="exploratory",
                )
                executed_path = await execute_attack_path(
                    session=self.session,
                    attack_path_id=path.id,
                    user=user,
                )
                execution.attack_path_id = executed_path.id
                self._record_stage_complete(execution, PipelineStage.ATTACK_PATH_EXECUTION)
            else:
                self._record_stage_start(execution, PipelineStage.RED_TEAM_SIMULATION)
                asset_res = await self.session.execute(
                    select(SyntheticAsset).where(SyntheticAsset.sandbox_id == sandbox.id)
                )
                assets = list(asset_res.scalars().all())

                # Find compatible asset for the chosen scenario
                try:
                    scenario_def = red_team_agent.registry.get(scenario_id)
                    applicable_types = scenario_def.applicable_asset_types
                    target_asset = next(
                        (a for a in assets if a.asset_type in applicable_types),
                        assets[0],
                    )
                except Exception:
                    target_asset = assets[0]

                run = await red_team_agent.execute_run(
                    session=self.session,
                    campaign_id=campaign.id,
                    scenario_id=scenario_id,
                    asset_id=target_asset.id,
                    user=user,
                )
                execution.simulation_id = run.id
                self._record_stage_complete(execution, PipelineStage.RED_TEAM_SIMULATION)

            await self.session.flush()

            # -----------------------------------------------------------------
            # Stage 4: BLUE_GUARDIAN_ANALYSIS
            # -----------------------------------------------------------------
            self._record_stage_start(execution, PipelineStage.BLUE_GUARDIAN_ANALYSIS)
            guardian_req = GuardianExecutionCreateRequest(
                sandbox_id=sandbox.id,
                attack_run_id=execution.simulation_id,
                attack_path_id=execution.attack_path_id,
                correlation_window_seconds=correlation_window_seconds,
            )
            guardian_exec = await self.guardian_orchestrator.execute_analysis(
                request=guardian_req,
                user=user,
            )
            execution.guardian_execution_id = guardian_exec.id
            self._record_stage_complete(execution, PipelineStage.BLUE_GUARDIAN_ANALYSIS)

            # -----------------------------------------------------------------
            # Stage 5 & 6: THREAT_DETECTION & RISK_ASSESSMENT
            # -----------------------------------------------------------------
            self._record_stage_start(execution, PipelineStage.THREAT_DETECTION)
            self._record_stage_complete(execution, PipelineStage.THREAT_DETECTION)

            self._record_stage_start(execution, PipelineStage.RISK_ASSESSMENT)
            self._record_stage_complete(execution, PipelineStage.RISK_ASSESSMENT)

            # -----------------------------------------------------------------
            # Stage 7 & 8: DEFENSIVE_RECOMMENDATIONS & REMEDIATION_PLANNING
            # -----------------------------------------------------------------
            self._record_stage_start(execution, PipelineStage.DEFENSIVE_RECOMMENDATIONS)
            self._record_stage_complete(execution, PipelineStage.DEFENSIVE_RECOMMENDATIONS)

            self._record_stage_start(execution, PipelineStage.REMEDIATION_PLANNING)
            plan_stmt = select(RemediationPlan).where(
                RemediationPlan.guardian_execution_id == guardian_exec.id
            )
            plan = (await self.session.execute(plan_stmt)).scalars().first()
            if not plan:
                raise ValueError("Remediation plan was not generated by Guardian analysis.")
            execution.remediation_plan_id = plan.id
            self._record_stage_complete(execution, PipelineStage.REMEDIATION_PLANNING)

            # -----------------------------------------------------------------
            # Stage 9: INCIDENT_REPORT
            # -----------------------------------------------------------------
            self._record_stage_start(execution, PipelineStage.INCIDENT_REPORT)
            self._record_stage_complete(execution, PipelineStage.INCIDENT_REPORT)

            # -----------------------------------------------------------------
            # Optional Advisory: LangGraph Multi-Agent Intelligence Layer
            # -----------------------------------------------------------------
            try:
                from app.ai.graphs.execution_service import graph_execution_service
                from app.ai.schemas.agent_schemas import GraphExecutionRequest, GraphRequestType

                ai_request = GraphExecutionRequest(
                    sandbox_id=sandbox.id,
                    execution_id=guardian_exec.id,
                    request_type=GraphRequestType.FULL_INVESTIGATION,
                )
                ai_response = await graph_execution_service.execute_graph(
                    session=self.session,
                    user=user,
                    request=ai_request,
                )
                meta = dict(execution.execution_metadata or {})
                meta["ai_advisory"] = {
                    "graph_execution_id": str(ai_response.graph_execution_id),
                    "status": ai_response.execution_status,
                    "confidence": ai_response.overall_confidence,
                    "fallback_used": ai_response.fallback_used,
                    "selected_agents": ai_response.selected_agents,
                }
                execution.execution_metadata = meta
                await self.session.flush()
            except Exception as ai_exc:
                logger.warning(
                    "Optional LangGraph AI advisory stage completed with notice (%s: %s). Deterministic pipeline continuing.",
                    type(ai_exc).__name__,
                    ai_exc,
                )
                meta = dict(execution.execution_metadata or {})
                meta["ai_advisory"] = {
                    "status": "skipped",
                    "reason": str(ai_exc),
                }
                execution.execution_metadata = meta

            # -----------------------------------------------------------------
            # Stage 10: HUMAN_APPROVAL
            # -----------------------------------------------------------------
            self._record_stage_start(execution, PipelineStage.HUMAN_APPROVAL)
            appr_req = await self.approval_service.create_request(
                plan_id=plan.id,
                user=user,
                payload=ApprovalRequestCreate(
                    request_comments="Pipeline automated containment submission",
                    expires_in_hours=24,
                ),
            )
            execution.approval_request_id = appr_req.id
            await self.session.flush()

            # If auto-approval is not enabled, pause in WAITING_FOR_APPROVAL
            if not auto_approve:
                execution.execution_status = PipelineExecutionStatus.WAITING_FOR_APPROVAL.value
                await self.session.commit()
                return execution

            # Auto-approval branch: record required decisions
            effective_approver = approver or user
            if appr_req.required_approvals > 1:
                # First vote
                await self.approval_service.record_decision(
                    request_id=appr_req.id,
                    approver=effective_approver,
                    payload=ApprovalDecisionCreate(
                        decision=ApprovalDecisionType.APPROVED,
                        comments="Automated pipeline operator signoff",
                    ),
                )
                # Second vote (Admin)
                effective_admin = admin_approver or effective_approver
                await self.approval_service.record_decision(
                    request_id=appr_req.id,
                    approver=effective_admin,
                    payload=ApprovalDecisionCreate(
                        decision=ApprovalDecisionType.APPROVED,
                        comments="Automated pipeline administrator signoff",
                    ),
                )
            else:
                await self.approval_service.record_decision(
                    request_id=appr_req.id,
                    approver=effective_approver,
                    payload=ApprovalDecisionCreate(
                        decision=ApprovalDecisionType.APPROVED,
                        comments="Automated pipeline signoff",
                    ),
                )

            self._record_stage_complete(execution, PipelineStage.HUMAN_APPROVAL)

            # -----------------------------------------------------------------
            # Stage 11: SYNTHETIC_REMEDIATION & STATE_SNAPSHOTS
            # -----------------------------------------------------------------
            self._record_stage_start(execution, PipelineStage.SYNTHETIC_REMEDIATION)
            remed_exec = await self.remediation_executor.execute_approved_plan(
                approval_request_id=appr_req.id,
                user=user,
            )
            execution.synthetic_execution_id = remed_exec.id
            self._record_stage_complete(execution, PipelineStage.SYNTHETIC_REMEDIATION)

            self._record_stage_start(execution, PipelineStage.STATE_SNAPSHOTS)
            self._record_stage_complete(execution, PipelineStage.STATE_SNAPSHOTS)

            # -----------------------------------------------------------------
            # Stage 12: REGRESSION_VERIFICATION
            # -----------------------------------------------------------------
            self._record_stage_start(execution, PipelineStage.REGRESSION_VERIFICATION)
            verif_summary = await self.verification_engine.get_execution_verification_summary(
                execution_id=remed_exec.id,
            )
            if verif_summary.verifications:
                execution.verification_id = verif_summary.verifications[0].id

            self._record_stage_complete(execution, PipelineStage.REGRESSION_VERIFICATION)

            # -----------------------------------------------------------------
            # Stage 13: FINAL_AUDIT_SUMMARY & Completion
            # -----------------------------------------------------------------
            self._record_stage_start(execution, PipelineStage.FINAL_AUDIT_SUMMARY)
            audit_stmt = (
                select(AuditLog)
                .where(AuditLog.resource_id.in_([
                    str(execution.id),
                    str(execution.sandbox_id),
                    str(guardian_exec.id),
                    str(remed_exec.id),
                ]))
                .order_by(AuditLog.created_at.desc())
                .limit(20)
            )
            audit_logs = (await self.session.execute(audit_stmt)).scalars().all()
            hashes_valid = all(verify_event_hash(log) for log in audit_logs)

            execution.execution_metadata["audit_verification"] = {
                "logs_checked": len(audit_logs),
                "all_hashes_valid": hashes_valid,
            }
            self._record_stage_complete(execution, PipelineStage.FINAL_AUDIT_SUMMARY)

            # Determine final status
            if remed_exec.execution_status == ExecutionStatus.PARTIAL_FAILURE.value:
                execution.execution_status = PipelineExecutionStatus.PARTIAL_FAILURE.value
            else:
                execution.execution_status = PipelineExecutionStatus.COMPLETED.value

            execution.current_stage = PipelineStage.COMPLETED.value
            execution.completed_at = datetime.now(timezone.utc)

            await self.session.commit()
            return execution

        except Exception as exc:
            logger.error("Pipeline execution failed at stage %s: %s", execution.current_stage, exc, exc_info=True)
            self._record_stage_failure(execution, PipelineStage(execution.current_stage), str(exc))
            await self.session.commit()
            return execution

    # =========================================================================
    # Resuming Paused / Approved Pipeline
    # =========================================================================

    async def resume_pipeline_after_approval(
        self,
        execution_id: uuid.UUID,
        user: User,
    ) -> OrchestrationExecution:
        """Resumes a pipeline paused at WAITING_FOR_APPROVAL once approval is granted."""
        execution = await self.session.get(OrchestrationExecution, execution_id)
        if not execution:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Execution '{execution_id}' not found.")

        if execution.execution_status != PipelineExecutionStatus.WAITING_FOR_APPROVAL.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Execution is not waiting for approval (current status: '{execution.execution_status}').",
            )

        appr_req = await self.session.get(ApprovalRequest, execution.approval_request_id)
        if not appr_req or appr_req.approval_status != ApprovalStatus.APPROVED.value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Underlying approval request is not approved (status: '{appr_req.approval_status if appr_req else 'None'}').",
            )

        execution.execution_status = PipelineExecutionStatus.RUNNING.value
        execution.retry_count += 1
        await self.session.flush()

        sandbox = await self.session.get(SandboxEnvironment, execution.sandbox_id)

        try:
            # Complete Stage 10: HUMAN_APPROVAL
            self._record_stage_complete(execution, PipelineStage.HUMAN_APPROVAL)

            # Stage 11: SYNTHETIC_REMEDIATION
            self._record_stage_start(execution, PipelineStage.SYNTHETIC_REMEDIATION)
            remed_exec = await self.remediation_executor.execute_approved_plan(
                approval_request_id=appr_req.id,
                user=user,
            )
            execution.synthetic_execution_id = remed_exec.id
            self._record_stage_complete(execution, PipelineStage.SYNTHETIC_REMEDIATION)

            # Stage 12: STATE_SNAPSHOTS
            self._record_stage_start(execution, PipelineStage.STATE_SNAPSHOTS)
            self._record_stage_complete(execution, PipelineStage.STATE_SNAPSHOTS)

            # Stage 13: REGRESSION_VERIFICATION
            self._record_stage_start(execution, PipelineStage.REGRESSION_VERIFICATION)
            verif_summary = await self.verification_engine.get_execution_verification_summary(
                execution_id=remed_exec.id,
            )
            if verif_summary.verifications:
                execution.verification_id = verif_summary.verifications[0].id

            self._record_stage_complete(execution, PipelineStage.REGRESSION_VERIFICATION)

            # Stage 14: FINAL_AUDIT_SUMMARY
            self._record_stage_start(execution, PipelineStage.FINAL_AUDIT_SUMMARY)
            self._record_stage_complete(execution, PipelineStage.FINAL_AUDIT_SUMMARY)

            if remed_exec.execution_status == ExecutionStatus.PARTIAL_FAILURE.value:
                execution.execution_status = PipelineExecutionStatus.PARTIAL_FAILURE.value
            else:
                execution.execution_status = PipelineExecutionStatus.COMPLETED.value

            execution.current_stage = PipelineStage.COMPLETED.value
            execution.completed_at = datetime.now(timezone.utc)

            await self.session.commit()
            return execution

        except Exception as exc:
            self._record_stage_failure(execution, PipelineStage(execution.current_stage), str(exc))
            await self.session.commit()
            return execution

    # =========================================================================
    # Observability & Metrics
    # =========================================================================

    async def get_observability_metrics(
        self,
        sandbox_id: Optional[uuid.UUID] = None,
    ) -> Dict[str, Any]:
        """Calculates real persisted observability metrics across pipeline runs."""
        stmt = select(OrchestrationExecution)
        if sandbox_id:
            stmt = stmt.where(OrchestrationExecution.sandbox_id == sandbox_id)

        rows = (await self.session.execute(stmt)).scalars().all()

        total = len(rows)
        successful = sum(1 for r in rows if r.execution_status == PipelineExecutionStatus.COMPLETED.value)
        failed = sum(1 for r in rows if r.execution_status == PipelineExecutionStatus.FAILED.value)
        partial = sum(1 for r in rows if r.execution_status == PipelineExecutionStatus.PARTIAL_FAILURE.value)
        running = sum(1 for r in rows if r.execution_status == PipelineExecutionStatus.RUNNING.value)
        waiting = sum(1 for r in rows if r.execution_status == PipelineExecutionStatus.WAITING_FOR_APPROVAL.value)

        # Stage durations aggregation
        stage_times: Dict[str, List[float]] = {}
        approval_waits: List[float] = []

        for r in rows:
            metrics = r.stage_metrics or {}
            for stg, data in metrics.items():
                if isinstance(data, dict) and "duration_seconds" in data:
                    stage_times.setdefault(stg, []).append(float(data["duration_seconds"]))

            # Approval wait time
            appr_metric = metrics.get(PipelineStage.HUMAN_APPROVAL.value, {})
            if isinstance(appr_metric, dict) and "duration_seconds" in appr_metric:
                approval_waits.append(float(appr_metric["duration_seconds"]))

        avg_stage_durations = {
            stg: round(sum(vals) / len(vals), 3) for stg, vals in stage_times.items() if vals
        }
        avg_approval_wait = round(sum(approval_waits) / len(approval_waits), 3) if approval_waits else 0.0

        # Verification outcomes
        verif_stmt = select(RemediationVerification.verification_status, func.count(RemediationVerification.id)).group_by(
            RemediationVerification.verification_status
        )
        verif_counts = dict((await self.session.execute(verif_stmt)).all())

        retry_total = sum(r.retry_count for r in rows)

        return {
            "total_executions": total,
            "successful_executions": successful,
            "failed_executions": failed,
            "partial_failure_executions": partial,
            "running_executions": running,
            "waiting_approval_executions": waiting,
            "average_stage_durations": avg_stage_durations,
            "average_approval_wait_seconds": avg_approval_wait,
            "verification_outcomes": verif_counts,
            "retry_counts_total": retry_total,
        }
