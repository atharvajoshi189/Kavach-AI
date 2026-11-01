"""Execution Orchestrator Service for Blue Guardian Defensive Analysis.

Coordinates authentication, authorization, sandbox scoping, telemetry ingestion,
deterministic correlation, database persistence, and SHA-256 chained audit logging.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from fastapi import HTTPException, status
from sqlalchemy import and_, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.blue_guardian.schemas import (
    GuardianExecutionCreateRequest,
    GuardianExecutionResponse,
    GuardianExecutionStatus,
)
from app.models.attack_path import AttackPath
from app.models.attack_run import AttackRun
from app.models.campaign import Campaign
from app.models.guardian import CorrelatedEventGroup, DefensiveEventRecord, GuardianExecution
from app.models.sandbox import SandboxEnvironment
from app.models.user import User
from app.security.gateway import authorize_action
from app.services.audit_service import record_audit_log
from app.services.guardian.correlation_service import CorrelationService
from app.services.guardian.detection_engine import DetectionEngine
from app.services.guardian.risk_analysis_service import RiskAnalysisService
from app.services.guardian.recommendation_engine import RecommendationEngine
from app.services.guardian.remediation_planner import RemediationPlanner
from app.services.guardian.incident_report_service import IncidentReportService
from app.services.guardian.ingestion_service import (
    CrossSandboxSecurityViolation,
    IngestionService,
    IngestionValidationError,
    NonSyntheticEvidenceViolation,
)
from app.services.sandbox_service import get_sandbox_by_id, verify_sandbox_access

logger = logging.getLogger("aegismesh.guardian.orchestrator")


class GuardianOrchestrationService:
    """Coordinates defensive ingestion and correlation pipeline runs."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.ingestion_service = IngestionService(session)
        self.correlation_service = CorrelationService(session)
        self.detection_engine = DetectionEngine(session)
        self.risk_service = RiskAnalysisService(session)
        self.recommendation_engine = RecommendationEngine(session)
        self.remediation_planner = RemediationPlanner(session)
        self.incident_report_service = IncidentReportService(session)

    async def execute_analysis(
        self,
        request: GuardianExecutionCreateRequest,
        user: User,
    ) -> GuardianExecution:
        """Executes full defensive ingestion and deterministic correlation pipeline."""
        audit_role = user.role.value if hasattr(user.role, "value") else str(user.role)

        # ---------------------------------------------------------------------
        # 1. Authorize via Security Gateway / OPA
        # ---------------------------------------------------------------------
        decision = await authorize_action(
            user=user,
            operation="guardian.execute",
            capability="scan",
            resource_type="guardian_execution",
            resource_id=str(request.sandbox_id),
            environment="sandbox",
            session=self.session,
        )
        if not decision.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=decision.reason,
            )

        # ---------------------------------------------------------------------
        # 2. Validate Sandbox Scope and Ownership
        # ---------------------------------------------------------------------
        sandbox = await get_sandbox_by_id(self.session, request.sandbox_id)
        if not sandbox:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Sandbox environment '{request.sandbox_id}' not found.",
            )

        if sandbox.status == "archived":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Sandbox '{sandbox.name}' is archived. Defensive analysis cannot execute on archived environments.",
            )

        if not verify_sandbox_access(sandbox, user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: user is not authorized to interact with this sandbox environment.",
            )

        # ---------------------------------------------------------------------
        # 3. Validate Target Identity (AttackRun or AttackPath)
        # ---------------------------------------------------------------------
        target_campaign_id: Optional[uuid.UUID] = None
        if request.attack_run_id:
            run = await self.session.get(AttackRun, request.attack_run_id)
            if not run:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Target AttackRun '{request.attack_run_id}' not found.",
                )
            campaign = await self.session.get(Campaign, run.campaign_id)
            if not campaign or campaign.sandbox_id != sandbox.id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"AttackRun '{request.attack_run_id}' does not belong to target sandbox '{sandbox.id}'.",
                )
            target_campaign_id = campaign.id

        elif request.attack_path_id:
            path = await self.session.get(AttackPath, request.attack_path_id)
            if not path:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Target AttackPath '{request.attack_path_id}' not found.",
                )
            if path.sandbox_id != sandbox.id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"AttackPath '{request.attack_path_id}' does not belong to target sandbox '{sandbox.id}'.",
                )
            target_campaign_id = path.campaign_id

        # ---------------------------------------------------------------------
        # 4. Concurrency Control via PostgreSQL Advisory Lock
        # ---------------------------------------------------------------------
        bind = self.session.get_bind()
        dialect_name = bind.dialect.name if bind else "postgresql"
        lock_target_str = str(request.attack_run_id or request.attack_path_id)

        if dialect_name == "postgresql":
            try:
                lock_res = await self.session.execute(
                    text("SELECT pg_try_advisory_xact_lock(hashtext(:target), hashtext('guardian_analysis'));"),
                    {"target": lock_target_str},
                )
                lock_acquired = lock_res.scalar()
                if not lock_acquired:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="A defensive analysis execution is already in progress for this target.",
                    )
            except HTTPException:
                raise
            except Exception as lock_err:
                logger.warning("Advisory lock failed: %s", lock_err)

        # In addition to the transaction advisory lock, verify no active execution is running
        target_filters = []
        if request.attack_run_id:
            target_filters.append(GuardianExecution.attack_run_id == request.attack_run_id)
        if request.attack_path_id:
            target_filters.append(GuardianExecution.attack_path_id == request.attack_path_id)

        if target_filters:
            active_q = select(GuardianExecution.id).where(
                or_(*target_filters),
                GuardianExecution.status.in_([
                    GuardianExecutionStatus.PENDING.value,
                    GuardianExecutionStatus.INGESTING.value,
                    GuardianExecutionStatus.CORRELATING.value,
                ]),
            )
            existing_active = (await self.session.execute(active_q)).scalars().first()
            if existing_active:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A defensive analysis execution is already active for this target.",
                )

        # ---------------------------------------------------------------------
        # 5. Initialize GuardianExecution Record
        # ---------------------------------------------------------------------
        execution = GuardianExecution(
            sandbox_id=sandbox.id,
            attack_run_id=request.attack_run_id,
            attack_path_id=request.attack_path_id,
            status=GuardianExecutionStatus.INGESTING.value,
            started_at=datetime.now(timezone.utc),
            events_ingested=0,
            correlation_groups_count=0,
            execution_metadata={
                "initiated_by": str(user.id),
                "initiated_by_username": user.username,
                "correlation_window_seconds": request.correlation_window_seconds,
                "campaign_id": str(target_campaign_id) if target_campaign_id else None,
            },
        )
        self.session.add(execution)
        await self.session.flush()

        # Audit: Execution Started
        await record_audit_log(
            session=self.session,
            event_type="guardian.execution_started",
            action="guardian.execute",
            resource_type="guardian_execution",
            actor_id=user.id,
            actor_role=audit_role,
            resource_id=str(execution.id),
            decision="ALLOW",
            event_data={
                "sandbox_id": str(sandbox.id),
                "attack_run_id": str(request.attack_run_id) if request.attack_run_id else None,
                "attack_path_id": str(request.attack_path_id) if request.attack_path_id else None,
                "simulation_only": True,
                "is_simulated": True,
            },
        )
        await self.session.commit()

        # Re-query execution after initial commit
        execution = await self.session.get(GuardianExecution, execution.id)

        user_id = user.id
        sandbox_id = sandbox.id
        execution_id = execution.id

        # ---------------------------------------------------------------------
        # 6. Execute Ingestion & Correlation Pipeline
        # ---------------------------------------------------------------------
        try:
            # 6a. Telemetry Ingestion
            ingested_events = await self.ingestion_service.ingest_events_for_execution(
                execution=execution,
                correlation_window_seconds=request.correlation_window_seconds,
            )

            # Audit: Ingestion Completed
            await record_audit_log(
                session=self.session,
                event_type="guardian.ingestion_completed",
                action="guardian.ingest",
                resource_type="guardian_execution",
                actor_id=user_id,
                actor_role=audit_role,
                resource_id=str(execution_id),
                decision="ALLOW",
                event_data={
                    "sandbox_id": str(sandbox_id),
                    "events_ingested": len(ingested_events),
                    "simulation_only": True,
                    "is_simulated": True,
                },
            )

            # 6b. Deterministic Correlation
            execution.status = GuardianExecutionStatus.CORRELATING.value
            await self.session.flush()

            correlated_groups = await self.correlation_service.correlate_events_for_execution(
                execution=execution,
                events=ingested_events,
                window_seconds=request.correlation_window_seconds,
            )

            # Audit: Correlation Completed
            await record_audit_log(
                session=self.session,
                event_type="guardian.correlation_completed",
                action="guardian.correlate",
                resource_type="guardian_execution",
                actor_id=user_id,
                actor_role=audit_role,
                resource_id=str(execution_id),
                decision="ALLOW",
                event_data={
                    "sandbox_id": str(sandbox_id),
                    "events_ingested": len(ingested_events),
                    "groups_correlated": len(correlated_groups),
                    "simulation_only": True,
                    "is_simulated": True,
                },
            )

            # 6c. Threat Detection Pipeline
            execution.status = GuardianExecutionStatus.DETECTING.value
            await self.session.flush()

            await record_audit_log(
                session=self.session,
                event_type="guardian.detection.started",
                action="guardian.detect",
                resource_type="guardian_execution",
                actor_id=user_id,
                actor_role=audit_role,
                resource_id=str(execution_id),
                decision="ALLOW",
                event_data={
                    "sandbox_id": str(sandbox_id),
                    "groups_to_evaluate": len(correlated_groups),
                    "simulation_only": True,
                    "is_simulated": True,
                },
            )

            detections = await self.detection_engine.run_detection_for_execution(
                execution=execution,
                groups=correlated_groups,
                events=ingested_events,
            )

            # Audit individual detections
            for det in detections:
                await record_audit_log(
                    session=self.session,
                    event_type="guardian.detection.created",
                    action="guardian.detect",
                    resource_type="threat_detection",
                    actor_id=user_id,
                    actor_role=audit_role,
                    resource_id=str(det.id),
                    decision="ALLOW",
                    event_data={
                        "sandbox_id": str(sandbox_id),
                        "detection_code": det.detection_code,
                        "rule_code": det.rule_code,
                        "severity": det.severity,
                        "confidence_score": det.confidence_score,
                        "simulation_only": True,
                        "is_simulated": True,
                    },
                )

            # Audit: Detection Completed
            await record_audit_log(
                session=self.session,
                event_type="guardian.detection.completed",
                action="guardian.detect",
                resource_type="guardian_execution",
                actor_id=user_id,
                actor_role=audit_role,
                resource_id=str(execution_id),
                decision="ALLOW",
                event_data={
                    "sandbox_id": str(sandbox_id),
                    "detections_count": len(detections),
                    "simulation_only": True,
                    "is_simulated": True,
                },
            )

            # 6d. Risk Analysis Pipeline
            execution.status = GuardianExecutionStatus.ANALYZING_RISK.value
            await self.session.flush()

            await record_audit_log(
                session=self.session,
                event_type="guardian.risk_analysis.started",
                action="guardian.risk_analyze",
                resource_type="guardian_execution",
                actor_id=user_id,
                actor_role=audit_role,
                resource_id=str(execution_id),
                decision="ALLOW",
                event_data={
                    "sandbox_id": str(sandbox_id),
                    "detections_to_analyze": len(detections),
                    "simulation_only": True,
                    "is_simulated": True,
                },
            )

            assessments = await self.risk_service.run_risk_analysis_for_execution(
                execution=execution,
                detections=detections,
            )

            # Audit individual risk assessments
            for ass in assessments:
                cat_val = ass.risk_category.value if hasattr(ass.risk_category, "value") else str(ass.risk_category)
                await record_audit_log(
                    session=self.session,
                    event_type="guardian.risk_assessment.created",
                    action="guardian.risk_analyze",
                    resource_type="threat_risk_assessment",
                    actor_id=user_id,
                    actor_role=audit_role,
                    resource_id=str(ass.id),
                    decision="ALLOW",
                    event_data={
                        "sandbox_id": str(sandbox_id),
                        "threat_detection_id": str(ass.threat_detection_id),
                        "risk_score": ass.risk_score,
                        "risk_category": cat_val,
                        "critical_asset_exposed": ass.critical_asset_exposed,
                        "directly_affected_count": ass.directly_affected_count,
                        "blast_radius_size": ass.blast_radius_size,
                        "simulation_only": True,
                        "is_simulated": True,
                    },
                )

            # Audit: Risk Analysis Completed
            await record_audit_log(
                session=self.session,
                event_type="guardian.risk_analysis.completed",
                action="guardian.risk_analyze",
                resource_type="guardian_execution",
                actor_id=user_id,
                actor_role=audit_role,
                resource_id=str(execution_id),
                decision="ALLOW",
                event_data={
                    "sandbox_id": str(sandbox_id),
                    "assessments_count": len(assessments),
                    "max_risk_score": round(max((float(a.risk_score or 0.0) for a in assessments), default=0.0), 2),
                    "simulation_only": True,
                    "is_simulated": True,
                },
            )

            # 6e. Defensive Recommendations Pipeline
            execution.status = GuardianExecutionStatus.RECOMMENDING.value
            await self.session.flush()

            await record_audit_log(
                session=self.session,
                event_type="guardian.recommendations.started",
                action="guardian.recommend",
                resource_type="guardian_execution",
                actor_id=user_id,
                actor_role=audit_role,
                resource_id=str(execution_id),
                decision="ALLOW",
                event_data={
                    "sandbox_id": str(sandbox_id),
                    "assessments_count": len(assessments),
                    "simulation_only": True,
                    "is_simulated": True,
                },
            )

            recommendations = await self.recommendation_engine.generate_recommendations_for_execution(
                execution=execution,
            )

            for rec in recommendations:
                await record_audit_log(
                    session=self.session,
                    event_type="guardian.recommendation.created",
                    action="guardian.recommend",
                    resource_type="defensive_recommendation",
                    actor_id=user_id,
                    actor_role=audit_role,
                    resource_id=str(rec.id),
                    decision="ALLOW",
                    event_data={
                        "sandbox_id": str(sandbox_id),
                        "recommendation_code": rec.recommendation_code,
                        "priority": rec.priority,
                        "playbook_id": rec.playbook_id,
                        "threat_detection_id": str(rec.threat_detection_id),
                        "simulation_only": True,
                        "is_simulated": True,
                    },
                )

            await record_audit_log(
                session=self.session,
                event_type="guardian.recommendations.completed",
                action="guardian.recommend",
                resource_type="guardian_execution",
                actor_id=user_id,
                actor_role=audit_role,
                resource_id=str(execution_id),
                decision="ALLOW",
                event_data={
                    "sandbox_id": str(sandbox_id),
                    "recommendations_count": len(recommendations),
                    "simulation_only": True,
                    "is_simulated": True,
                },
            )

            # 6f. Remediation Planning Pipeline
            execution.status = GuardianExecutionStatus.PLANNING.value
            await self.session.flush()

            remediation_plan = await self.remediation_planner.generate_plan_for_execution(
                execution=execution,
                recommendations=recommendations,
            )

            await record_audit_log(
                session=self.session,
                event_type="guardian.remediation_plan.created",
                action="guardian.plan",
                resource_type="remediation_plan",
                actor_id=user_id,
                actor_role=audit_role,
                resource_id=str(remediation_plan.id),
                decision="ALLOW",
                event_data={
                    "sandbox_id": str(sandbox_id),
                    "overall_priority": remediation_plan.overall_priority,
                    "actions_count": remediation_plan.action_count,
                    "simulation_only": True,
                    "is_simulated": True,
                },
            )

            # 6g. Incident Report Synthesis
            incident_report = await self.incident_report_service.generate_incident_report(
                execution=execution,
                report_version=1,
            )

            await record_audit_log(
                session=self.session,
                event_type="guardian.incident_report.generated",
                action="guardian.report",
                resource_type="incident_report",
                actor_id=user_id,
                actor_role=audit_role,
                resource_id=str(incident_report.id),
                decision="ALLOW",
                event_data={
                    "sandbox_id": str(sandbox_id),
                    "report_version": incident_report.report_version,
                    "max_risk_score": incident_report.max_risk_score,
                    "severity": incident_report.severity,
                    "simulation_only": True,
                    "is_simulated": True,
                },
            )

            # 6h. Execution Completion
            execution.status = GuardianExecutionStatus.COMPLETED.value
            execution.completed_at = datetime.now(timezone.utc)
            execution.events_ingested = len(ingested_events)
            execution.correlation_groups_count = len(correlated_groups)
            execution.threat_detections_count = len(detections)
            execution.risk_assessments_count = len(assessments)
            execution.recommendations_count = len(recommendations)
            execution.remediation_plans_count = 1 if remediation_plan else 0
            execution.incident_reports_count = 1
            if assessments:
                execution.max_risk_score = round(max(float(a.risk_score or 0.0) for a in assessments), 2)
            else:
                execution.max_risk_score = 0.0
            await self.session.flush()

            await self.session.commit()
            await self.session.refresh(execution)
            return execution

        except (CrossSandboxSecurityViolation, NonSyntheticEvidenceViolation, IngestionValidationError) as val_err:
            logger.warning("Defensive ingestion validation error: %s", val_err)
            await self.session.rollback()

            # Re-fetch and mark execution failed
            exec_obj = await self.session.get(GuardianExecution, execution_id)
            if exec_obj:
                exec_obj.status = GuardianExecutionStatus.FAILED.value
                exec_obj.completed_at = datetime.now(timezone.utc)
                exec_obj.error_message = str(val_err)
                await self.session.flush()

                await record_audit_log(
                    session=self.session,
                    event_type="guardian.execution_failed",
                    action="guardian.execute",
                    resource_type="guardian_execution",
                    actor_id=user_id,
                    actor_role=audit_role,
                    resource_id=str(execution_id),
                    decision="DENY",
                    event_data={
                        "sandbox_id": str(sandbox_id),
                        "error": str(val_err),
                        "failure_type": val_err.__class__.__name__,
                    },
                )
                await self.session.commit()

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(val_err),
            ) from val_err

        except Exception as exc:
            logger.error("Unexpected failure in defensive pipeline: %s", exc, exc_info=True)
            await self.session.rollback()

            exec_obj = await self.session.get(GuardianExecution, execution_id)
            if exec_obj:
                exec_obj.status = GuardianExecutionStatus.FAILED.value
                exec_obj.completed_at = datetime.now(timezone.utc)
                exec_obj.error_message = str(exc)
                await self.session.flush()

                await record_audit_log(
                    session=self.session,
                    event_type="guardian.execution_failed",
                    action="guardian.execute",
                    resource_type="guardian_execution",
                    actor_id=user_id,
                    actor_role=audit_role,
                    resource_id=str(execution_id),
                    decision="DENY",
                    event_data={
                        "sandbox_id": str(sandbox_id),
                        "error": str(exc),
                    },
                )
                await self.session.commit()

            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Defensive analysis pipeline failed: {str(exc)}",
            ) from exc
