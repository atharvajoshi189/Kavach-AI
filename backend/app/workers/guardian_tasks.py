"""Celery background tasks for Blue Guardian defensive ingestion and correlation."""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict
import uuid

from app.database.session import AsyncSessionLocal
from app.models.user import User
from app.services.guardian.orchestrator_service import GuardianOrchestrationService
from app.services.guardian.synthetic_remediation_executor import SyntheticRemediationExecutor
from app.services.unified_orchestrator import UnifiedOrchestrator
from app.agents.blue_guardian.schemas import GuardianExecutionCreateRequest
from app.workers.celery_app import celery_app

logger = logging.getLogger("aegismesh.workers.guardian")


async def run_guardian_analysis_async(
    sandbox_id: str,
    user_id: str,
    attack_run_id: str | None = None,
    attack_path_id: str | None = None,
    correlation_window_seconds: int = 300,
) -> Dict[str, Any]:
    """Async execution implementation for Blue Guardian defensive analysis."""
    async with AsyncSessionLocal() as session:
        user = await session.get(User, uuid.UUID(user_id))
        if not user:
            raise ValueError(f"User '{user_id}' not found.")

        req = GuardianExecutionCreateRequest(
            sandbox_id=uuid.UUID(sandbox_id),
            attack_run_id=uuid.UUID(attack_run_id) if attack_run_id else None,
            attack_path_id=uuid.UUID(attack_path_id) if attack_path_id else None,
            correlation_window_seconds=correlation_window_seconds,
        )
        service = GuardianOrchestrationService(session=session)
        execution = await service.execute_analysis(request=req, user=user)

        return {
            "execution_id": str(execution.id),
            "status": execution.status,
            "events_ingested": execution.events_ingested,
            "correlation_groups_count": execution.correlation_groups_count,
            "threat_detections_count": execution.threat_detections_count,
            "risk_assessments_count": getattr(execution, "risk_assessments_count", 0),
            "recommendations_count": getattr(execution, "recommendations_count", 0),
            "remediation_plans_count": getattr(execution, "remediation_plans_count", 0),
            "incident_reports_count": getattr(execution, "incident_reports_count", 0),
            "max_risk_score": getattr(execution, "max_risk_score", 0.0),
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
        }


@celery_app.task(name="app.workers.guardian_tasks.execute_guardian_analysis_task", bind=True)
def execute_guardian_analysis_task(
    self,
    sandbox_id: str,
    user_id: str,
    attack_run_id: str | None = None,
    attack_path_id: str | None = None,
    correlation_window_seconds: int = 300,
) -> Dict[str, Any]:
    """Celery background task orchestrating defensive ingestion and correlation."""
    task_id = getattr(self.request, "id", str(uuid.uuid4()))
    logger.info("Executing execute_guardian_analysis_task [%s] for sandbox %s", task_id, sandbox_id)

    res = asyncio.run(run_guardian_analysis_async(
        sandbox_id=sandbox_id,
        user_id=user_id,
        attack_run_id=attack_run_id,
        attack_path_id=attack_path_id,
        correlation_window_seconds=correlation_window_seconds,
    ))
    res["task_id"] = task_id
    return res


async def run_synthetic_remediation_async(
    approval_request_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Async execution implementation for Blue Guardian synthetic remediation execution."""
    async with AsyncSessionLocal() as session:
        user = await session.get(User, uuid.UUID(user_id))
        if not user:
            raise ValueError(f"User '{user_id}' not found.")

        executor = SyntheticRemediationExecutor(session=session)
        execution = await executor.execute_approved_plan(
            approval_request_id=uuid.UUID(approval_request_id),
            user=user,
        )

        return {
            "execution_id": str(execution.id),
            "remediation_plan_id": str(execution.remediation_plan_id),
            "approval_request_id": str(execution.approval_request_id),
            "status": execution.status,
            "actions_executed": execution.actions_executed,
            "actions_succeeded": execution.actions_succeeded,
            "actions_failed": execution.actions_failed,
            "verification_status": execution.verification_status,
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
        }


@celery_app.task(name="app.workers.guardian_tasks.execute_synthetic_remediation_task", bind=True)
def execute_synthetic_remediation_task(
    self,
    approval_request_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Celery background task orchestrating synthetic remediation execution and verification."""
    task_id = getattr(self.request, "id", str(uuid.uuid4()))
    logger.info("Executing execute_synthetic_remediation_task [%s] for approval %s", task_id, approval_request_id)

    res = asyncio.run(run_synthetic_remediation_async(
        approval_request_id=approval_request_id,
        user_id=user_id,
    ))
    res["task_id"] = task_id
    return res


async def run_unified_pipeline_async(
    sandbox_id: str,
    user_id: str,
    scenario_id: str = "simulated_initial_access",
    auto_approve: bool = False,
    run_attack_path: bool = False,
) -> Dict[str, Any]:
    """Async execution implementation for unified end-to-end platform pipeline."""
    async with AsyncSessionLocal() as session:
        user = await session.get(User, uuid.UUID(user_id))
        if not user:
            raise ValueError(f"User '{user_id}' not found.")

        orchestrator = UnifiedOrchestrator(session=session)
        execution = await orchestrator.start_pipeline(
            sandbox_id=uuid.UUID(sandbox_id),
            user=user,
            scenario_id=scenario_id,
            auto_approve=auto_approve,
            run_attack_path=run_attack_path,
        )

        return {
            "execution_id": str(execution.id),
            "sandbox_id": str(execution.sandbox_id),
            "current_stage": execution.current_stage,
            "execution_status": execution.execution_status,
            "simulation_id": str(execution.simulation_id) if execution.simulation_id else None,
            "attack_path_id": str(execution.attack_path_id) if execution.attack_path_id else None,
            "guardian_execution_id": str(execution.guardian_execution_id) if execution.guardian_execution_id else None,
            "remediation_plan_id": str(execution.remediation_plan_id) if execution.remediation_plan_id else None,
            "approval_request_id": str(execution.approval_request_id) if execution.approval_request_id else None,
            "synthetic_execution_id": str(execution.synthetic_execution_id) if execution.synthetic_execution_id else None,
            "verification_id": str(execution.verification_id) if execution.verification_id else None,
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
        }


@celery_app.task(name="app.workers.guardian_tasks.execute_unified_pipeline_task", bind=True)
def execute_unified_pipeline_task(
    self,
    sandbox_id: str,
    user_id: str,
    scenario_id: str = "simulated_initial_access",
    auto_approve: bool = False,
    run_attack_path: bool = False,
) -> Dict[str, Any]:
    """Celery background task orchestrating the complete end-to-end platform lifecycle."""
    task_id = getattr(self.request, "id", str(uuid.uuid4()))
    logger.info("Executing execute_unified_pipeline_task [%s] for sandbox %s", task_id, sandbox_id)

    res = asyncio.run(run_unified_pipeline_async(
        sandbox_id=sandbox_id,
        user_id=user_id,
        scenario_id=scenario_id,
        auto_approve=auto_approve,
        run_attack_path=run_attack_path,
    ))
    res["task_id"] = task_id
    return res
