"""Celery background tasks for asynchronous AI intelligence generation."""

import asyncio
import logging
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import select

from app.ai.gateway.intelligence_gateway import intelligence_gateway
from app.database.session import AsyncSessionLocal
from app.models.ai import AIAnalysisRecord
from app.models.user import User
from app.workers.celery_app import celery_app

logger = logging.getLogger("aegismesh.workers.ai")


async def run_ai_threat_explanation_async(
    detection_id: str,
    sandbox_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Async runner for threat explanation generation."""
    async with AsyncSessionLocal() as session:
        user = await session.get(User, uuid.UUID(user_id))
        if not user:
            raise ValueError(f"User '{user_id}' not found.")

        resp = await intelligence_gateway.explain_threat(
            session=session,
            user=user,
            detection_id=uuid.UUID(detection_id),
            sandbox_id=uuid.UUID(sandbox_id),
        )
        return resp.model_dump(mode="json")


async def run_ai_executive_briefing_async(
    execution_id: str,
    sandbox_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Async runner for executive briefing generation."""
    async with AsyncSessionLocal() as session:
        user = await session.get(User, uuid.UUID(user_id))
        if not user:
            raise ValueError(f"User '{user_id}' not found.")

        resp = await intelligence_gateway.generate_executive_briefing(
            session=session,
            user=user,
            execution_id=uuid.UUID(execution_id),
            sandbox_id=uuid.UUID(sandbox_id),
        )
        return resp.model_dump(mode="json")


@celery_app.task(
    name="app.workers.ai_tasks.generate_ai_threat_explanation_task",
    bind=True,
    max_retries=2,
    default_retry_delay=5,
)
def generate_ai_threat_explanation_task(
    self,
    detection_id: str,
    sandbox_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Background task generating AI threat explanations without blocking critical pipeline."""
    task_id = getattr(self.request, "id", str(uuid.uuid4()))
    logger.info("Executing generate_ai_threat_explanation_task [%s] for detection %s", task_id, detection_id)
    try:
        return asyncio.run(run_ai_threat_explanation_async(detection_id, sandbox_id, user_id))
    except Exception as exc:
        logger.warning("AI threat explanation task [%s] encountered error: %s", task_id, exc)
        raise self.retry(exc=exc)


@celery_app.task(
    name="app.workers.ai_tasks.generate_ai_executive_briefing_task",
    bind=True,
    max_retries=2,
    default_retry_delay=5,
)
def generate_ai_executive_briefing_task(
    self,
    execution_id: str,
    sandbox_id: str,
    user_id: str,
) -> Dict[str, Any]:
    """Background task generating executive security briefing."""
    task_id = getattr(self.request, "id", str(uuid.uuid4()))
    logger.info("Executing generate_ai_executive_briefing_task [%s] for execution %s", task_id, execution_id)
    try:
        return asyncio.run(run_ai_executive_briefing_async(execution_id, sandbox_id, user_id))
    except Exception as exc:
        logger.warning("AI executive briefing task [%s] encountered error: %s", task_id, exc)
        raise self.retry(exc=exc)


# --------------------------------------------------------------------------
# LangGraph Multi-Agent Task (Step 09.2.6.2)
# --------------------------------------------------------------------------

async def run_aegis_ai_graph_async(
    sandbox_id: str,
    execution_id: Optional[str] = None,
    request_type: str = "full_investigation",
    selected_agents: Optional[List[str]] = None,
    user_id: Optional[str] = None,
    user_query: Optional[str] = None,
) -> Dict[str, Any]:
    """Async runner for LangGraph multi-agent security graph execution."""
    async with AsyncSessionLocal() as session:
        user = await session.get(User, uuid.UUID(user_id)) if user_id else None

        # Idempotency check: if already executed for this execution_id
        if execution_id:
            stmt = select(AIAnalysisRecord).where(
                AIAnalysisRecord.guardian_execution_id == uuid.UUID(execution_id),
                AIAnalysisRecord.analysis_type == "multi_agent_graph",
            )
            existing = (await session.execute(stmt)).scalars().first()
            if existing and existing.response_content:
                logger.info("Found existing graph execution record for execution %s; returning idempotent result", execution_id)
                return existing.response_content

        from app.ai.graphs.execution_service import graph_execution_service
        from app.ai.schemas.agent_schemas import GraphExecutionRequest, GraphRequestType

        valid_type = (
            GraphRequestType(request_type)
            if request_type in GraphRequestType._value2member_map_
            else GraphRequestType.FULL_INVESTIGATION
        )

        req = GraphExecutionRequest(
            sandbox_id=uuid.UUID(sandbox_id),
            execution_id=uuid.UUID(execution_id) if execution_id else None,
            request_type=valid_type,
            selected_agents=selected_agents,
            user_query=user_query,
        )

        resp = await graph_execution_service.execute_graph(
            session=session,
            user=user,
            request=req,
        )
        return resp.model_dump(mode="json")


@celery_app.task(
    name="app.workers.ai_tasks.execute_aegis_ai_graph_task",
    bind=True,
    max_retries=2,
    default_retry_delay=5,
)
def execute_aegis_ai_graph_task(
    self,
    sandbox_id: str,
    execution_id: Optional[str] = None,
    request_type: str = "full_investigation",
    selected_agents: Optional[List[str]] = None,
    user_id: Optional[str] = None,
    user_query: Optional[str] = None,
) -> Dict[str, Any]:
    """Background task executing the LangGraph multi-agent security workflow."""
    task_id = getattr(self.request, "id", str(uuid.uuid4()))
    logger.info("Executing execute_aegis_ai_graph_task [%s] for sandbox %s", task_id, sandbox_id)
    try:
        return asyncio.run(run_aegis_ai_graph_async(
            sandbox_id=sandbox_id,
            execution_id=execution_id,
            request_type=request_type,
            selected_agents=selected_agents,
            user_id=user_id,
            user_query=user_query,
        ))
    except Exception as exc:
        logger.warning("LangGraph AI task [%s] encountered error: %s", task_id, exc)
        raise self.retry(exc=exc)

