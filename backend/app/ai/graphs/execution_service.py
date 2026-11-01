"""GraphExecutionService & AegisAgentOrchestrator coordinating LangGraph multi-agent runs."""

from datetime import datetime, timezone
import logging
from typing import Any, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.agents.registry import agent_registry
from app.ai.graphs.execution_tracker import agent_tracker
from app.ai.graphs.security_graph import aegis_security_graph
from app.ai.graphs.state_manager import GraphStateManager
from app.ai.nodes.context_node import evidence_retrieval_node
from app.ai.schemas.agent_schemas import (
    AegisAgentOutput,
    GraphExecutionRequest,
    GraphExecutionResponse,
    SingleAgentExecuteRequest,
)
from app.ai.state.state import AegisAIState
from app.models.ai import AIAnalysisRecord
from app.models.user import User

logger = logging.getLogger("aegismesh.ai.graph.service")


class GraphExecutionService:
    """Service orchestrating execution of multi-agent security graphs and individual agents."""

    def __init__(self) -> None:
        self._graph = aegis_security_graph
        self._state_manager = GraphStateManager
        self._tracker = agent_tracker

    async def execute_graph(
        self,
        session: AsyncSession,
        user: Optional[User],
        request: GraphExecutionRequest,
    ) -> GraphExecutionResponse:
        """Executes the full compiled LangGraph multi-agent security pipeline."""
        graph_id = uuid.uuid4()
        selected_agents = agent_registry.select_agents_for_request(
            request.request_type.value,
            request.selected_agents,
        )

        self._tracker.start_execution(
            graph_execution_id=graph_id,
            sandbox_id=request.sandbox_id,
            request_type=request.request_type.value,
            selected_agents=selected_agents,
        )

        initial_state = self._state_manager.initialize_state(
            request=request,
            graph_execution_id=graph_id,
        )

        # Retrieve evidence into initial state before graph invocation
        evidence_update = await evidence_retrieval_node(initial_state, session=session)
        initial_state.update(evidence_update)

        try:
            # Execute compiled LangGraph StateGraph
            final_state: AegisAIState = await self._graph.ainvoke(initial_state)

            final_resp_dict = final_state.get("final_response")
            if not final_resp_dict:
                # If final persistence didn't populate for some reason, build default response
                logger.warning("Graph execution did not produce final_response; generating fallback response")
                response = GraphExecutionResponse(
                    graph_execution_id=graph_id,
                    parent_execution_id=request.execution_id,
                    sandbox_id=request.sandbox_id,
                    request_type=request.request_type.value,
                    selected_agents=selected_agents,
                    individual_agent_statuses={},
                    agent_outputs={},
                    synthesis_summary="Multi-agent analysis completed with fallback.",
                    overall_confidence=0.85,
                    execution_status="fallback",
                    fallback_used=True,
                    is_simulated=True,
                    simulation_only=True,
                    started_at=datetime.now(timezone.utc),
                    completed_at=datetime.now(timezone.utc),
                    total_latency_ms=10.0,
                )
            else:
                response = GraphExecutionResponse.model_validate(final_resp_dict)

            # Persist record
            try:
                record = AIAnalysisRecord(
                    id=graph_id,
                    sandbox_id=request.sandbox_id,
                    guardian_execution_id=request.execution_id,
                    analysis_type="multi_agent_graph",
                    source_entity_type="guardian_execution" if request.execution_id else "sandbox",
                    source_entity_id=request.execution_id or request.sandbox_id,
                    source_version="v1.0",
                    provider="gemini/langgraph",
                    model="multi-agent-orchestrator",
                    prompt_version="v1.0",
                    response_content=response.model_dump(mode="json"),
                    evidence_references=list({
                        eid
                        for out in response.agent_outputs.values()
                        for eid in out.supporting_evidence_ids
                    }),
                    fallback_used=response.fallback_used,
                    fallback_reason="Template fallback used" if response.fallback_used else None,
                    tokens_used=response.total_tokens,
                    latency_ms=response.total_latency_ms,
                    created_at=response.completed_at,
                    created_by=user.id if user else None,
                )
                session.add(record)
                await session.commit()
            except Exception as pe:
                logger.warning("Failed to persist graph analysis record (%s: %s)", type(pe).__name__, pe)

            self._tracker.complete_execution(
                graph_execution_id=graph_id,
                status=response.execution_status,
                fallback_used=response.fallback_used,
                latency_ms=response.total_latency_ms,
                agent_statuses=response.individual_agent_statuses,
            )
            return response

        except Exception as exc:
            logger.error("LangGraph execution failed (%s: %s)", type(exc).__name__, exc, exc_info=True)
            self._tracker.complete_execution(
                graph_execution_id=graph_id,
                status="failed",
                fallback_used=True,
                latency_ms=10.0,
                agent_statuses={a: "failed" for a in selected_agents},
            )
            return GraphExecutionResponse(
                graph_execution_id=graph_id,
                parent_execution_id=request.execution_id,
                sandbox_id=request.sandbox_id,
                request_type=request.request_type.value,
                selected_agents=selected_agents,
                individual_agent_statuses={a: "failed" for a in selected_agents},
                agent_outputs={},
                synthesis_summary=f"Graph execution failed: {str(exc)}",
                overall_confidence=0.0,
                execution_status="failed",
                fallback_used=True,
                is_simulated=True,
                simulation_only=True,
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                total_latency_ms=10.0,
            )

    async def execute_single_agent(
        self,
        session: AsyncSession,
        user: Optional[User],
        request: SingleAgentExecuteRequest,
    ) -> AegisAgentOutput:
        """Executes an isolated specialized agent directly against sandbox evidence."""
        agent = agent_registry.get(request.agent_name)
        if not agent:
            raise ValueError(f"Unknown agent: '{request.agent_name}'")

        state: AegisAIState = {
            "execution_id": str(request.execution_id) if request.execution_id else "",
            "graph_execution_id": str(uuid.uuid4()),
            "sandbox_id": str(request.sandbox_id),
            "request_type": "custom",
            "input_reference_ids": [str(r) for r in (request.input_reference_ids or [])],
            "evidence_records": {},
            "validated_context": {},
            "selected_agents": [request.agent_name],
            "agent_outputs": {},
            "evidence_validation_results": {},
            "execution_status": "in_progress",
            "errors": [],
            "retry_count": 0,
            "final_response": None,
            "fallback_used": False,
            "simulation_only": True,
            "user_query": request.user_query,
            "start_time": datetime.now(timezone.utc).isoformat(),
        }

        evidence_update = await evidence_retrieval_node(state, session=session)
        state.update(evidence_update)

        output = await agent.execute(state, session=session)

        # Persist individual agent execution record
        try:
            record = AIAnalysisRecord(
                id=uuid.uuid4(),
                sandbox_id=request.sandbox_id,
                guardian_execution_id=request.execution_id,
                analysis_type=f"agent_{request.agent_name}",
                source_entity_type="guardian_execution" if request.execution_id else "sandbox",
                source_entity_id=request.execution_id or request.sandbox_id,
                source_version="v1.0",
                provider="gemini/langgraph",
                model=request.agent_name,
                prompt_version="v1.0",
                response_content=output.model_dump(mode="json"),
                evidence_references=output.supporting_evidence_ids,
                fallback_used=output.fallback_used,
                fallback_reason="Agent fallback used" if output.fallback_used else None,
                tokens_used=None,
                latency_ms=10.0,
                created_at=datetime.now(timezone.utc),
                created_by=user.id if user else None,
            )
            session.add(record)
            await session.commit()
        except Exception as pe:
            logger.warning("Failed to persist single agent analysis record (%s: %s)", type(pe).__name__, pe)

        return output

    async def get_graph_execution(
        self,
        session: AsyncSession,
        graph_execution_id: uuid.UUID,
        sandbox_id: uuid.UUID,
    ) -> Optional[GraphExecutionResponse]:
        """Retrieves a persisted graph execution by its UUID within the sandbox."""
        stmt = select(AIAnalysisRecord).where(
            AIAnalysisRecord.id == graph_execution_id,
            AIAnalysisRecord.sandbox_id == sandbox_id,
            AIAnalysisRecord.analysis_type == "multi_agent_graph",
        )
        res = await session.execute(stmt)
        record = res.scalar_one_or_none()
        if not record:
            return None

        return GraphExecutionResponse.model_validate(record.response_content)


# Global orchestrator singleton
graph_execution_service = GraphExecutionService()
AegisAgentOrchestrator = GraphExecutionService

