"""GraphStateManager managing state lifecycle and isolation for AegisSecurityGraph."""

from datetime import datetime, timezone
import logging
from typing import Any
import uuid

from app.ai.schemas.agent_schemas import GraphExecutionRequest
from app.ai.state.state import AegisAIState

logger = logging.getLogger("aegismesh.ai.graph.state")


class GraphStateManager:
    """Manages creation, validation, and lifecycle of AegisAIState."""

    @staticmethod
    def initialize_state(
        request: GraphExecutionRequest,
        graph_execution_id: uuid.UUID | None = None,
    ) -> AegisAIState:
        """Initializes a new isolated graph state from an inbound request."""
        now = datetime.now(timezone.utc).isoformat()
        gid = str(graph_execution_id or uuid.uuid4())

        state: AegisAIState = {
            "execution_id": str(request.execution_id) if request.execution_id else "",
            "graph_execution_id": gid,
            "sandbox_id": str(request.sandbox_id),
            "request_type": request.request_type.value,
            "input_reference_ids": [str(r) for r in (request.input_reference_ids or [])],
            "evidence_records": {},
            "validated_context": {},
            "selected_agents": request.selected_agents or [],
            "agent_outputs": {},
            "evidence_validation_results": {},
            "execution_status": "in_progress",
            "errors": [],
            "retry_count": 0,
            "final_response": None,
            "fallback_used": False,
            "simulation_only": True,
            "user_query": request.user_query,
            "start_time": now,
        }
        return state

    @staticmethod
    def is_terminal(state: AegisAIState) -> bool:
        """Checks if the graph state has reached a terminal outcome."""
        return state.get("execution_status") in ["completed", "failed", "partial"]

