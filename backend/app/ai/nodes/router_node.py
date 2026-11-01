"""Agent Router node and conditional edge dispatcher for LangGraph.

Determines agent selection and drives conditional parallel execution fan-out.
"""

import logging
from typing import Any, List

from app.ai.agents.registry import agent_registry
from app.ai.state.state import AegisAIState

logger = logging.getLogger("aegismesh.ai.nodes.router")

AGENT_TO_NODE_MAP = {
    "threat_intelligence_agent": "threat_agent",
    "attack_path_agent": "attack_path_agent",
    "risk_intelligence_agent": "risk_agent",
    "incident_analysis_agent": "incident_agent",
    "defensive_strategy_agent": "defense_agent",
    "executive_intelligence_agent": "executive_agent",
}

NODE_TO_AGENT_MAP = {v: k for k, v in AGENT_TO_NODE_MAP.items()}


async def agent_router_node(state: AegisAIState) -> dict[str, Any]:
    """Evaluates request_type and selected_agents to populate state with active agents."""
    req_type = state.get("request_type") or "full_investigation"
    explicit_agents = state.get("selected_agents")

    selected = agent_registry.select_agents_for_request(req_type, explicit_agents)
    logger.info("Agent router selected %d agents: %s for request_type '%s'", len(selected), selected, req_type)

    return {
        "selected_agents": selected,
    }


def route_to_agents(state: AegisAIState) -> List[str]:
    """Conditional edge router: returns list of graph node names to execute in parallel."""
    if state.get("execution_status") == "failed":
        return ["result_aggregation"]

    selected_agents = state.get("selected_agents") or []
    target_nodes = [
        AGENT_TO_NODE_MAP[agent_name]
        for agent_name in selected_agents
        if agent_name in AGENT_TO_NODE_MAP
    ]

    if not target_nodes:
        logger.warning("No valid agent nodes identified; routing directly to result_aggregation")
        return ["result_aggregation"]

    logger.info("Routing parallel execution to nodes: %s", target_nodes)
    return target_nodes

