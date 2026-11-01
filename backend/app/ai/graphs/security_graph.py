"""AegisSecurityGraph — LangGraph StateGraph compiling the multi-agent security pipeline.

Implements conditional routing, parallel agent fan-out, and evidence grounding.
"""

import logging
from typing import Any

from langgraph.graph import END, START, StateGraph

from app.ai.agents.registry import agent_registry
from app.ai.nodes.aggregation_node import final_persistence_node, result_aggregation_node
from app.ai.nodes.context_node import context_init_node, evidence_retrieval_node
from app.ai.nodes.router_node import agent_router_node, route_to_agents
from app.ai.nodes.validation_node import input_validation_node
from app.ai.state.state import AegisAIState

logger = logging.getLogger("aegismesh.ai.graph")


# --------------------------------------------------------------------------
# Specialized Agent Node Handlers
# --------------------------------------------------------------------------

async def threat_agent_node(state: AegisAIState) -> dict[str, Any]:
    agent = agent_registry.get("threat_intelligence_agent")
    if not agent:
        return {"agent_outputs": {}}
    output = await agent.execute(state)
    return {"agent_outputs": {"threat_intelligence_agent": output}}


async def attack_path_agent_node(state: AegisAIState) -> dict[str, Any]:
    agent = agent_registry.get("attack_path_agent")
    if not agent:
        return {"agent_outputs": {}}
    output = await agent.execute(state)
    return {"agent_outputs": {"attack_path_agent": output}}


async def risk_agent_node(state: AegisAIState) -> dict[str, Any]:
    agent = agent_registry.get("risk_intelligence_agent")
    if not agent:
        return {"agent_outputs": {}}
    output = await agent.execute(state)
    return {"agent_outputs": {"risk_intelligence_agent": output}}


async def incident_agent_node(state: AegisAIState) -> dict[str, Any]:
    agent = agent_registry.get("incident_analysis_agent")
    if not agent:
        return {"agent_outputs": {}}
    output = await agent.execute(state)
    return {"agent_outputs": {"incident_analysis_agent": output}}


async def defense_agent_node(state: AegisAIState) -> dict[str, Any]:
    agent = agent_registry.get("defensive_strategy_agent")
    if not agent:
        return {"agent_outputs": {}}
    output = await agent.execute(state)
    return {"agent_outputs": {"defensive_strategy_agent": output}}


async def executive_agent_node(state: AegisAIState) -> dict[str, Any]:
    agent = agent_registry.get("executive_intelligence_agent")
    if not agent:
        return {"agent_outputs": {}}
    output = await agent.execute(state)
    return {"agent_outputs": {"executive_intelligence_agent": output}}


# --------------------------------------------------------------------------
# Graph Construction & Compilation
# --------------------------------------------------------------------------

def build_aegis_security_graph() -> Any:
    """Builds and compiles the production LangGraph multi-agent security graph."""
    builder = StateGraph(AegisAIState)

    # 1. Register Sequential Preparation Nodes
    builder.add_node("context_init", context_init_node)
    builder.add_node("evidence_retrieval", evidence_retrieval_node)
    builder.add_node("input_validation", input_validation_node)
    builder.add_node("agent_router", agent_router_node)

    # 2. Register Specialized Agent Nodes
    builder.add_node("threat_agent", threat_agent_node)
    builder.add_node("attack_path_agent", attack_path_agent_node)
    builder.add_node("risk_agent", risk_agent_node)
    builder.add_node("incident_agent", incident_agent_node)
    builder.add_node("defense_agent", defense_agent_node)
    builder.add_node("executive_agent", executive_agent_node)

    # 3. Register Aggregation and Persistence Nodes
    builder.add_node("result_aggregation", result_aggregation_node)
    builder.add_node("final_persistence", final_persistence_node)

    # 4. Wire Edges
    builder.add_edge(START, "context_init")
    builder.add_edge("context_init", "evidence_retrieval")
    builder.add_edge("evidence_retrieval", "input_validation")
    builder.add_edge("input_validation", "agent_router")

    # 5. Conditional Fan-out to Selected Agents
    builder.add_conditional_edges(
        "agent_router",
        route_to_agents,
        [
            "threat_agent",
            "attack_path_agent",
            "risk_agent",
            "incident_agent",
            "defense_agent",
            "executive_agent",
            "result_aggregation",
        ],
    )

    # 6. Fan-in: All Agent Nodes converge at Result Aggregation
    builder.add_edge("threat_agent", "result_aggregation")
    builder.add_edge("attack_path_agent", "result_aggregation")
    builder.add_edge("risk_agent", "result_aggregation")
    builder.add_edge("incident_agent", "result_aggregation")
    builder.add_edge("defense_agent", "result_aggregation")
    builder.add_edge("executive_agent", "result_aggregation")

    # 7. Final Pipeline Edges
    builder.add_edge("result_aggregation", "final_persistence")
    builder.add_edge("final_persistence", END)

    logger.info("Compiled AegisSecurityGraph successfully")
    return builder.compile()


# Global compiled graph instance
aegis_security_graph = build_aegis_security_graph()

