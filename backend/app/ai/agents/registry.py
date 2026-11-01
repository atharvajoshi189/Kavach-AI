"""Agent Registry managing specialized AI agents in AegisMesh 2.0."""

import logging
from typing import Dict, List, Optional

from app.ai.agents.attack_path_agent import AttackPathAgent
from app.ai.agents.base_agent import BaseAegisAgent
from app.ai.agents.defensive_strategy_agent import DefensiveStrategyAgent
from app.ai.agents.executive_intelligence_agent import ExecutiveIntelligenceAgent
from app.ai.agents.incident_analysis_agent import IncidentAnalysisAgent
from app.ai.agents.risk_intelligence_agent import RiskIntelligenceAgent
from app.ai.agents.threat_intelligence_agent import ThreatIntelligenceAgent
from app.ai.schemas.agent_schemas import AgentMetadata

logger = logging.getLogger("aegismesh.ai.registry")


class AgentRegistry:
    """Central registry of all specialized security AI agents."""

    def __init__(self) -> None:
        self._agents: Dict[str, BaseAegisAgent] = {}
        self._register_default_agents()

    def _register_default_agents(self) -> None:
        agents: List[BaseAegisAgent] = [
            ThreatIntelligenceAgent(),
            AttackPathAgent(),
            RiskIntelligenceAgent(),
            IncidentAnalysisAgent(),
            DefensiveStrategyAgent(),
            ExecutiveIntelligenceAgent(),
        ]
        for agent in agents:
            self._agents[agent.agent_name] = agent
        logger.info("AgentRegistry initialized with %d specialized AI agents", len(self._agents))

    def get(self, agent_name: str) -> Optional[BaseAegisAgent]:
        """Retrieves an agent by its canonical identifier."""
        return self._agents.get(agent_name)

    def list_all(self) -> List[BaseAegisAgent]:
        """Returns all registered agents."""
        return list(self._agents.values())

    def list_metadata(self) -> List[AgentMetadata]:
        """Returns public metadata specifications for all registered agents."""
        return [
            AgentMetadata(
                agent_name=agent.agent_name,
                display_name=agent.display_name,
                description=agent.description,
                responsibilities=agent.responsibilities,
                supported_request_types=agent.supported_request_types,
                advisory_boundary=agent.advisory_boundary,
            )
            for agent in self._agents.values()
        ]

    def select_agents_for_request(
        self,
        request_type: str,
        explicit_agents: Optional[List[str]] = None,
    ) -> List[str]:
        """Determines which agents should execute for a given request type."""
        if explicit_agents:
            # Filter strictly to known registered agents
            valid = [a for a in explicit_agents if a in self._agents]
            if valid:
                return valid

        # Default mapping based on request_type
        if request_type == "full_investigation":
            return [
                "threat_intelligence_agent",
                "attack_path_agent",
                "risk_intelligence_agent",
                "incident_analysis_agent",
                "defensive_strategy_agent",
                "executive_intelligence_agent",
            ]
        elif request_type == "threat_focus":
            return ["threat_intelligence_agent", "attack_path_agent"]
        elif request_type == "attack_path_focus":
            return ["attack_path_agent", "threat_intelligence_agent"]
        elif request_type == "risk_focus":
            return ["risk_intelligence_agent", "executive_intelligence_agent"]
        elif request_type == "incident_focus":
            return ["incident_analysis_agent", "threat_intelligence_agent", "defensive_strategy_agent"]
        elif request_type == "defense_focus":
            return ["defensive_strategy_agent", "risk_intelligence_agent"]
        elif request_type == "executive_briefing":
            return ["executive_intelligence_agent", "risk_intelligence_agent"]
        else:
            return list(self._agents.keys())


# Global singleton registry
agent_registry = AgentRegistry()

