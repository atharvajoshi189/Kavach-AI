"""Base class and interface for specialized AegisMesh AI Agents.

All agents adhere to a strict advisory contract, non-authoritative boundaries,
and evidence-grounded reasoning.
"""

from abc import ABC, abstractmethod
import logging
from typing import Any, Set

from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.gateway.intelligence_gateway import intelligence_gateway
from app.ai.prompts.system_instructions import BASE_CYBERSECURITY_SYSTEM_INSTRUCTION
from app.ai.schemas.agent_schemas import AegisAgentOutput
from app.ai.state.state import AegisAIState

logger = logging.getLogger("aegismesh.ai.agents")


class BaseAegisAgent(ABC):
    """Abstract base class for all specialized security AI agents."""

    agent_name: str
    display_name: str
    description: str
    responsibilities: list[str]
    supported_request_types: list[str]
    advisory_boundary: str

    @abstractmethod
    def build_prompt(self, evidence: dict[str, Any], user_query: str | None = None) -> str:
        """Constructs the agent-specific prompt from sanitized evidence."""
        pass

    @abstractmethod
    def extract_evidence(self, state: AegisAIState) -> tuple[dict[str, Any], Set[str], float | None]:
        """Extracts the agent's required evidence partition and valid evidence UUIDs from graph state.

        Returns (evidence_dict, valid_id_set, optional_authoritative_score).
        """
        pass

    @abstractmethod
    def generate_fallback(self, evidence: dict[str, Any], reason: str) -> AegisAgentOutput:
        """Generates a deterministic template fallback when live provider is unavailable."""
        pass

    async def execute(self, state: AegisAIState, session: AsyncSession | None = None) -> AegisAgentOutput:
        """Executes the specialized agent reasoning over the graph state.

        Guarantees that errors in this agent return a graceful fallback rather
        than crashing the overall graph execution.
        """
        logger.info("Executing specialized AI agent '%s'", self.agent_name)
        try:
            evidence, valid_ids, auth_score = self.extract_evidence(state)
            user_query = state.get("user_query")

            prompt = self.build_prompt(evidence, user_query)
            fallback_factory = lambda reason: self.generate_fallback(evidence, reason)

            output = await intelligence_gateway.execute_agent_analysis(
                agent_name=self.agent_name,
                system_instruction=BASE_CYBERSECURITY_SYSTEM_INSTRUCTION,
                prompt=prompt,
                valid_evidence_ids=valid_ids,
                fallback_factory=fallback_factory,
                authoritative_score=auth_score,
            )
            return output

        except Exception as exc:
            logger.warning(
                "Agent '%s' encounter unexpected error (%s: %s). Falling back to deterministic template.",
                self.agent_name,
                type(exc).__name__,
                str(exc),
            )
            evidence, _, _ = self.extract_evidence(state)
            return self.generate_fallback(evidence, f"Execution exception: {type(exc).__name__}")

