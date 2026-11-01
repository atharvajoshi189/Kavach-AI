"""Defensive Strategy Agent.

Explains defensive recommendations, playbooks, dependencies, and operational side-effects.
Advisory only: CANNOT approve plans or execute synthetic remediation.
"""

from typing import Any, Set

from app.ai.agents.base_agent import BaseAegisAgent
from app.ai.fallbacks.agent_fallbacks import AgentFallbackGenerator
from app.ai.prompts.agent_prompts import build_defensive_strategy_agent_prompt
from app.ai.schemas.agent_schemas import AegisAgentOutput
from app.ai.state.state import AegisAIState


class DefensiveStrategyAgent(BaseAegisAgent):
    """Specialized agent reasoning over defensive countermeasures and remediation plans."""

    agent_name = "defensive_strategy_agent"
    display_name = "Defensive Strategy Agent"
    description = "Explains technical rationale, operational dependencies, and verification criteria for countermeasures."
    responsibilities = [
        "Analyze persisted defensive recommendations and playbooks",
        "Explain tactical rationale for specific countermeasure selection",
        "Identify sequencing dependencies and potential operational disruptions",
        "Formulate verification criteria for human operators reviewing approvals",
        "Highlight non-binding containment and hardening advisory tips",
    ]
    supported_request_types = ["full_investigation", "defense_focus", "incident_focus", "custom"]
    advisory_boundary = "Strictly advisory. CANNOT approve remediation plans or execute synthetic actions."

    def build_prompt(self, evidence: dict[str, Any], user_query: str | None = None) -> str:
        return build_defensive_strategy_agent_prompt(evidence, user_query)

    def extract_evidence(self, state: AegisAIState) -> tuple[dict[str, Any], Set[str], float | None]:
        records = state.get("evidence_records", {})
        recommendations = records.get("recommendations", [])
        plans = records.get("remediation_plans", [])

        valid_ids: Set[str] = set()
        cleaned_recs = []

        for r in recommendations:
            rid = str(r.get("id"))
            valid_ids.add(rid)
            if r.get("threat_detection_id"):
                valid_ids.add(str(r["threat_detection_id"]))
            if r.get("risk_assessment_id"):
                valid_ids.add(str(r["risk_assessment_id"]))

            cleaned_recs.append({
                "recommendation_id": rid,
                "recommendation_code": r.get("recommendation_code"),
                "title": r.get("title"),
                "description": r.get("description"),
                "priority": r.get("priority"),
                "recommendation_type": r.get("recommendation_type"),
                "playbook_id": r.get("playbook_id"),
            })

        cleaned_plans = []
        for p in plans:
            pid = str(p.get("id"))
            valid_ids.add(pid)
            cleaned_plans.append({
                "plan_id": pid,
                "plan_status": p.get("plan_status"),
                "total_actions": p.get("total_actions"),
            })

        evidence = {
            "sandbox_id": state.get("sandbox_id"),
            "execution_id": state.get("execution_id"),
            "total_recommendations": len(cleaned_recs),
            "recommendations": cleaned_recs,
            "remediation_plans": cleaned_plans,
        }

        return evidence, valid_ids, None

    def generate_fallback(self, evidence: dict[str, Any], reason: str) -> AegisAgentOutput:
        return AgentFallbackGenerator.defensive_strategy_agent(evidence, reason)

