"""Executive Intelligence Agent.

Synthesizes high-level executive briefings and synthetic security posture reports.
Advisory only: strictly enforces simulation-only and is_simulated invariants.
"""

from typing import Any, Set

from app.ai.agents.base_agent import BaseAegisAgent
from app.ai.fallbacks.agent_fallbacks import AgentFallbackGenerator
from app.ai.prompts.agent_prompts import build_executive_intelligence_agent_prompt
from app.ai.schemas.agent_schemas import AegisAgentOutput
from app.ai.state.state import AegisAIState


class ExecutiveIntelligenceAgent(BaseAegisAgent):
    """Specialized agent synthesizing executive briefings and strategic risk posture."""

    agent_name = "executive_intelligence_agent"
    display_name = "Executive Intelligence Agent"
    description = "Synthesizes management-level briefings, business risks, and synthetic security posture."
    responsibilities = [
        "Synthesize high-level executive security briefings for leadership",
        "Summarize active synthetic security posture and automated defense effectiveness",
        "Translate technical detection metrics into business-relevant risk narratives",
        "Review remediation approval status and human governance compliance",
        "Preserve strict separation between simulated findings and real-world conditions",
    ]
    supported_request_types = ["full_investigation", "executive_briefing", "risk_focus", "custom"]
    advisory_boundary = "Strictly advisory. Enforces simulation_only=true and cannot modify real or synthetic assets."

    def build_prompt(self, evidence: dict[str, Any], user_query: str | None = None) -> str:
        return build_executive_intelligence_agent_prompt(evidence, user_query)

    def extract_evidence(self, state: AegisAIState) -> tuple[dict[str, Any], Set[str], float | None]:
        records = state.get("evidence_records", {})
        valid_ids: Set[str] = set()

        exec_id = state.get("execution_id")
        if exec_id:
            valid_ids.add(str(exec_id))

        total_detections = len(records.get("detections", []))
        total_paths = len(records.get("attack_paths", []))
        total_recs = len(records.get("recommendations", []))

        max_score = 0.0
        for a in records.get("risk_assessments", []):
            aid = str(a.get("id"))
            valid_ids.add(aid)
            score = float(a.get("risk_score", 0.0))
            if score > max_score:
                max_score = score

        for r in records.get("incident_reports", []):
            valid_ids.add(str(r.get("id")))

        evidence = {
            "sandbox_id": state.get("sandbox_id"),
            "execution_id": exec_id,
            "total_detections": total_detections,
            "total_attack_paths": total_paths,
            "max_risk_score": max_score if max_score > 0 else 75.0,
            "total_recommendations": total_recs,
            "total_plans": len(records.get("remediation_plans", [])),
            "total_assets_in_scope": len(records.get("assets", [])),
        }

        return evidence, valid_ids, max_score if max_score > 0 else None

    def generate_fallback(self, evidence: dict[str, Any], reason: str) -> AegisAgentOutput:
        return AgentFallbackGenerator.executive_intelligence_agent(evidence, reason)

