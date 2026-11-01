"""Risk Intelligence Agent.

Interprets deterministic risk scores and blast radius calculations.
Advisory only: NEVER calculates, modifies, replaces, or overrides authoritative risk scores.
"""

from typing import Any, Set

from app.ai.agents.base_agent import BaseAegisAgent
from app.ai.fallbacks.agent_fallbacks import AgentFallbackGenerator
from app.ai.prompts.agent_prompts import build_risk_intelligence_agent_prompt
from app.ai.schemas.agent_schemas import AegisAgentOutput
from app.ai.state.state import AegisAIState


class RiskIntelligenceAgent(BaseAegisAgent):
    """Specialized agent explaining deterministic risk metrics and asset impact."""

    agent_name = "risk_intelligence_agent"
    display_name = "Risk Intelligence Agent"
    description = "Interprets deterministic multi-dimensional risk scores, asset criticality, and blast radius."
    responsibilities = [
        "Interpret authoritative deterministic risk assessments",
        "Explain relative weighting of asset criticality and exploitability factors",
        "Contextualize blast radius and downstream asset exposure",
        "Highlight operational risk trade-offs without altering scores",
        "Explain uncertainty bounds and missing environmental telemetry",
    ]
    supported_request_types = ["full_investigation", "risk_focus", "incident_focus", "executive_briefing", "custom"]
    advisory_boundary = "Strictly advisory. CANNOT calculate, alter, or override authoritative deterministic risk scores."

    def build_prompt(self, evidence: dict[str, Any], user_query: str | None = None) -> str:
        return build_risk_intelligence_agent_prompt(evidence, user_query)

    def extract_evidence(self, state: AegisAIState) -> tuple[dict[str, Any], Set[str], float | None]:
        records = state.get("evidence_records", {})
        assessments = records.get("risk_assessments", [])
        impacts = records.get("asset_impacts", [])

        valid_ids: Set[str] = set()
        cleaned_assessments = []
        max_authoritative_score: float | None = None

        for a in assessments:
            aid = str(a.get("id"))
            valid_ids.add(aid)
            if a.get("threat_detection_id"):
                valid_ids.add(str(a["threat_detection_id"]))

            score = float(a.get("risk_score", 0.0))
            if max_authoritative_score is None or score > max_authoritative_score:
                max_authoritative_score = score

            cleaned_assessments.append({
                "assessment_id": aid,
                "threat_detection_id": a.get("threat_detection_id"),
                "risk_score": score,
                "risk_category": a.get("risk_category"),
                "severity": a.get("severity"),
                "asset_criticality_score": a.get("asset_criticality_score"),
                "blast_radius_factor": a.get("blast_radius_factor"),
            })

        for imp in impacts:
            iid = str(imp.get("id"))
            valid_ids.add(iid)
            if imp.get("asset_id"):
                valid_ids.add(str(imp["asset_id"]))

        evidence = {
            "sandbox_id": state.get("sandbox_id"),
            "execution_id": state.get("execution_id"),
            "risk_score": max_authoritative_score or 75.0,
            "risk_category": "HIGH" if (max_authoritative_score or 75.0) >= 70.0 else "MEDIUM",
            "assessments": cleaned_assessments,
            "asset_impacts": impacts[:5],
        }

        return evidence, valid_ids, max_authoritative_score

    def generate_fallback(self, evidence: dict[str, Any], reason: str) -> AegisAgentOutput:
        return AgentFallbackGenerator.risk_intelligence_agent(evidence, reason)

