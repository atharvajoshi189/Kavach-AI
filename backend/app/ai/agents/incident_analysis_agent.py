"""Incident Analysis Agent.

Constructs evidence-based incident narratives across events and detections.
Advisory only: does not manufacture events or extrapolate beyond confirmed records.
"""

from typing import Any, Set

from app.ai.agents.base_agent import BaseAegisAgent
from app.ai.fallbacks.agent_fallbacks import AgentFallbackGenerator
from app.ai.prompts.agent_prompts import build_incident_analysis_agent_prompt
from app.ai.schemas.agent_schemas import AegisAgentOutput
from app.ai.state.state import AegisAIState


class IncidentAnalysisAgent(BaseAegisAgent):
    """Specialized agent synthesizing coherent incident timelines and dossiers."""

    agent_name = "incident_analysis_agent"
    display_name = "Incident Analysis Agent"
    description = "Constructs evidence-based incident narratives, separating observed facts from deductions."
    responsibilities = [
        "Synthesize comprehensive security incident narratives",
        "Chronologically order observed ingress, persistence, and impact events",
        "Strictly separate confirmed facts, deduced objectives, and inferred risks",
        "Identify unresolved questions and forensic gaps for SOC triage",
        "Produce actionable incident dossiers for security operations",
    ]
    supported_request_types = ["full_investigation", "incident_focus", "threat_focus", "custom"]
    advisory_boundary = "Strictly advisory. Cannot manufacture incident records, alter status, or fabricate evidence."

    def build_prompt(self, evidence: dict[str, Any], user_query: str | None = None) -> str:
        return build_incident_analysis_agent_prompt(evidence, user_query)

    def extract_evidence(self, state: AegisAIState) -> tuple[dict[str, Any], Set[str], float | None]:
        records = state.get("evidence_records", {})
        reports = records.get("incident_reports", [])
        detections = records.get("detections", [])

        valid_ids: Set[str] = set()
        cleaned_reports = []

        for r in reports:
            rid = str(r.get("id"))
            valid_ids.add(rid)
            if r.get("guardian_execution_id"):
                valid_ids.add(str(r["guardian_execution_id"]))
            for aid in r.get("affected_asset_ids", []):
                valid_ids.add(str(aid))

            cleaned_reports.append({
                "report_id": rid,
                "title": r.get("title"),
                "severity": r.get("severity"),
                "max_risk_score": r.get("max_risk_score"),
                "executive_summary": r.get("executive_summary"),
                "report_status": r.get("report_status"),
                "affected_asset_ids": r.get("affected_asset_ids", []),
            })

        for d in detections:
            valid_ids.add(str(d.get("id")))

        evidence = {
            "sandbox_id": state.get("sandbox_id"),
            "execution_id": state.get("execution_id"),
            "incident_reports": cleaned_reports,
            "total_detections_in_incident": len(detections),
            "key_detection_codes": [d.get("detection_code") for d in detections[:5] if d.get("detection_code")],
        }

        return evidence, valid_ids, None

    def generate_fallback(self, evidence: dict[str, Any], reason: str) -> AegisAgentOutput:
        return AgentFallbackGenerator.incident_analysis_agent(evidence, reason)

