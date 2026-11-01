"""Threat Intelligence Agent.

Interprets existing threat detections and event correlation groups.
Advisory only: does not create or confirm detections.
"""

from typing import Any, Set

from app.ai.agents.base_agent import BaseAegisAgent
from app.ai.fallbacks.agent_fallbacks import AgentFallbackGenerator
from app.ai.prompts.agent_prompts import build_threat_intelligence_agent_prompt
from app.ai.schemas.agent_schemas import AegisAgentOutput
from app.ai.state.state import AegisAIState


class ThreatIntelligenceAgent(BaseAegisAgent):
    """Specialized agent reasoning over detected anomalies and correlation groups."""

    agent_name = "threat_intelligence_agent"
    display_name = "Threat Intelligence Agent"
    description = "Interprets existing threat detections and correlated event groups, explaining observed patterns."
    responsibilities = [
        "Interpret persisted Blue Guardian threat detections",
        "Explain suspicious activity and correlated event groups",
        "Identify valid supporting telemetry and evidence references",
        "Differentiate confirmed observations from threat hypotheses",
        "Highlight potential attack implications and missing forensic context",
    ]
    supported_request_types = ["full_investigation", "threat_focus", "incident_focus", "custom"]
    advisory_boundary = "Strictly advisory. Cannot create, confirm, or alter authoritative threat detection records."

    def build_prompt(self, evidence: dict[str, Any], user_query: str | None = None) -> str:
        return build_threat_intelligence_agent_prompt(evidence, user_query)

    def extract_evidence(self, state: AegisAIState) -> tuple[dict[str, Any], Set[str], float | None]:
        records = state.get("evidence_records", {})
        detections = records.get("detections", [])
        groups = records.get("correlation_groups", [])

        valid_ids: Set[str] = set()
        evidence_detections = []

        for d in detections:
            did = str(d.get("id"))
            valid_ids.add(did)
            if d.get("correlated_group_id"):
                valid_ids.add(str(d["correlated_group_id"]))
            for aid in d.get("affected_asset_ids", []):
                valid_ids.add(str(aid))

            evidence_detections.append({
                "detection_id": did,
                "title": d.get("title"),
                "rule_code": d.get("rule_code"),
                "classification": d.get("classification"),
                "severity": d.get("severity"),
                "confidence_score": d.get("confidence_score"),
                "mitre_techniques": d.get("mitre_techniques", []),
                "affected_asset_ids": d.get("affected_asset_ids", []),
                "detection_rationale": d.get("detection_rationale"),
            })

        for g in groups:
            gid = str(g.get("id"))
            valid_ids.add(gid)
            for eid in g.get("member_event_ids", []):
                valid_ids.add(str(eid))

        evidence = {
            "sandbox_id": state.get("sandbox_id"),
            "execution_id": state.get("execution_id"),
            "total_detections": len(evidence_detections),
            "detections": evidence_detections,
            "correlation_groups": groups[:5],
        }

        return evidence, valid_ids, None

    def generate_fallback(self, evidence: dict[str, Any], reason: str) -> AegisAgentOutput:
        return AgentFallbackGenerator.threat_intelligence_agent(evidence, reason)

