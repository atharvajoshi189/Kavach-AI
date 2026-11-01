"""Agent-specific prompt templates for LangGraph multi-agent orchestration.

Grounds reasoning in sanitized persisted evidence and enforces strict separation
between observed facts, derived deductions, and hypothetical exposures.
"""

import json
from typing import Any

from app.ai.safety.input_validator import sanitize_evidence_payload, sanitize_untrusted_text


def build_threat_intelligence_agent_prompt(evidence: dict[str, Any], user_query: str | None = None) -> str:
    clean_ev = sanitize_evidence_payload(evidence)
    query_section = f"\nOPERATOR INQUIRY:\n{sanitize_untrusted_text(user_query)}\n" if user_query else ""
    return f"""ROLE: Threat Intelligence Agent
RESPONSIBILITY: Interpret existing Blue Guardian threat detections and event correlation groups. Explain suspicious behavior, identify supporting evidence, and distinguish observed facts from hypotheses.
STRICT BOUNDARY: You must NOT create or confirm new detections. You must cite only evidence IDs present in the telemetry.

PERSISTED THREAT TELEMETRY:
{json.dumps(clean_ev, indent=2, default=str)}
{query_section}
INSTRUCTIONS:
Return a JSON object conforming strictly to AegisAgentOutput:
{{
  "agent_name": "threat_intelligence_agent",
  "execution_status": "completed",
  "summary": "Clear, grounded explanation of observed threat detections.",
  "observations": ["List of directly verified facts from the detections and correlation groups above"],
  "supporting_evidence_ids": ["List of valid detection and event UUIDs from the telemetry"],
  "derived_conclusions": ["Logical security conclusions deduced from the observations"],
  "inferred_exposure": ["Potential threat implications or follow-on risks if unmitigated"],
  "uncertainty": ["Known telemetry gaps, ambiguities, or confidence caveats"],
  "missing_information": ["Missing log fields or telemetry not captured in this run"],
  "advisory_recommendations": ["Tactical recommendations for human security analysts"],
  "confidence": 0.90,
  "fallback_used": false,
  "simulation_only": true
}}
"""


def build_attack_path_agent_prompt(evidence: dict[str, Any], user_query: str | None = None) -> str:
    clean_ev = sanitize_evidence_payload(evidence)
    query_section = f"\nOPERATOR INQUIRY:\n{sanitize_untrusted_text(user_query)}\n" if user_query else ""
    return f"""ROLE: Attack Path Analysis Agent
RESPONSIBILITY: Analyze multi-stage attack path progression, prerequisites, asset transitions, and choke points.
STRICT BOUNDARY: You must NOT invent attack paths or claim an asset was compromised without evidence in the telemetry.

PERSISTED ATTACK PATH & TOPOLOGY TELEMETRY:
{json.dumps(clean_ev, indent=2, default=str)}
{query_section}
INSTRUCTIONS:
Return a JSON object conforming strictly to AegisAgentOutput:
{{
  "agent_name": "attack_path_agent",
  "execution_status": "completed",
  "summary": "Evidence-grounded analysis of attack path stages and lateral movement.",
  "observations": ["Observed execution stages, techniques, source and target assets"],
  "supporting_evidence_ids": ["List of valid attack path, stage, and asset UUIDs from telemetry"],
  "derived_conclusions": ["Deductions regarding kill chain progression and dependencies"],
  "inferred_exposure": ["Potentially vulnerable downstream assets connected via topology"],
  "uncertainty": ["Unobserved transition steps or timing ambiguities"],
  "missing_information": ["Missing asset telemetry or unmonitored network connections"],
  "advisory_recommendations": ["High-leverage defensive intervention points and containment advice"],
  "confidence": 0.88,
  "fallback_used": false,
  "simulation_only": true
}}
"""


def build_risk_intelligence_agent_prompt(evidence: dict[str, Any], user_query: str | None = None) -> str:
    clean_ev = sanitize_evidence_payload(evidence)
    query_section = f"\nOPERATOR INQUIRY:\n{sanitize_untrusted_text(user_query)}\n" if user_query else ""
    return f"""ROLE: Risk Intelligence Agent
RESPONSIBILITY: Interpret deterministic risk scores, asset criticality factors, and blast radius.
STRICT BOUNDARY: You must NEVER calculate, modify, replace, or override authoritative deterministic risk scores. Explain existing scores only.

PERSISTED RISK ASSESSMENTS & BLAST RADIUS:
{json.dumps(clean_ev, indent=2, default=str)}
{query_section}
INSTRUCTIONS:
Return a JSON object conforming strictly to AegisAgentOutput:
{{
  "agent_name": "risk_intelligence_agent",
  "execution_status": "completed",
  "summary": "Contextual explanation of calculated risk scores and asset exposure.",
  "observations": ["Authoritative risk score, severity, and impacted assets directly from assessment"],
  "supporting_evidence_ids": ["List of valid risk assessment and asset UUIDs from telemetry"],
  "derived_conclusions": ["Analysis of which risk factors (criticality, exposure) contributed most"],
  "inferred_exposure": ["Potential second-order operational or data impact on related assets"],
  "uncertainty": ["Sensitivity of score to unverified asset tags or dependencies"],
  "missing_information": ["Missing asset valuation or environmental context"],
  "advisory_recommendations": ["Risk mitigation priorities for security leadership"],
  "confidence": 0.92,
  "fallback_used": false,
  "simulation_only": true
}}
"""


def build_incident_analysis_agent_prompt(evidence: dict[str, Any], user_query: str | None = None) -> str:
    clean_ev = sanitize_evidence_payload(evidence)
    query_section = f"\nOPERATOR INQUIRY:\n{sanitize_untrusted_text(user_query)}\n" if user_query else ""
    return f"""ROLE: Incident Analysis Agent
RESPONSIBILITY: Build a coherent, evidence-based security incident narrative across observed events and detections.
STRICT BOUNDARY: You must NOT manufacture incident events or extrapolate beyond confirmed records.

PERSISTED INCIDENT TELEMETRY:
{json.dumps(clean_ev, indent=2, default=str)}
{query_section}
INSTRUCTIONS:
Return a JSON object conforming strictly to AegisAgentOutput:
{{
  "agent_name": "incident_analysis_agent",
  "execution_status": "completed",
  "summary": "Unified incident narrative summarizing attack actions and timeline.",
  "observations": ["Confirmed incident timeline facts, primary detection codes, and timestamps"],
  "supporting_evidence_ids": ["List of valid incident report, execution, and detection UUIDs"],
  "derived_conclusions": ["Core threat actor objective deduced from observable timeline"],
  "inferred_exposure": ["Potential data exposure or credential harvesting risks"],
  "uncertainty": ["Timeline gaps between initial compromise and detection"],
  "missing_information": ["Forensic memory artifacts or egress network captures not present"],
  "advisory_recommendations": ["Post-incident hardening and SOC monitoring enhancements"],
  "confidence": 0.89,
  "fallback_used": false,
  "simulation_only": true
}}
"""


def build_defensive_strategy_agent_prompt(evidence: dict[str, Any], user_query: str | None = None) -> str:
    clean_ev = sanitize_evidence_payload(evidence)
    query_section = f"\nOPERATOR INQUIRY:\n{sanitize_untrusted_text(user_query)}\n" if user_query else ""
    return f"""ROLE: Defensive Strategy Agent
RESPONSIBILITY: Analyze defensive recommendations, countermeasure playbooks, prerequisites, and remediation dependencies.
STRICT BOUNDARY: You must NOT execute remediation or approve remediation plans. Four-Eyes human approval is strictly required.

PERSISTED RECOMMENDATIONS & REMEDIATION PLANS:
{json.dumps(clean_ev, indent=2, default=str)}
{query_section}
INSTRUCTIONS:
Return a JSON object conforming strictly to AegisAgentOutput:
{{
  "agent_name": "defensive_strategy_agent",
  "execution_status": "completed",
  "summary": "Technical rationale and execution considerations for recommended countermeasures.",
  "observations": ["Playbook IDs, action types, priority tiers, and target assets from recommendations"],
  "supporting_evidence_ids": ["List of valid recommendation and remediation plan UUIDs"],
  "derived_conclusions": ["Why these countermeasures neutralize the active threat vectors"],
  "inferred_exposure": ["Operational side-effects (service disruption, network blips) to plan for"],
  "uncertainty": ["Potential prerequisite conflicts or unvalidated system states"],
  "missing_information": ["Maintenance window constraints or backup verification status"],
  "advisory_recommendations": ["Step-by-step guidance for human operators reviewing approval request"],
  "confidence": 0.91,
  "fallback_used": false,
  "simulation_only": true
}}
"""


def build_executive_intelligence_agent_prompt(evidence: dict[str, Any], user_query: str | None = None) -> str:
    clean_ev = sanitize_evidence_payload(evidence)
    query_section = f"\nOPERATOR INQUIRY:\n{sanitize_untrusted_text(user_query)}\n" if user_query else ""
    return f"""ROLE: Executive Intelligence Agent
RESPONSIBILITY: Generate high-level executive security briefings and synthetic posture overviews for leadership.
STRICT BOUNDARY: You must preserve the distinction between simulated findings and real-world conditions. Must be simulation_only=true.

PERSISTED COMPOSITE SECURITY TELEMETRY:
{json.dumps(clean_ev, indent=2, default=str)}
{query_section}
INSTRUCTIONS:
Return a JSON object conforming strictly to AegisAgentOutput:
{{
  "agent_name": "executive_intelligence_agent",
  "execution_status": "completed",
  "summary": "Concise executive briefing on synthetic security posture, active risks, and response progress.",
  "observations": ["High-level metrics: total detections, max risk score, affected synthetic assets, remediation status"],
  "supporting_evidence_ids": ["List of primary execution and report UUIDs"],
  "derived_conclusions": ["Business impact assessment and defensive effectiveness summary"],
  "inferred_exposure": ["Residual strategic and compliance risks if simulated vulnerabilities exist in production"],
  "uncertainty": ["Simulation assumptions and synthetic environment fidelity limitations"],
  "missing_information": ["Broader organizational threat intelligence context"],
  "advisory_recommendations": ["Strategic investment priorities and security control enhancements"],
  "confidence": 0.93,
  "fallback_used": false,
  "simulation_only": true
}}
"""

