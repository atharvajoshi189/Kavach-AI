"""Prompt builder functions for AI analysis capabilities."""

import json
from typing import Any
from app.ai.safety.input_validator import sanitize_evidence_payload, sanitize_untrusted_text


def build_threat_explanation_prompt(evidence: dict[str, Any]) -> str:
    clean_evidence = sanitize_evidence_payload(evidence)
    return f"""Analyze the following Blue Guardian threat detection and provide an evidence-grounded explanation.

PERSISTED THREAT TELEMETRY:
{json.dumps(clean_evidence, indent=2, default=str)}

Respond with a JSON object conforming to ThreatExplanationResponse:
- detection_id: "{clean_evidence.get('detection_id')}"
- mitre_attack_technique: "{clean_evidence.get('mitre_technique_id', '')}"
- severity: "{clean_evidence.get('severity', 'HIGH')}"
- target_asset_id: "{clean_evidence.get('target_asset_id', '')}"
- summary: Detailed contextual explanation of what occurred and why it was detected.
- key_findings: List of key security insights.
- supporting_evidence_ids: List of valid event, asset, or detection IDs from the telemetry above.
- observed_facts: Explicit facts extracted directly from the records.
- derived_conclusions: Logical defensive deductions.
- inferred_observations: Potential threat actor motivations or patterns.
- uncertainties: Incomplete information or potential false-positive indicators.
- suggested_actions: Tactical response and validation recommendations.
- attack_implications: Potential consequences if unaddressed.
- recommended_investigation_steps: Practical triage steps for the SOC team.
- provider: "gemini"
- model: "gemini-2.5-flash"
- is_ai_generated: true
"""


def build_attack_path_prompt(evidence: dict[str, Any]) -> str:
    clean_evidence = sanitize_evidence_payload(evidence)
    return f"""Analyze the progression of this multi-stage synthetic attack path.

ATTACK PATH TELEMETRY:
{json.dumps(clean_evidence, indent=2, default=str)}

Respond with a JSON object conforming to AttackPathAnalysisResponse:
- attack_path_id: "{clean_evidence.get('attack_path_id')}"
- progression_summary: Narrative of how the attack progressed across stages.
- critical_stages: List of stage objects with stage_number, technique, asset_id, and severity.
- transition_points: Key lateral movement or privilege escalation steps.
- affected_assets: List of asset UUIDs directly impacted.
- defensive_intervention_points: High-leverage interception opportunities.
- is_simulated: true
- summary: Overall executive overview of the attack path.
- key_findings: Bulleted insights on path efficacy and choke points.
- supporting_evidence_ids: List of valid stage IDs, detection IDs, and asset IDs.
- observed_facts: Facts observed in the stage execution logs.
- derived_conclusions: Kill-chain conclusions.
- inferred_observations: Inferred attack trajectory and objectives.
- uncertainties: Gaps in synthetic telemetry.
- suggested_actions: Recommended defensive hardening actions.
- provider: "gemini"
- model: "gemini-2.5-flash"
- is_ai_generated: true
"""


def build_risk_explanation_prompt(evidence: dict[str, Any]) -> str:
    clean_evidence = sanitize_evidence_payload(evidence)
    authoritative_score = clean_evidence.get("risk_score", 0.0)
    return f"""Explain the calculated Blue Guardian risk score for this threat assessment.
DO NOT recalculate or modify the risk score of {authoritative_score}. It is authoritative.

RISK ASSESSMENT TELEMETRY:
{json.dumps(clean_evidence, indent=2, default=str)}

Respond with a JSON object conforming to RiskExplanationResponse:
- assessment_id: "{clean_evidence.get('assessment_id')}"
- authoritative_risk_score: {authoritative_score}
- risk_level: "{clean_evidence.get('risk_level', 'HIGH')}"
- score_factors_explanation: Map of risk dimensions (e.g., severity_weight, asset_criticality, blast_radius, evidence_confidence) explaining how each contributed.
- primary_risk_drivers: Primary factors driving the score.
- defensive_focus_areas: Priority systems requiring mitigation.
- score_immutable_notice: "Deterministic risk score is authoritative and cannot be overridden by AI."
- summary: Cohesive explanation of why this risk score was assigned.
- key_findings: Key takeaways regarding operational exposure.
- supporting_evidence_ids: List of detection and asset IDs backing this score.
- observed_facts: Metrics and configurations recorded.
- derived_conclusions: Conclusions regarding relative exposure.
- inferred_observations: Potential cascading business impacts.
- uncertainties: Limitations of the risk calculation.
- suggested_actions: Suggested risk reduction steps.
- provider: "gemini"
- model: "gemini-2.5-flash"
- is_ai_generated: true
"""


def build_incident_summary_prompt(evidence: dict[str, Any]) -> str:
    clean_evidence = sanitize_evidence_payload(evidence)
    return f"""Synthesize a complete incident narrative and defensive briefing for this security incident.

INCIDENT REPORT DATA:
{json.dumps(clean_evidence, indent=2, default=str)}

Respond with a JSON object conforming to IncidentSummaryResponse:
- report_id: "{clean_evidence.get('report_id')}"
- incident_narrative: Clear narrative synthesizing initial trigger, lateral activity, impact, and containment.
- timeline_highlights: Key chronological event timestamps and milestones.
- potential_consequences: Operational, data, or integrity impacts.
- immediate_defensive_priorities: Top 3-5 immediate defensive steps.
- summary: High-level executive overview of the incident.
- key_findings: Major findings uncovered during investigation.
- supporting_evidence_ids: List of detection IDs, event IDs, and asset IDs.
- observed_facts: Chronological verified events.
- derived_conclusions: Attacker objectives and blast radius conclusions.
- inferred_observations: Potential broader campaign associations.
- uncertainties: Any remaining ambiguities or unobserved steps.
- suggested_actions: Post-incident hardening and playbook updates.
- provider: "gemini"
- model: "gemini-2.5-flash"
- is_ai_generated: true
"""


def build_recommendation_prompt(evidence: dict[str, Any]) -> str:
    clean_evidence = sanitize_evidence_payload(evidence)
    return f"""Explain the defensive rationale, operational side effects, and verification criteria for this recommendation.

DEFENSIVE RECOMMENDATION DATA:
{json.dumps(clean_evidence, indent=2, default=str)}

Respond with a JSON object conforming to RecommendationExplanationResponse:
- recommendation_id: "{clean_evidence.get('recommendation_id')}"
- playbook_title: "{clean_evidence.get('playbook_name', 'Playbook')}"
- action_rationale: Technical rationale explaining why this countermeasure mitigates the threat.
- expected_defensive_impact: Measurable impact on threat disruption.
- operational_side_effects: Potential side-effects on legitimate workflows or services.
- verification_guidance: Specific telemetry checks to confirm resolution.
- requires_human_approval: true
- summary: Practical explanation of the recommendation for SOC operators.
- key_findings: Core advantages and prerequisites.
- supporting_evidence_ids: List of detection and asset IDs.
- observed_facts: Triggering conditions in the environment.
- derived_conclusions: Effectiveness justification.
- inferred_observations: Risk reduction implications.
- uncertainties: Edge cases where the countermeasure may be incomplete.
- suggested_actions: Implementation steps for human approval review.
- provider: "gemini"
- model: "gemini-2.5-flash"
- is_ai_generated: true
"""


def build_executive_briefing_prompt(evidence: dict[str, Any]) -> str:
    clean_evidence = sanitize_evidence_payload(evidence)
    return f"""Generate an executive security briefing for organizational leadership based on this execution run.

EXECUTION & POSTURE TELEMETRY:
{json.dumps(clean_evidence, indent=2, default=str)}

Respond with a JSON object conforming to ExecutiveBriefingResponse:
- execution_id: "{clean_evidence.get('execution_id')}"
- executive_overview: High-level strategic summary of the security exercise.
- critical_risk_posture: Clear statement of overall defensive readiness and posture.
- top_findings: Bulleted strategic observations for leadership.
- strategic_priorities: Recommended resource allocation and defensive initiatives.
- remediation_governance_status: Summary of human approvals and remediation actions taken.
- operational_limitations: Explicit boundary statement that this was a synthetic simulation.
- summary: High-level executive overview.
- key_findings: Key takeaways.
- supporting_evidence_ids: List of execution, detection, and plan IDs.
- observed_facts: Metrics regarding detected threats and response latency.
- derived_conclusions: Organizational resilience posture.
- inferred_observations: Future threat resilience trends.
- uncertainties: Scope boundaries of the synthetic evaluation.
- suggested_actions: Board/Leadership level recommendations.
- provider: "gemini"
- model: "gemini-2.5-flash"
- is_ai_generated: true
"""


def build_security_qa_prompt(evidence: dict[str, Any], question: str) -> str:
    clean_evidence = sanitize_evidence_payload(evidence)
    clean_question = sanitize_untrusted_text(question, max_length=1000)
    return f"""Answer the user's security question using strictly the provided contextual telemetry.
Do not invent information outside the context.

CONTEXT TELEMETRY:
{json.dumps(clean_evidence, indent=2, default=str)}

USER QUESTION:
{clean_question}

Respond with a JSON object conforming to SecurityQAResponse:
- execution_id: "{clean_evidence.get('execution_id')}"
- question: "{clean_question}"
- answer: Accurate, concise answer directly addressing the question using the telemetry.
- grounded_facts: Specific data points cited to substantiate the answer.
- summary: Quick one-sentence takeaway.
- key_findings: Findings relevant to the inquiry.
- supporting_evidence_ids: List of matching detection or asset IDs.
- observed_facts: Observed facts referenced in the answer.
- derived_conclusions: Deductions answering the question.
- inferred_observations: Relevant contextual patterns.
- uncertainties: What cannot be definitively answered from available telemetry.
- suggested_actions: Follow-up investigation actions.
- provider: "gemini"
- model: "gemini-2.5-flash"
- is_ai_generated: true
"""

