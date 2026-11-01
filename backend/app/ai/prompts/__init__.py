"""AI prompts package."""

from app.ai.prompts.agent_prompts import (
    build_attack_path_agent_prompt,
    build_defensive_strategy_agent_prompt,
    build_executive_intelligence_agent_prompt,
    build_incident_analysis_agent_prompt,
    build_risk_intelligence_agent_prompt,
    build_threat_intelligence_agent_prompt,
)
from app.ai.prompts.system_instructions import (
    BASE_CYBERSECURITY_SYSTEM_INSTRUCTION,
)
from app.ai.prompts.templates import (
    build_attack_path_prompt,
    build_executive_briefing_prompt,
    build_incident_summary_prompt,
    build_recommendation_prompt,
    build_risk_explanation_prompt,
    build_security_qa_prompt,
    build_threat_explanation_prompt,
)

__all__ = [
    "BASE_CYBERSECURITY_SYSTEM_INSTRUCTION",
    "build_attack_path_agent_prompt",
    "build_defensive_strategy_agent_prompt",
    "build_executive_intelligence_agent_prompt",
    "build_incident_analysis_agent_prompt",
    "build_risk_intelligence_agent_prompt",
    "build_threat_intelligence_agent_prompt",
    "build_attack_path_prompt",
    "build_executive_briefing_prompt",
    "build_incident_summary_prompt",
    "build_recommendation_prompt",
    "build_risk_explanation_prompt",
    "build_security_qa_prompt",
    "build_threat_explanation_prompt",
]

