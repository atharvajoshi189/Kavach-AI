"""Attack Path Analysis Agent.

Analyzes existing attack path records and multi-stage kill chain progression.
Advisory only: does not invent attack paths or claim unevidenced compromises.
"""

from typing import Any, Set

from app.ai.agents.base_agent import BaseAegisAgent
from app.ai.fallbacks.agent_fallbacks import AgentFallbackGenerator
from app.ai.prompts.agent_prompts import build_attack_path_agent_prompt
from app.ai.schemas.agent_schemas import AegisAgentOutput
from app.ai.state.state import AegisAIState


class AttackPathAgent(BaseAegisAgent):
    """Specialized agent reasoning over multi-stage attack paths and asset graphs."""

    agent_name = "attack_path_agent"
    display_name = "Attack Path Analysis Agent"
    description = "Analyzes kill chain progression, stage dependencies, and choke points across synthetic assets."
    responsibilities = [
        "Analyze persisted multi-stage attack path records",
        "Explain sequential dependencies and prerequisite satisfaction",
        "Identify potentially exposed synthetic assets in the topology",
        "Highlight kill-chain gaps and lateral movement choke points",
        "Contextualize MITRE ATT&CK techniques grounded in persisted telemetry",
    ]
    supported_request_types = ["full_investigation", "attack_path_focus", "threat_focus", "custom"]
    advisory_boundary = "Strictly advisory. Cannot invent attack paths, simulate transitions, or modify topology state."

    def build_prompt(self, evidence: dict[str, Any], user_query: str | None = None) -> str:
        return build_attack_path_agent_prompt(evidence, user_query)

    def extract_evidence(self, state: AegisAIState) -> tuple[dict[str, Any], Set[str], float | None]:
        records = state.get("evidence_records", {})
        attack_paths = records.get("attack_paths", [])
        assets = records.get("assets", [])

        valid_ids: Set[str] = set()
        cleaned_paths = []

        for p in attack_paths:
            pid = str(p.get("id"))
            valid_ids.add(pid)
            if p.get("source_asset_id"):
                valid_ids.add(str(p["source_asset_id"]))
            if p.get("target_asset_id"):
                valid_ids.add(str(p["target_asset_id"]))

            stages = []
            for s in p.get("stages", []):
                sid = str(s.get("id"))
                valid_ids.add(sid)
                if s.get("source_asset_id"):
                    valid_ids.add(str(s["source_asset_id"]))
                if s.get("destination_asset_id"):
                    valid_ids.add(str(s["destination_asset_id"]))
                stages.append({
                    "stage_id": sid,
                    "sequence_number": s.get("sequence_number"),
                    "scenario_id": s.get("scenario_id"),
                    "status": s.get("status"),
                    "source_asset_id": s.get("source_asset_id"),
                    "destination_asset_id": s.get("destination_asset_id"),
                    "risk_score": s.get("risk_score"),
                })

            cleaned_paths.append({
                "attack_path_id": pid,
                "status": p.get("status"),
                "total_stages": p.get("total_stages"),
                "completed_stages": p.get("completed_stages"),
                "path_risk_score": p.get("path_risk_score"),
                "source_asset_id": p.get("source_asset_id"),
                "target_asset_id": p.get("target_asset_id"),
                "stages": stages,
            })

        cleaned_assets = []
        for a in assets:
            aid = str(a.get("id"))
            valid_ids.add(aid)
            cleaned_assets.append({
                "asset_id": aid,
                "name": a.get("name"),
                "asset_type": a.get("asset_type"),
                "risk_level": a.get("risk_level"),
            })

        evidence = {
            "sandbox_id": state.get("sandbox_id"),
            "execution_id": state.get("execution_id"),
            "attack_paths": cleaned_paths,
            "connected_assets": cleaned_assets[:10],
        }

        return evidence, valid_ids, None

    def generate_fallback(self, evidence: dict[str, Any], reason: str) -> AegisAgentOutput:
        return AgentFallbackGenerator.attack_path_agent(evidence, reason)

