"""Attack path planning — generates ordered multi-stage synthetic attack sequences."""

from datetime import datetime, timezone
from typing import Any, Optional
import uuid
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.attack_path import AttackPath
from app.models.attack_path_stage import AttackPathStage
from app.models.campaign import Campaign
from app.models.sandbox import SandboxEnvironment
from app.models.synthetic_asset import SyntheticAsset
from app.services.attack_path_graph import AssetRelationshipGraph
from app.services.scenario_dependency import (
    KILL_CHAIN_ORDER,
    SCENARIO_DEPENDENCY_MAP,
    dependency_engine,
)

logger = logging.getLogger("aegismesh.services.attack_path_planner")

MAX_PATH_DEPTH = 8
MAX_STAGES = 8


def _risk_level_to_float(risk_level: str) -> float:
    return {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}.get(risk_level, 0.5)


def _stage_base_risk(scenario_id: str) -> float:
    """Returns a base risk score for a scenario based on its kill-chain position."""
    base_risk = {
        "simulated_service_discovery": 2.0,
        "simulated_weak_configuration_assessment": 2.5,
        "simulated_authentication_anomaly": 4.0,
        "simulated_initial_access": 5.0,
        "simulated_privilege_escalation": 6.5,
        "simulated_lateral_movement": 7.0,
        "simulated_persistence": 7.5,
        "simulated_data_exfiltration": 9.0,
    }
    return base_risk.get(scenario_id, 5.0)


async def plan_attack_path(
    session: AsyncSession,
    campaign: Campaign,
    sandbox: SandboxEnvironment,
    source_asset: SyntheticAsset,
    destination_asset_id: Optional[uuid.UUID] = None,
    execution_mode: str = "exploratory",
    scenario_constraints: Optional[list[str]] = None,
    max_stages: int = 6,
) -> tuple[AttackPath, list[str], list[dict[str, Any]]]:
    """
    Plans a multi-stage synthetic attack path.

    Returns:
        (AttackPath, planning_explanation, rejected_candidates)
    """
    planning_explanation: list[str] = []
    rejected_candidates: list[dict[str, Any]] = []

    # Clamp max_stages
    max_stages = min(max_stages, MAX_STAGES)

    # Build asset relationship graph
    graph = await AssetRelationshipGraph.build(session=session, sandbox_id=sandbox.id)
    planning_explanation.append(f"Built asset relationship graph: {len(graph.asset_map)} assets, {sum(len(v) for v in graph.adjacency.values())} edges")

    # Validate source asset
    if str(source_asset.id) not in graph.asset_map:
        raise ValueError(f"Source asset '{source_asset.id}' not found in sandbox graph (may be archived).")

    source_asset_type = source_asset.asset_type

    # Determine candidate scenarios for source asset type, filtered by constraints
    all_compatible = dependency_engine.get_supported_scenarios_for_asset_type(source_asset_type)
    if scenario_constraints:
        all_compatible = [s for s in all_compatible if s in scenario_constraints]
        planning_explanation.append(f"Applied scenario constraints: {scenario_constraints}")

    if not all_compatible:
        raise ValueError(f"No compatible scenarios found for asset type '{source_asset_type}' with the given constraints.")

    # Planning algorithm: build a kill-chain ordered stage sequence
    # Start from the first compatible scenario and follow allowed transitions
    stages_plan: list[dict[str, Any]] = []  # {scenario_id, source_asset_id, destination_asset_id}

    current_scenario = all_compatible[0]
    current_asset_id = str(source_asset.id)
    current_asset_type = source_asset_type

    planning_explanation.append(f"Starting path at scenario '{current_scenario}' on asset '{source_asset.name}' (type: {current_asset_type})")

    while len(stages_plan) < max_stages:
        info = SCENARIO_DEPENDENCY_MAP.get(current_scenario, {})
        requires_dest = info.get("requires_destination", False)
        dest_asset_id_str: Optional[str] = None

        if requires_dest:
            # For lateral movement: need a connected neighbor
            neighbors = graph.get_neighbors(current_asset_id)
            # Filter to compatible asset types for the scenario
            compatible_neighbors = [
                n for n in neighbors
                if dependency_engine.is_compatible(current_scenario, graph.asset_map[n].asset_type)
            ]
            if not compatible_neighbors:
                rejected_candidates.append({
                    "scenario_id": current_scenario,
                    "reason": f"No connected neighbors available for lateral movement from asset '{current_asset_id}'",
                    "asset_id": current_asset_id,
                })
                planning_explanation.append(f"Skipping '{current_scenario}': no connected neighbors for lateral movement")
                # Skip lateral movement — try next in allowed transitions
                next_options = info.get("allowed_transitions", [])
                next_options = [s for s in next_options if dependency_engine.is_compatible(s, current_asset_type)]
                if not next_options:
                    break
                current_scenario = next_options[0]
                continue

            # If destination_asset_id was specified, prefer it if reachable
            if destination_asset_id and str(destination_asset_id) in compatible_neighbors:
                dest_asset_id_str = str(destination_asset_id)
            else:
                dest_asset_id_str = compatible_neighbors[0]

        stages_plan.append({
            "scenario_id": current_scenario,
            "source_asset_id": uuid.UUID(current_asset_id),
            "destination_asset_id": uuid.UUID(dest_asset_id_str) if dest_asset_id_str else None,
            "base_risk": _stage_base_risk(current_scenario),
        })
        planning_explanation.append(
            f"Stage {len(stages_plan)}: '{current_scenario}' on asset '{graph.asset_map[current_asset_id].name}'"
            + (f" → '{graph.asset_map[dest_asset_id_str].name}'" if dest_asset_id_str else "")
        )

        # After lateral movement, move to destination asset for subsequent stages
        if requires_dest and dest_asset_id_str:
            current_asset_id = dest_asset_id_str
            current_asset_type = graph.asset_map[current_asset_id].asset_type

        # Check if we've reached the destination
        if destination_asset_id and current_asset_id == str(destination_asset_id):
            # Check if destination asset supports exfiltration or persistence
            dest_asset_type = graph.asset_map[current_asset_id].asset_type
            if dependency_engine.is_compatible("simulated_data_exfiltration", dest_asset_type):
                if len(stages_plan) < max_stages:
                    stages_plan.append({
                        "scenario_id": "simulated_data_exfiltration",
                        "source_asset_id": uuid.UUID(current_asset_id),
                        "destination_asset_id": None,
                        "base_risk": _stage_base_risk("simulated_data_exfiltration"),
                    })
                    planning_explanation.append(f"Stage {len(stages_plan)}: 'simulated_data_exfiltration' on destination asset")
            planning_explanation.append("Reached destination asset — path planning complete")
            break

        # Find next scenario
        allowed = info.get("allowed_transitions", [])
        if scenario_constraints:
            allowed = [s for s in allowed if s in scenario_constraints]

        # Filter to scenarios compatible with current asset type
        compatible_next = [s for s in allowed if dependency_engine.is_compatible(s, current_asset_type)]

        # Prefer kill-chain order
        compatible_next_ordered = sorted(compatible_next, key=lambda s: KILL_CHAIN_ORDER.index(s) if s in KILL_CHAIN_ORDER else 999)

        if not compatible_next_ordered:
            planning_explanation.append(f"No further transitions from '{current_scenario}' for asset type '{current_asset_type}' — path complete")
            break

        # Track rejected candidates
        for rejected in allowed:
            if rejected not in compatible_next:
                rejected_candidates.append({
                    "scenario_id": rejected,
                    "reason": f"Incompatible with current asset type '{current_asset_type}'",
                    "asset_id": current_asset_id,
                })

        current_scenario = compatible_next_ordered[0]

    if not stages_plan:
        raise ValueError(f"Attack path planner could not generate any stages for asset type '{source_asset_type}'")

    planning_explanation.append(f"Attack path planning complete: {len(stages_plan)} stages planned")

    # Create AttackPath record
    attack_path = AttackPath(
        campaign_id=campaign.id,
        sandbox_id=sandbox.id,
        source_asset_id=source_asset.id,
        status="planned",
        execution_mode=execution_mode,
        total_stages=len(stages_plan),
        completed_stages=0,
        failed_stages=0,
        risk_score=None,
        simulation_only=True,
        path_metadata={
            "planning_explanation": planning_explanation,
            "rejected_candidates": rejected_candidates,
            "campaign_name": campaign.name,
            "sandbox_name": sandbox.name,
            "source_asset_name": source_asset.name,
        },
    )
    session.add(attack_path)
    await session.flush()

    # Create AttackPathStage records
    for i, stage_data in enumerate(stages_plan, start=1):
        stage = AttackPathStage(
            attack_path_id=attack_path.id,
            sequence_number=i,
            scenario_id=stage_data["scenario_id"],
            source_asset_id=stage_data["source_asset_id"],
            destination_asset_id=stage_data.get("destination_asset_id"),
            status="pending",
            prerequisites=[],
            risk_score=stage_data["base_risk"],
            stage_metadata={},
            simulation_only=True,
            is_simulated=True,
        )
        session.add(stage)

    await session.flush()

    # Refresh to load stages
    await session.refresh(attack_path, ["stages"])

    return attack_path, planning_explanation, rejected_candidates
