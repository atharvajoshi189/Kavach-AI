"""Attack path graph reconstruction from completed execution records."""
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.attack_path import AttackPath
from app.models.synthetic_asset import SyntheticAsset
from app.agents.red_team.attack_path_schemas import AttackPathNode, AttackPathEdge


async def reconstruct_attack_path_graph(
    session: AsyncSession,
    attack_path: AttackPath,
) -> tuple[list[AttackPathNode], list[AttackPathEdge]]:
    """
    Reconstructs the attack path graph from executed/planned stages.

    Returns:
        (nodes, edges) where nodes are unique participating assets
        and edges represent actual execution outcomes (not hypothetical).

    Edge status values:
        confirmed_relationship - exists in connected_asset_ids
        completed_stage - stage executed successfully
        failed_stage - stage failed
        skipped_stage - stage was skipped due to upstream failure
        planned_only - stage was planned but never executed
    """
    nodes_by_id: dict[str, AttackPathNode] = {}
    edges: list[AttackPathEdge] = []

    async def get_asset(asset_id) -> SyntheticAsset | None:
        return await session.get(SyntheticAsset, asset_id)

    async def ensure_node(asset_id) -> str:
        aid = str(asset_id)
        if aid not in nodes_by_id:
            asset = await get_asset(asset_id)
            if asset:
                nodes_by_id[aid] = AttackPathNode(
                    asset_id=aid,
                    asset_name=asset.name,
                    asset_type=asset.asset_type,
                    sandbox_id=str(asset.sandbox_id),
                    status=asset.status,
                    risk_level=asset.risk_level,
                )
        return aid

    for stage in attack_path.stages:
        src = await ensure_node(stage.source_asset_id)

        # Determine edge status based on stage status
        if stage.status == "completed":
            edge_status = "completed_stage"
        elif stage.status == "failed":
            edge_status = "failed_stage"
        elif stage.status == "skipped":
            edge_status = "skipped_stage"
        else:
            edge_status = "planned_only"

        if stage.destination_asset_id:
            dst = await ensure_node(stage.destination_asset_id)
            # Check confirmed_relationship for lateral movement
            src_asset = await get_asset(stage.source_asset_id)
            if src_asset and str(stage.destination_asset_id) in (src_asset.connected_asset_ids or []):
                confirmed_status = "confirmed_relationship"
            else:
                confirmed_status = edge_status

            edges.append(AttackPathEdge(
                source_asset_id=src,
                destination_asset_id=dst,
                relationship_type="lateral_movement",
                scenario_reference=stage.scenario_id,
                edge_status=confirmed_status,
            ))
        else:
            # Self-directed scenario — add a self-edge
            edges.append(AttackPathEdge(
                source_asset_id=src,
                destination_asset_id=src,
                relationship_type="scenario_execution",
                scenario_reference=stage.scenario_id,
                edge_status=edge_status,
            ))

    return list(nodes_by_id.values()), edges

