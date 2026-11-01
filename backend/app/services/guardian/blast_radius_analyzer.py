"""Bounded Blast Radius Graph Traversal Engine for Blue Guardian.

Performs deterministic, bounded traversal over explicitly registered SyntheticAsset
relationship topologies within authorized sandbox boundaries.
Guarantees cycle prevention, maximum traversal depth, and maximum node bounds.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import logging
from typing import Any, Dict, List, Optional, Set
import uuid

logger = logging.getLogger("aegismesh.guardian.blast_radius")


@dataclass(frozen=True)
class BlastRadiusNode:
    """Represents a discovered downstream asset in the blast radius."""
    asset_id: uuid.UUID
    depth: int
    path: List[str]
    exposure_reason: str


@dataclass(frozen=True)
class BlastRadiusResult:
    """Comprehensive traversal output for an analyzed threat detection."""
    root_asset_ids: Set[uuid.UUID]
    downstream_nodes: Dict[uuid.UUID, BlastRadiusNode]
    max_depth_reached: int
    total_nodes_visited: int
    blast_radius_ratio: float  # (directly_affected + exposed) / total_sandbox_assets


class BlastRadiusAnalyzer:
    """Evaluates bounded downstream asset exposure along registered connectivity graphs."""

    def __init__(
        self,
        max_depth: int = 3,
        max_nodes: int = 25,
    ):
        self.max_depth = max_depth
        self.max_nodes = max_nodes

    def analyze_blast_radius(
        self,
        root_asset_ids: Set[uuid.UUID],
        adjacency_map: Dict[uuid.UUID, Set[uuid.UUID]],
        valid_sandbox_asset_ids: Set[uuid.UUID],
    ) -> BlastRadiusResult:
        """Executes breadth-first search starting from root assets to find exposed assets.
        
        Rules:
        1. Roots are evaluated at depth 0.
        2. Downstream nodes are explored strictly up to max_depth and max_nodes.
        3. All traversed IDs must belong to valid_sandbox_asset_ids (sandbox isolation).
        4. Cycles are strictly prevented using a visited set.
        """
        # Filter roots strictly to valid sandbox assets
        sanitized_roots = {aid for aid in root_asset_ids if aid in valid_sandbox_asset_ids}
        if not sanitized_roots:
            return BlastRadiusResult(
                root_asset_ids=set(),
                downstream_nodes={},
                max_depth_reached=0,
                total_nodes_visited=0,
                blast_radius_ratio=0.0,
            )

        visited: Set[uuid.UUID] = set(sanitized_roots)
        downstream: Dict[uuid.UUID, BlastRadiusNode] = {}
        queue: deque[tuple[uuid.UUID, int, List[str]]] = deque()

        for root in sorted(list(sanitized_roots), key=lambda x: str(x)):
            queue.append((root, 0, [str(root)]))

        max_depth_reached = 0

        while queue and len(visited) < self.max_nodes:
            curr_id, curr_depth, curr_path = queue.popleft()
            max_depth_reached = max(max_depth_reached, curr_depth)

            if curr_depth >= self.max_depth:
                continue

            # Get neighbors from adjacency map, strictly constrained to sandbox assets
            neighbors = sorted(
                list(adjacency_map.get(curr_id, set()) & valid_sandbox_asset_ids),
                key=lambda x: str(x),
            )

            for neighbor_id in neighbors:
                if neighbor_id in visited:
                    continue

                visited.add(neighbor_id)
                next_depth = curr_depth + 1
                next_path = curr_path + [str(neighbor_id)]

                downstream[neighbor_id] = BlastRadiusNode(
                    asset_id=neighbor_id,
                    depth=next_depth,
                    path=next_path,
                    exposure_reason=(
                        f"Potentially exposed at network hop {next_depth} via connection "
                        f"from asset '{curr_id}'."
                    ),
                )

                if len(visited) >= self.max_nodes:
                    break

                queue.append((neighbor_id, next_depth, next_path))

        total_sandbox_count = max(1, len(valid_sandbox_asset_ids))
        total_impacted = len(sanitized_roots) + len(downstream)
        ratio = round(min(1.0, total_impacted / total_sandbox_count), 4)

        return BlastRadiusResult(
            root_asset_ids=sanitized_roots,
            downstream_nodes=downstream,
            max_depth_reached=max_depth_reached,
            total_nodes_visited=len(visited),
            blast_radius_ratio=ratio,
        )

