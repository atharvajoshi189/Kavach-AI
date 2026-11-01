"""Asset relationship graph for attack path planning."""
from collections import deque
from typing import Optional
import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.synthetic_asset import SyntheticAsset


class AssetRelationshipGraph:
    """Directed graph of synthetic asset relationships within a sandbox."""

    def __init__(self, adjacency: dict[str, list[str]], asset_map: dict[str, SyntheticAsset]):
        # adjacency: {asset_id_str: [connected_asset_id_str, ...]}
        self.adjacency = adjacency
        self.asset_map = asset_map  # {asset_id_str: SyntheticAsset}

    @classmethod
    async def build(cls, session: AsyncSession, sandbox_id: uuid.UUID) -> "AssetRelationshipGraph":
        """Builds graph from all non-archived synthetic assets in the sandbox."""
        result = await session.execute(
            select(SyntheticAsset).where(
                SyntheticAsset.sandbox_id == sandbox_id,
                SyntheticAsset.status != "archived",
            )
        )
        assets = list(result.scalars().all())
        asset_ids = {str(a.id) for a in assets}
        asset_map = {str(a.id): a for a in assets}

        adjacency: dict[str, list[str]] = {}
        for asset in assets:
            neighbors = []
            for target_id in (asset.connected_asset_ids or []):
                if target_id in asset_ids:
                    neighbors.append(target_id)
                # Skip if target not in sandbox or archived
            adjacency[str(asset.id)] = neighbors

        return cls(adjacency=adjacency, asset_map=asset_map)

    def has_edge(self, source_id: str, dest_id: str) -> bool:
        """Returns True if there is a direct edge from source to dest."""
        return dest_id in self.adjacency.get(source_id, [])

    def get_neighbors(self, asset_id: str) -> list[str]:
        """Returns direct neighbors of an asset."""
        return list(self.adjacency.get(asset_id, []))

    def get_reachable_assets(self, source_id: str, max_depth: int = 5) -> list[str]:
        """BFS to find all reachable assets from source within max_depth hops."""
        visited = set()
        queue = deque([(source_id, 0)])
        reachable = []
        while queue:
            current, depth = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            if current != source_id:
                reachable.append(current)
            if depth < max_depth:
                for neighbor in self.adjacency.get(current, []):
                    if neighbor not in visited:
                        queue.append((neighbor, depth + 1))
        return reachable

    def find_paths(
        self,
        source_id: str,
        dest_id: Optional[str] = None,
        max_depth: int = 5,
    ) -> list[list[str]]:
        """DFS to find all simple paths from source to dest (or all reachable if dest is None)."""
        paths = []

        def dfs(current: str, path: list[str], visited: set[str]) -> None:
            if dest_id is not None and current == dest_id:
                paths.append(list(path))
                return
            if len(path) > max_depth:
                return
            for neighbor in self.adjacency.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    path.append(neighbor)
                    dfs(neighbor, path, visited)
                    path.pop()
                    visited.remove(neighbor)

        dfs(source_id, [source_id], {source_id})
        return paths

    def detect_cycles(self) -> list[list[str]]:
        """Detects cycles in the graph using DFS. Returns list of cycle paths."""
        visited = set()
        rec_stack = set()
        cycles = []

        def dfs(node: str, path: list[str]) -> None:
            visited.add(node)
            rec_stack.add(node)
            for neighbor in self.adjacency.get(node, []):
                if neighbor not in visited:
                    dfs(neighbor, path + [neighbor])
                elif neighbor in rec_stack:
                    cycle_start = path.index(neighbor) if neighbor in path else 0
                    cycles.append(path[cycle_start:] + [neighbor])
            rec_stack.discard(node)

        for node in self.adjacency:
            if node not in visited:
                dfs(node, [node])

        return cycles

