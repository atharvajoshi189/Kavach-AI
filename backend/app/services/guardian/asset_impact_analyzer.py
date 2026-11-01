"""Asset Impact Analyzer for Blue Guardian.

Resolves and categorizes asset exposure resulting from ThreatDetection records into:
- DIRECTLY_AFFECTED: Assets with confirmed telemetry or direct exploit targeting.
- POTENTIALLY_EXPOSED: Assets reachable via explicit network edges within blast radius.
- INFERRED_EXPOSURE: Assets sharing common service or administrative domains.

Preserves historical/archived assets and strictly respects sandbox isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
from typing import Any, Dict, List, Optional, Set
import uuid

from app.agents.blue_guardian.schemas import AssetImpactType
from app.models.guardian import CorrelatedEventGroup, DefensiveEventRecord, ThreatDetection
from app.models.synthetic_asset import SyntheticAsset
from app.services.guardian.blast_radius_analyzer import BlastRadiusAnalyzer, BlastRadiusResult

logger = logging.getLogger("aegismesh.guardian.impact_analyzer")


@dataclass(frozen=True)
class EvaluatedAssetImpact:
    """Structured impact specification for an asset evaluated in a threat detection."""
    asset_id: uuid.UUID
    impact_type: AssetImpactType
    impact_score: float
    traversal_depth: int
    relationship_path: List[str]
    impact_rationale: str
    evidence_references: Dict[str, Any]


class AssetImpactAnalyzer:
    """Analyzes direct and indirect asset impact for a ThreatDetection."""

    def __init__(self, blast_radius_analyzer: Optional[BlastRadiusAnalyzer] = None):
        self.blast_analyzer = blast_radius_analyzer or BlastRadiusAnalyzer(max_depth=3, max_nodes=25)

    def analyze_impact(
        self,
        detection: ThreatDetection,
        sandbox_assets_by_id: Dict[uuid.UUID, SyntheticAsset],
        adjacency_map: Dict[uuid.UUID, Set[uuid.UUID]],
        supporting_events: Optional[List[DefensiveEventRecord]] = None,
    ) -> List[EvaluatedAssetImpact]:
        """Resolves directly affected and downstream exposed assets for a detection.
        
        Guarantees that downstream connected assets are marked as POTENTIALLY_EXPOSED,
        never as confirmed compromised.
        """
        valid_sandbox_ids = set(sandbox_assets_by_id.keys())
        direct_asset_ids: Set[uuid.UUID] = set()

        # 1. Resolve directly affected assets from detection record
        for aid_str in (detection.affected_asset_ids or []):
            try:
                aid = uuid.UUID(str(aid_str))
                if aid in valid_sandbox_ids:
                    direct_asset_ids.add(aid)
            except ValueError:
                pass

        # 2. Corroborate with supporting defensive event records
        events = supporting_events or []
        for ev in events:
            if ev.source_asset_id and ev.source_asset_id in valid_sandbox_ids:
                direct_asset_ids.add(ev.source_asset_id)
            if ev.destination_asset_id and ev.destination_asset_id in valid_sandbox_ids:
                direct_asset_ids.add(ev.destination_asset_id)

        # 3. Execute bounded blast radius analysis for downstream exposure
        blast_result: BlastRadiusResult = self.blast_analyzer.analyze_blast_radius(
            root_asset_ids=direct_asset_ids,
            adjacency_map=adjacency_map,
            valid_sandbox_asset_ids=valid_sandbox_ids,
        )

        impacts: List[EvaluatedAssetImpact] = []

        # 4. Generate DIRECTLY_AFFECTED records (depth 0)
        for root_id in sorted(list(blast_result.root_asset_ids), key=lambda x: str(x)):
            asset = sandbox_assets_by_id.get(root_id)
            asset_name = asset.name if asset else str(root_id)
            is_archived = asset.status == "archived" if asset else False

            status_note = " (Historical/Archived)" if is_archived else ""
            rationale = (
                f"Directly targeted or observed as source/destination in telemetry "
                f"for rule '{detection.rule_code}' ({detection.title}){status_note}."
            )

            impacts.append(
                EvaluatedAssetImpact(
                    asset_id=root_id,
                    impact_type=AssetImpactType.DIRECTLY_AFFECTED,
                    impact_score=1.0,
                    traversal_depth=0,
                    relationship_path=[str(root_id)],
                    impact_rationale=rationale,
                    evidence_references={
                        "detection_code": detection.detection_code,
                        "rule_code": detection.rule_code,
                        "is_archived": is_archived,
                    },
                )
            )

        # 5. Generate POTENTIALLY_EXPOSED records (depth 1..max_depth)
        for exp_id, node in blast_result.downstream_nodes.items():
            if exp_id in blast_result.root_asset_ids:
                continue

            # Decay impact score by network hop distance
            depth_decay = max(0.1, round(1.0 - (node.depth * 0.25), 2))
            asset = sandbox_assets_by_id.get(exp_id)
            is_archived = asset.status == "archived" if asset else False

            impacts.append(
                EvaluatedAssetImpact(
                    asset_id=exp_id,
                    impact_type=AssetImpactType.POTENTIALLY_EXPOSED,
                    impact_score=depth_decay,
                    traversal_depth=node.depth,
                    relationship_path=node.path,
                    impact_rationale=node.exposure_reason,
                    evidence_references={
                        "detection_code": detection.detection_code,
                        "hops_from_root": node.depth,
                        "is_archived": is_archived,
                    },
                )
            )

        # 6. Fallback: If no direct assets could be resolved from metadata, infer sandbox scope
        if not impacts and valid_sandbox_ids:
            # First asset in sandbox receives inferred exposure
            fallback_id = sorted(list(valid_sandbox_ids), key=lambda x: str(x))[0]
            impacts.append(
                EvaluatedAssetImpact(
                    asset_id=fallback_id,
                    impact_type=AssetImpactType.INFERRED_EXPOSURE,
                    impact_score=0.20,
                    traversal_depth=0,
                    relationship_path=[str(fallback_id)],
                    impact_rationale="Inferred sandbox exposure based on target environment scoping.",
                    evidence_references={"detection_code": detection.detection_code, "inferred": True},
                )
            )

        return impacts

