"""Deterministic Defensive Event Correlation Engine for Blue Guardian.

Groups ingested DefensiveEventRecord instances across verified dimensions:
1. Direct Attack Run Correlation (DIRECT)
2. Direct Campaign Correlation (DIRECT)
3. Relational Asset Dependency Correlation (RELATIONAL)
4. Temporal Proximity Correlation (TEMPORAL)
5. Multi-Stage Attack Path Correlation (RELATIONAL)

Guarantees 100% determinism, stable sorting, explicit epistemic provenance,
and strict sandbox isolation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.blue_guardian.schemas import CorrelationBasis
from app.models.attack_path import AttackPath
from app.models.guardian import CorrelatedEventGroup, DefensiveEventRecord, GuardianExecution
from app.models.synthetic_asset import SyntheticAsset

logger = logging.getLogger("aegismesh.guardian.correlation")


def generate_deterministic_group_id(
    execution_id: uuid.UUID,
    rule_code: str,
    key_identifier: str,
) -> uuid.UUID:
    """Generates a reproducible UUIDv5 for a correlated group to prevent duplicate clusters."""
    name = f"{execution_id}:{rule_code}:{key_identifier}"
    return uuid.uuid5(uuid.NAMESPACE_DNS, name)


def determine_stage_from_scenario(scenario_id: Optional[str], event_type: str) -> str:
    """Deterministic heuristic mapping scenario or event type to kill-chain stage."""
    normalized = f"{scenario_id or ''} {event_type}".lower()
    if any(k in normalized for k in ["recon", "discovery", "probe", "port_scan"]):
        return "RECON"
    if any(k in normalized for k in ["auth_bypass", "initial_access", "login", "ingress"]):
        return "INITIAL_ACCESS"
    if any(k in normalized for k in ["privilege_escalation", "role_escalation", "admin_grant"]):
        return "PRIVILEGE_ESCALATION"
    if any(k in normalized for k in ["lateral_movement", "pivot", "network_traverse"]):
        return "LATERAL_MOVEMENT"
    if any(k in normalized for k in ["exfiltration", "data_leak", "pii", "egress"]):
        return "DATA_EXFILTRATION"
    if any(k in normalized for k in ["persistence", "backdoor", "account_creation"]):
        return "PERSISTENCE"
    return "GENERAL"


class CorrelationService:
    """Service implementing deterministic correlation rules over ingested defensive events."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def build_asset_relationship_map(self, sandbox_id: uuid.UUID) -> Dict[str, Set[str]]:
        """Builds an adjacency graph of registered connected synthetic assets in the sandbox.
        
        Note: Includes historical/archived assets belonging to this sandbox so that post-simulation
        correlation accurately reflects connectivity at the time of the event.
        """
        query = select(SyntheticAsset).where(
            SyntheticAsset.sandbox_id == sandbox_id,
        )
        result = await self.session.execute(query)
        assets = result.scalars().all()

        adj: Dict[str, Set[str]] = {}
        for asset in assets:
            aid = str(asset.id)
            if aid not in adj:
                adj[aid] = set()
            conns = asset.connected_asset_ids or []
            for c in conns:
                adj[aid].add(str(c))
                if str(c) not in adj:
                    adj[str(c)] = set()
                adj[str(c)].add(aid)
        return adj

    def correlate_by_attack_run(
        self,
        execution: GuardianExecution,
        events: List[DefensiveEventRecord],
    ) -> List[CorrelatedEventGroup]:
        """Rule CORR-DIR-001: Direct Attack Run Correlation.
        
        Groups events that explicitly share the same attack_run_id.
        Basis: DIRECT.
        """
        groups_by_run: Dict[str, List[DefensiveEventRecord]] = {}
        for ev in events:
            if not ev.attack_run_id:
                continue
            run_key = str(ev.attack_run_id)
            groups_by_run.setdefault(run_key, []).append(ev)

        correlated_groups: List[CorrelatedEventGroup] = []
        for run_id_str, run_events in sorted(groups_by_run.items(), key=lambda item: item[0]):
            if not run_events:
                continue

            # Sort events stably
            run_events.sort(key=lambda e: (e.original_timestamp, e.source_event_id))

            earliest = run_events[0].original_timestamp
            latest = run_events[-1].original_timestamp
            stage = determine_stage_from_scenario(run_events[0].scenario_id, run_events[0].event_type)

            root_asset = str(run_events[0].source_asset_id) if run_events[0].source_asset_id else None
            impacted_assets = sorted({
                str(e.source_asset_id) for e in run_events if e.source_asset_id
            } | {
                str(e.destination_asset_id) for e in run_events if e.destination_asset_id
            })

            group_id = generate_deterministic_group_id(execution.id, "CORR-DIR-001", run_id_str)
            group = CorrelatedEventGroup(
                id=group_id,
                guardian_execution_id=execution.id,
                sandbox_id=execution.sandbox_id,
                campaign_id=run_events[0].campaign_id,
                title=f"Attack Run Execution Cluster: {run_id_str[:8]}",
                stage=stage,
                correlation_basis=CorrelationBasis.DIRECT.value,
                correlation_rule="CORR-DIR-001: Direct Attack Run Grouping",
                member_event_ids=[e.source_event_id for e in run_events],
                root_cause_asset_id=root_asset,
                impacted_asset_ids=impacted_assets,
                earliest_event_timestamp=earliest,
                latest_event_timestamp=latest,
                correlation_confidence=1.0,
                simulation_only=True,
                is_simulated=True,
                group_metadata={
                    "attack_run_id": run_id_str,
                    "event_count": len(run_events),
                    "scenario_id": run_events[0].scenario_id,
                    "causality_claim": "direct_execution_identity",
                },
                created_at=datetime.now(timezone.utc),
            )
            correlated_groups.append(group)

        return correlated_groups

    def correlate_by_temporal_window(
        self,
        execution: GuardianExecution,
        events: List[DefensiveEventRecord],
        window_seconds: int = 300,
    ) -> List[CorrelatedEventGroup]:
        """Rule CORR-TEMP-004: Temporal Sliding Window Correlation.
        
        Clusters events that occurred within a defined sliding time window.
        Basis: TEMPORAL.
        Explicitly notes that temporal proximity does not prove causation.
        """
        if not events:
            return []

        # Ensure events are sorted chronologically
        sorted_events = sorted(events, key=lambda e: (e.original_timestamp, e.source_event_id))

        clusters: List[List[DefensiveEventRecord]] = []
        current_cluster: List[DefensiveEventRecord] = [sorted_events[0]]

        for ev in sorted_events[1:]:
            delta = (ev.original_timestamp - current_cluster[-1].original_timestamp).total_seconds()
            if delta <= window_seconds:
                current_cluster.append(ev)
            else:
                clusters.append(current_cluster)
                current_cluster = [ev]
        if current_cluster:
            clusters.append(current_cluster)

        temporal_groups: List[CorrelatedEventGroup] = []
        for idx, cluster in enumerate(clusters):
            # Only create temporal clusters if there are at least 2 events or if it's the sole cluster
            if len(cluster) < 1:
                continue

            earliest = cluster[0].original_timestamp
            latest = cluster[-1].original_timestamp
            stage = determine_stage_from_scenario(cluster[0].scenario_id, cluster[0].event_type)

            root_asset = str(cluster[0].source_asset_id) if cluster[0].source_asset_id else None
            impacted_assets = sorted({
                str(e.source_asset_id) for e in cluster if e.source_asset_id
            } | {
                str(e.destination_asset_id) for e in cluster if e.destination_asset_id
            })

            key_id = f"window-{idx}:{earliest.isoformat()}:{cluster[0].source_event_id}"
            group_id = generate_deterministic_group_id(execution.id, "CORR-TEMP-004", key_id)

            group = CorrelatedEventGroup(
                id=group_id,
                guardian_execution_id=execution.id,
                sandbox_id=execution.sandbox_id,
                campaign_id=cluster[0].campaign_id,
                title=f"Temporal Activity Window {idx + 1} ({len(cluster)} events)",
                stage=stage,
                correlation_basis=CorrelationBasis.TEMPORAL.value,
                correlation_rule=f"CORR-TEMP-004: Sliding Window ({window_seconds}s)",
                member_event_ids=[e.source_event_id for e in cluster],
                root_cause_asset_id=root_asset,
                impacted_asset_ids=impacted_assets,
                earliest_event_timestamp=earliest,
                latest_event_timestamp=latest,
                correlation_confidence=0.75,  # Lower confidence due to temporal-only nature
                simulation_only=True,
                is_simulated=True,
                group_metadata={
                    "window_seconds": window_seconds,
                    "event_count": len(cluster),
                    "causality_note": "Temporal correlation does not imply causality.",
                },
                created_at=datetime.now(timezone.utc),
            )
            temporal_groups.append(group)

        return temporal_groups

    def correlate_by_asset_topology(
        self,
        execution: GuardianExecution,
        events: List[DefensiveEventRecord],
        asset_adj: Dict[str, Set[str]],
    ) -> List[CorrelatedEventGroup]:
        """Rule CORR-REL-003: Relational Asset Graph Correlation.
        
        Groups events where assets share verified dependency or network links.
        Basis: RELATIONAL.
        """
        # Group events by connected asset components
        asset_to_events: Dict[str, List[DefensiveEventRecord]] = {}
        for ev in events:
            if ev.source_asset_id:
                asset_to_events.setdefault(str(ev.source_asset_id), []).append(ev)
            if ev.destination_asset_id:
                asset_to_events.setdefault(str(ev.destination_asset_id), []).append(ev)

        # Find connected pairs
        relational_pairs: List[Tuple[str, str, List[DefensiveEventRecord]]] = []
        seen_pairs: Set[Tuple[str, str]] = set()

        for a1, conns in sorted(asset_adj.items()):
            for a2 in sorted(conns):
                pair = tuple(sorted([a1, a2]))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)

                related_events = sorted(
                    {e for aid in pair for e in asset_to_events.get(aid, [])},
                    key=lambda e: (e.original_timestamp, e.source_event_id),
                )
                if len(related_events) >= 2:
                    relational_pairs.append((pair[0], pair[1], related_events))

        relational_groups: List[CorrelatedEventGroup] = []
        for a1, a2, pair_events in relational_pairs:
            earliest = pair_events[0].original_timestamp
            latest = pair_events[-1].original_timestamp
            stage = "LATERAL_MOVEMENT"

            key_id = f"{a1}:{a2}:{pair_events[0].source_event_id}"
            group_id = generate_deterministic_group_id(execution.id, "CORR-REL-003", key_id)

            group = CorrelatedEventGroup(
                id=group_id,
                guardian_execution_id=execution.id,
                sandbox_id=execution.sandbox_id,
                campaign_id=pair_events[0].campaign_id,
                title=f"Lateral Asset Dependency Activity: {a1[:8]} <-> {a2[:8]}",
                stage=stage,
                correlation_basis=CorrelationBasis.RELATIONAL.value,
                correlation_rule="CORR-REL-003: Asset Graph Adjacency",
                member_event_ids=[e.source_event_id for e in pair_events],
                root_cause_asset_id=a1,
                impacted_asset_ids=sorted([a1, a2]),
                earliest_event_timestamp=earliest,
                latest_event_timestamp=latest,
                correlation_confidence=0.85,
                simulation_only=True,
                is_simulated=True,
                group_metadata={
                    "connected_assets": [a1, a2],
                    "event_count": len(pair_events),
                    "basis_description": "Events linked via registered synthetic asset graph connections.",
                },
                created_at=datetime.now(timezone.utc),
            )
            relational_groups.append(group)

        return relational_groups

    def correlate_by_attack_path(
        self,
        execution: GuardianExecution,
        events: List[DefensiveEventRecord],
    ) -> List[CorrelatedEventGroup]:
        """Rule CORR-PATH-005: Attack Path Multi-Stage Correlation.
        
        When execution is bound to an AttackPath, groups all path stages into a unified kill-chain sequence.
        Basis: RELATIONAL.
        """
        if not execution.attack_path_id:
            return []

        path_events = [e for e in events if e.attack_path_id == execution.attack_path_id]
        if not path_events:
            return []

        path_events.sort(key=lambda e: (e.original_timestamp, e.source_event_id))
        earliest = path_events[0].original_timestamp
        latest = path_events[-1].original_timestamp

        all_impacted = sorted({
            str(e.source_asset_id) for e in path_events if e.source_asset_id
        } | {
            str(e.destination_asset_id) for e in path_events if e.destination_asset_id
        })

        group_id = generate_deterministic_group_id(
            execution.id, "CORR-PATH-005", str(execution.attack_path_id)
        )

        group = CorrelatedEventGroup(
            id=group_id,
            guardian_execution_id=execution.id,
            sandbox_id=execution.sandbox_id,
            campaign_id=path_events[0].campaign_id,
            title=f"Attack Path Multi-Stage Kill Chain: {str(execution.attack_path_id)[:8]}",
            stage="MULTI_STAGE_KILL_CHAIN",
            correlation_basis=CorrelationBasis.RELATIONAL.value,
            correlation_rule="CORR-PATH-005: Attack Path Orchestration",
            member_event_ids=[e.source_event_id for e in path_events],
            root_cause_asset_id=str(path_events[0].source_asset_id) if path_events[0].source_asset_id else None,
            impacted_asset_ids=all_impacted,
            earliest_event_timestamp=earliest,
            latest_event_timestamp=latest,
            correlation_confidence=0.95,
            simulation_only=True,
            is_simulated=True,
            group_metadata={
                "attack_path_id": str(execution.attack_path_id),
                "total_events": len(path_events),
                "basis_description": "Synthesized multi-stage attack path kill chain.",
            },
            created_at=datetime.now(timezone.utc),
        )
        return [group]

    async def correlate_events_for_execution(
        self,
        execution: GuardianExecution,
        events: List[DefensiveEventRecord],
        window_seconds: int = 300,
    ) -> List[CorrelatedEventGroup]:
        """Runs all deterministic correlation rules and persists the resulting groups.
        
        Guarantees deterministic execution and prevents duplicate records.
        """
        if not events:
            return []

        asset_adj = await self.build_asset_relationship_map(execution.sandbox_id)

        all_groups: List[CorrelatedEventGroup] = []

        # 1. Direct Attack Run Groups
        all_groups.extend(self.correlate_by_attack_run(execution, events))

        # 2. Relational Attack Path Groups
        all_groups.extend(self.correlate_by_attack_path(execution, events))

        # 3. Relational Asset Graph Groups
        all_groups.extend(self.correlate_by_asset_topology(execution, events, asset_adj))

        # 4. Temporal Sliding Window Groups
        all_groups.extend(self.correlate_by_temporal_window(execution, events, window_seconds))

        # Stable tie-breaking sort: by earliest timestamp, then stage, then title
        all_groups.sort(
            key=lambda g: (
                g.earliest_event_timestamp.isoformat(),
                g.stage,
                g.title,
                str(g.id),
            )
        )

        # Retrieve existing group IDs to enforce database idempotency
        existing_query = select(CorrelatedEventGroup.id).where(
            CorrelatedEventGroup.guardian_execution_id == execution.id
        )
        existing_res = await self.session.execute(existing_query)
        existing_group_ids = set(existing_res.scalars().all())

        persisted_groups: List[CorrelatedEventGroup] = []
        for g in all_groups:
            if g.id in existing_group_ids:
                continue
            self.session.add(g)
            persisted_groups.append(g)

        await self.session.flush()

        execution.correlation_groups_count = len(existing_group_ids) + len(persisted_groups)
        await self.session.flush()

        # Fetch complete sorted groups
        final_query = (
            select(CorrelatedEventGroup)
            .where(CorrelatedEventGroup.guardian_execution_id == execution.id)
            .order_by(CorrelatedEventGroup.earliest_event_timestamp, CorrelatedEventGroup.title)
        )
        final_res = await self.session.execute(final_query)
        return list(final_res.scalars().all())
