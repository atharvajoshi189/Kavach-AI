"""Threat Detection Engine Service for Blue Guardian.

Consumes CorrelatedEventGroups and DefensiveEventRecords to evaluate deterministic
detection rules, mapping behaviors to MITRE ATT&CK techniques, evaluating severity
and confidence independently, and persisting structured ThreatDetection records.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.guardian import CorrelatedEventGroup, DefensiveEventRecord, GuardianExecution, ThreatDetection
from app.models.synthetic_asset import SyntheticAsset
from app.services.guardian.confidence_engine import ConfidenceEngine
from app.services.guardian.detection_rules import DetectionRuleRegistry
from app.services.guardian.severity_engine import SeverityEngine

logger = logging.getLogger("aegismesh.guardian.detection_engine")


class DetectionEngine:
    """Service evaluating forensic evidence against detection rules to generate threat detections."""

    def __init__(self, session: AsyncSession, registry: Optional[DetectionRuleRegistry] = None):
        self.session = session
        self.registry = registry or DetectionRuleRegistry()

    async def get_sandbox_assets_map(self, sandbox_id: uuid.UUID) -> Dict[str, Dict[str, Any]]:
        """Retrieves all assets for the sandbox, preserving historical/archived assets."""
        query = select(SyntheticAsset).where(SyntheticAsset.sandbox_id == sandbox_id)
        result = await self.session.execute(query)
        assets = result.scalars().all()
        return {
            str(a.id): {
                "id": str(a.id),
                "name": a.name,
                "asset_type": a.asset_type,
                "status": a.status,
                "criticality": getattr(a, "risk_level", "low") or "low",
            }
            for a in assets
        }

    async def run_detection_for_execution(
        self,
        execution: GuardianExecution,
        groups: Optional[List[CorrelatedEventGroup]] = None,
        events: Optional[List[DefensiveEventRecord]] = None,
    ) -> List[ThreatDetection]:
        """Runs the detection engine over an execution's correlated groups and events.
        
        Guarantees idempotency and non-destructive retention.
        """
        sandbox_id = execution.sandbox_id
        execution_id = execution.id

        # 1. Load groups if not supplied
        if groups is None:
            g_query = (
                select(CorrelatedEventGroup)
                .where(CorrelatedEventGroup.guardian_execution_id == execution_id)
                .order_by(CorrelatedEventGroup.earliest_event_timestamp)
            )
            groups = list((await self.session.execute(g_query)).scalars().all())

        # 2. Load events if not supplied
        if events is None:
            e_query = (
                select(DefensiveEventRecord)
                .where(DefensiveEventRecord.guardian_execution_id == execution_id)
                .order_by(DefensiveEventRecord.original_timestamp, DefensiveEventRecord.source_event_id)
            )
            events = list((await self.session.execute(e_query)).scalars().all())

        # Build lookup map of events by source_event_id
        events_by_source_id: Dict[str, DefensiveEventRecord] = {
            ev.source_event_id: ev for ev in events
        }

        # Retrieve sandbox asset profiles
        assets_map = await self.get_sandbox_assets_map(sandbox_id)

        # Retrieve existing detections to guarantee idempotency on retry
        existing_det_query = select(
            ThreatDetection.rule_code,
            ThreatDetection.correlated_group_id,
        ).where(ThreatDetection.guardian_execution_id == execution_id)
        existing_res = await self.session.execute(existing_det_query)
        existing_signatures: set[tuple[str, uuid.UUID]] = {
            (r[0], r[1]) for r in existing_res.all()
        }

        persisted_detections: List[ThreatDetection] = []
        rules = self.registry.get_all_rules()

        for group in groups:
            # Resolve member events for this group
            member_ids = group.member_event_ids or []
            member_events = [
                events_by_source_id[sid]
                for sid in member_ids
                if sid in events_by_source_id
            ]

            # If member_events is empty but events exist, use all events matching stage
            if not member_events and events:
                member_events = [
                    ev for ev in events
                    if ev.event_type and any(k in ev.event_type.lower() for k in group.stage.lower().split("_"))
                ]

            for rule in rules:
                if not rule.enabled:
                    continue

                # Idempotency check: skip if detection already exists for this (rule, group)
                if (rule.rule_code, group.id) in existing_signatures:
                    logger.debug("Detection for rule %s and group %s already exists, skipping", rule.rule_code, group.id)
                    continue

                eval_result = rule.evaluate(group, member_events)
                if not eval_result or not eval_result.matched:
                    continue

                # Resolve affected asset objects
                affected_asset_objs = [
                    assets_map[aid]
                    for aid in eval_result.affected_asset_ids
                    if aid in assets_map
                ]

                # Independent Severity Evaluation
                final_severity, sev_rationale = SeverityEngine.evaluate_severity(
                    base_severity=eval_result.base_severity,
                    affected_assets=affected_asset_objs,
                    is_compromised=eval_result.is_compromised,
                    multi_host_scope=eval_result.multi_host_scope,
                )

                # Independent Confidence Evaluation
                final_confidence, conf_rationale = ConfidenceEngine.evaluate_confidence(
                    base_confidence=eval_result.base_confidence,
                    event_count=len(member_events),
                    min_required_events=rule.min_event_count,
                    correlation_confidence=group.correlation_confidence,
                    correlation_basis=group.correlation_basis,
                    has_rich_payload=eval_result.has_rich_payload,
                    asset_resolution_verified=len(affected_asset_objs) > 0,
                )

                # Deterministic detection code
                det_code = f"DET-{rule.rule_code}-{group.id.hex[:8]}"

                full_rationale = (
                    f"{eval_result.detection_rationale} "
                    f"[Severity Rationale: {sev_rationale}] "
                    f"[Confidence Rationale: {conf_rationale}]"
                )

                detection = ThreatDetection(
                    guardian_execution_id=execution_id,
                    correlated_group_id=group.id,
                    sandbox_id=sandbox_id,
                    detection_code=det_code,
                    rule_code=rule.rule_code,
                    rule_version=rule.rule_version,
                    title=eval_result.title,
                    description=eval_result.description,
                    classification=eval_result.classification,
                    severity=final_severity,
                    confidence_score=final_confidence,
                    mitre_techniques=eval_result.mitre_techniques,
                    mitre_tactics=eval_result.mitre_tactics,
                    affected_asset_ids=eval_result.affected_asset_ids,
                    evidence_references=eval_result.evidence_references,
                    detection_rationale=full_rationale,
                    status="new",
                    is_simulated=True,
                    simulation_only=True,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )

                self.session.add(detection)
                persisted_detections.append(detection)
                existing_signatures.add((rule.rule_code, group.id))

        await self.session.flush()

        # Load all detections for this execution to return full state
        all_detections_query = (
            select(ThreatDetection)
            .where(ThreatDetection.guardian_execution_id == execution_id)
            .order_by(ThreatDetection.created_at, ThreatDetection.detection_code)
        )
        return list((await self.session.execute(all_detections_query)).scalars().all())

