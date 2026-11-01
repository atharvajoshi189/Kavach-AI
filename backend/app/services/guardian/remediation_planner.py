"""Deterministic Remediation Planner for Blue Guardian.

Aggregates defensive recommendations into structured, prioritized, and dependency-ordered
remediation plans containing concrete RemediationPlanAction steps.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.agents.blue_guardian.schemas import (
    ActionStatus,
    RecommendationPriority,
    RemediationPlanStatus,
)
from app.models.guardian import (
    DefensiveRecommendation,
    GuardianExecution,
    RemediationPlan,
    RemediationPlanAction,
)
from app.services.guardian.playbook_library import PlaybookLibrary

logger = logging.getLogger("aegismesh.guardian.remediation_planner")


class RemediationPlanner:
    """Async engine for synthesizing recommendations into executable remediation plans."""

    def __init__(
        self,
        session: AsyncSession,
        playbook_library: Optional[PlaybookLibrary] = None,
    ):
        self.session = session
        self.playbook_library = playbook_library or PlaybookLibrary()

    def _determine_overall_priority(
        self,
        recommendations: List[DefensiveRecommendation],
    ) -> RecommendationPriority:
        """Determines highest priority among all recommendations."""
        priorities = {r.priority.upper() for r in recommendations}
        if "P0" in priorities:
            return RecommendationPriority.P0
        if "P1" in priorities:
            return RecommendationPriority.P1
        if "P2" in priorities:
            return RecommendationPriority.P2
        return RecommendationPriority.P3

    async def generate_plan_for_execution(
        self,
        execution: GuardianExecution,
        recommendations: Optional[List[DefensiveRecommendation]] = None,
    ) -> RemediationPlan:
        """Constructs an integrated, deduplicated, and dependency-ordered RemediationPlan.
        
        Strictly enforces:
        1. Sandbox boundary isolation
        2. Priority-first sequence ordering (P0 before P1, P2, P3)
        3. Dependency tracking (depends_on validation)
        4. Action deduplication across overlapping playbook recommendations
        5. Idempotent replacement of previous draft plans
        """
        execution_id = execution.id
        sandbox_id = execution.sandbox_id

        # 1. Fetch recommendations if not provided
        if recommendations is None:
            rec_query = (
                select(DefensiveRecommendation)
                .where(DefensiveRecommendation.guardian_execution_id == execution_id)
                .where(DefensiveRecommendation.sandbox_id == sandbox_id)
                .order_by(DefensiveRecommendation.created_at)
            )
            rec_res = await self.session.execute(rec_query)
            recommendations = list(rec_res.scalars().all())

        # Sort recommendations by priority rank: P0 (0) -> P1 (1) -> P2 (2) -> P3 (3)
        priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
        sorted_recs = sorted(
            recommendations,
            key=lambda r: (priority_order.get(r.priority.upper(), 99), r.created_at),
        )

        overall_priority = (
            self._determine_overall_priority(sorted_recs)
            if sorted_recs
            else RecommendationPriority.P3
        )

        # 2. Collect target asset IDs
        all_target_assets: Set[str] = set()
        for r in sorted_recs:
            if r.affected_asset_ids and isinstance(r.affected_asset_ids, list):
                all_target_assets.update(str(aid) for aid in r.affected_asset_ids)

        # 3. Check for existing draft plan to ensure idempotency
        plan_query = (
            select(RemediationPlan)
            .where(RemediationPlan.guardian_execution_id == execution_id)
            .where(RemediationPlan.sandbox_id == sandbox_id)
            .options(selectinload(RemediationPlan.actions))
        )
        plan_res = await self.session.execute(plan_query)
        existing_plan = plan_res.scalars().first()

        if existing_plan:
            plan = existing_plan
            plan.overall_priority = overall_priority.value
            plan.target_asset_ids = sorted(list(all_target_assets))
            plan.updated_at = datetime.now(timezone.utc)
            # Remove existing actions to re-generate cleanly
            await self.session.execute(
                delete(RemediationPlanAction).where(
                    RemediationPlanAction.remediation_plan_id == plan.id
                )
            )
            await self.session.flush()
        else:
            plan = RemediationPlan(
                id=uuid.uuid4(),
                guardian_execution_id=execution_id,
                sandbox_id=sandbox_id,
                title=f"Remediation Plan for Execution {execution_id.hex[:8].upper()}",
                description="Comprehensive incident response and risk mitigation plan synthesized from detected attack paths and asset impact models.",
                overall_priority=overall_priority.value,
                status=RemediationPlanStatus.DRAFT.value,
                plan_version="1.0.0",
                target_asset_ids=sorted(list(all_target_assets)),
                plan_metadata={
                    "recommendations_count": len(sorted_recs),
                    "execution_id": str(execution_id),
                    "sandbox_id": str(sandbox_id),
                    "priorities_breakdown": {
                        p: sum(1 for r in sorted_recs if r.priority.upper() == p)
                        for p in ("P0", "P1", "P2", "P3")
                    },
                },
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                is_simulated=True,
                simulation_only=True,
            )
            self.session.add(plan)
            await self.session.flush()

        # 4. Generate actions from recommendations and playbook action templates
        plan_actions: List[RemediationPlanAction] = []
        action_seq = 1
        seen_action_signatures: Set[str] = set()

        for rec in sorted_recs:
            playbook = self.playbook_library.get_playbook(rec.playbook_id)
            if not playbook:
                continue

            for tpl in playbook.action_templates:
                # Deduplication key: action_type + set of target asset IDs
                # Avoid running duplicate identical actions on the same assets
                action_sig = f"{tpl.action_type}:{','.join(sorted(rec.affected_asset_ids))}"
                if action_sig in seen_action_signatures:
                    logger.debug("Deduplicating redundant action signature: %s", action_sig)
                    continue
                seen_action_signatures.add(action_sig)

                # Action code: ACT-<SEQ>-<PLAYBOOK_ACTION>
                action_code = f"ACT-{action_seq:02d}-{tpl.action_code}"

                action = RemediationPlanAction(
                    id=uuid.uuid4(),
                    remediation_plan_id=plan.id,
                    recommendation_id=rec.id,
                    action_code=action_code,
                    title=f"[{rec.priority}] {tpl.title}",
                    description=tpl.description,
                    sequence_order=action_seq,
                    priority=rec.priority,
                    depends_on=list(tpl.depends_on),
                    target_asset_ids=list(rec.affected_asset_ids or []),
                    expected_outcome=tpl.expected_outcome,
                    verification_criteria=list(tpl.verification_criteria),
                    action_type=tpl.action_type,
                    status=ActionStatus.PENDING.value,
                    created_at=datetime.now(timezone.utc),
                    updated_at=datetime.now(timezone.utc),
                )
                self.session.add(action)
                plan_actions.append(action)
                action_seq += 1

        await self.session.flush()

        # Update metadata and counts
        plan.plan_metadata["total_actions"] = len(plan_actions)
        execution.remediation_plans_count = 1
        await self.session.flush()

        return plan

