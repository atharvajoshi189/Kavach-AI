"""Synthetic Regression Verification Engine evaluating post-remediation security state."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.blue_guardian.approval_schemas import (
    RemediationVerificationResponse,
    RemediationVerificationSummaryResponse,
    VerificationStatus,
)
from app.models.guardian import (
    RemediationPlan,
    RemediationPlanAction,
    RemediationVerification,
    SyntheticRemediationExecution,
    SyntheticStateSnapshot,
)
from app.services.audit_service import record_audit_log

logger = logging.getLogger("aegismesh.guardian.verification_engine")


class RegressionVerificationEngine:
    """Evaluates evidence-backed regression verification checks against pre/post snapshots."""

    def __init__(self, session: AsyncSession):
        self.session = session

    @classmethod
    def verification_to_response(cls, v: RemediationVerification) -> RemediationVerificationResponse:
        return RemediationVerificationResponse(
            id=v.id,
            execution_id=v.execution_id,
            remediation_plan_action_id=v.remediation_plan_action_id,
            sandbox_id=v.sandbox_id,
            verification_status=v.verification_status,
            expected_condition=v.expected_condition,
            actual_condition=v.actual_condition,
            before_value=v.before_value,
            after_value=v.after_value,
            evidence_references=v.evidence_references,
            failure_reason=v.failure_reason,
            verified_at=v.verified_at,
        )

    async def verify_execution(
        self,
        execution: SyntheticRemediationExecution,
        plan: RemediationPlan,
        actions: List[RemediationPlanAction],
        before_snapshot: SyntheticStateSnapshot,
        after_snapshot: Optional[SyntheticStateSnapshot],
        actor_id: Optional[uuid.UUID] = None,
    ) -> RemediationVerificationSummaryResponse:
        """Runs deterministic verification checks across all actions in the plan."""
        now = datetime.now(timezone.utc)
        verifications: List[RemediationVerification] = []

        before_assets = {
            a["asset_id"]: a for a in before_snapshot.snapshot_data.get("assets", [])
        }
        after_assets = {
            a["asset_id"]: a for a in (after_snapshot.snapshot_data.get("assets", []) if after_snapshot else [])
        }

        passed_count = 0
        failed_count = 0
        inconclusive_count = 0

        for action in actions:
            if not after_snapshot:
                # Without an after snapshot, all checks are inconclusive/failed
                v_record = RemediationVerification(
                    id=uuid.uuid4(),
                    execution_id=execution.id,
                    remediation_plan_action_id=action.id,
                    sandbox_id=execution.sandbox_id,
                    verification_status=VerificationStatus.INCONCLUSIVE.value,
                    expected_condition=action.expected_outcome,
                    actual_condition="Post-remediation state snapshot unavailable.",
                    before_value={"captured": True},
                    after_value={"captured": False},
                    evidence_references={"before_snapshot_id": str(before_snapshot.id)},
                    failure_reason="Post-execution snapshot missing or execution aborted.",
                    verified_at=now,
                )
                self.session.add(v_record)
                verifications.append(v_record)
                inconclusive_count += 1
                continue

            # Target assets for this action
            target_ids = action.target_asset_ids or []
            if not target_ids:
                # If no specific target assets, evaluate all assets in snapshot
                target_ids = list(after_assets.keys())

            action_passed = True
            action_evaluations: List[Dict[str, Any]] = []
            failure_reasons: List[str] = []

            for aid in target_ids:
                pre = before_assets.get(aid, {})
                post = after_assets.get(aid, {})

                if not post:
                    action_passed = False
                    failure_reasons.append(f"Asset '{aid}' not found in post-execution snapshot.")
                    continue

                pre_cfg = pre.get("configuration", {})
                post_cfg = post.get("configuration", {})

                # Deterministic check based on action type or criteria
                asset_passed, reason, expected, actual = self._evaluate_action_criteria(
                    action=action,
                    pre_cfg=pre_cfg,
                    post_cfg=post_cfg,
                    pre_asset=pre,
                    post_asset=post,
                )
                if not asset_passed:
                    action_passed = False
                    failure_reasons.append(f"Asset '{aid}': {reason}")

                action_evaluations.append({
                    "asset_id": aid,
                    "passed": asset_passed,
                    "expected": expected,
                    "actual": actual,
                })

            v_status = VerificationStatus.PASSED.value if action_passed else VerificationStatus.FAILED.value
            if action_passed:
                passed_count += 1
            else:
                failed_count += 1

            v_record = RemediationVerification(
                id=uuid.uuid4(),
                execution_id=execution.id,
                remediation_plan_action_id=action.id,
                sandbox_id=execution.sandbox_id,
                verification_status=v_status,
                expected_condition=action.expected_outcome,
                actual_condition="All target assets satisfied verification criteria." if action_passed else "; ".join(failure_reasons),
                before_value={"evaluations": len(action_evaluations)},
                after_value={"evaluations": action_evaluations},
                evidence_references={
                    "before_snapshot_id": str(before_snapshot.id),
                    "after_snapshot_id": str(after_snapshot.id),
                    "action_code": action.action_code,
                    "verification_criteria": action.verification_criteria,
                },
                failure_reason="; ".join(failure_reasons) if failure_reasons else None,
                verified_at=now,
            )
            self.session.add(v_record)
            verifications.append(v_record)

        await self.session.flush()

        # Determine overall summary status
        total_checks = len(actions)
        if passed_count == total_checks and total_checks > 0:
            overall_status = VerificationStatus.PASSED.value
            audit_event = "guardian.verification.completed"
        elif passed_count > 0:
            overall_status = VerificationStatus.PARTIALLY_PASSED.value
            audit_event = "guardian.verification.failed"
        elif inconclusive_count > 0:
            overall_status = VerificationStatus.INCONCLUSIVE.value
            audit_event = "guardian.verification.failed"
        else:
            overall_status = VerificationStatus.FAILED.value
            audit_event = "guardian.verification.failed"

        # Record Audit Event
        try:
            await record_audit_log(
                session=self.session,
                event_type=audit_event,
                action="guardian.verification",
                resource_type="remediation_execution",
                actor_id=actor_id,
                resource_id=str(execution.id),
                decision=overall_status,
                event_data={
                    "execution_id": str(execution.id),
                    "remediation_plan_id": str(plan.id),
                    "overall_status": overall_status,
                    "total_checks": total_checks,
                    "passed_checks": passed_count,
                    "failed_checks": failed_count,
                    "inconclusive_checks": inconclusive_count,
                },
            )
            await self.session.flush()
        except Exception as e:
            logger.warning("Audit log recording failed for verification: %s", e)

        return RemediationVerificationSummaryResponse(
            execution_id=execution.id,
            remediation_plan_id=plan.id,
            sandbox_id=execution.sandbox_id,
            overall_status=overall_status,
            total_checks=total_checks,
            passed_checks=passed_count,
            failed_checks=failed_count,
            inconclusive_checks=inconclusive_count,
            verifications=[self.verification_to_response(v) for v in verifications],
        )

    def _evaluate_action_criteria(
        self,
        action: RemediationPlanAction,
        pre_cfg: Dict[str, Any],
        post_cfg: Dict[str, Any],
        pre_asset: Dict[str, Any],
        post_asset: Dict[str, Any],
    ) -> tuple[bool, str, str, str]:
        """Evaluates specific expected security configuration against observed post-state."""
        code = action.action_code.upper()
        act_type = action.action_type.lower()

        # Session Revocation
        if "001-01" in code or "session" in act_type:
            actual = str(post_cfg.get("active_bearer_tokens_valid"))
            if post_cfg.get("active_bearer_tokens_valid") is False or post_cfg.get("active_sessions_revoked_at"):
                return True, "Active identity sessions revoked", "active_bearer_tokens_valid=False", actual
            return False, "Active sessions not revoked", "active_bearer_tokens_valid=False", actual

        # Credential Reset & MFA
        if "001-02" in code or "credential" in act_type or "mfa" in act_type:
            actual = f"mfa={post_cfg.get('mfa_enforced')}"
            if post_cfg.get("mfa_enforced") is True or post_cfg.get("credential_rotation"):
                return True, "MFA enforced and credentials rotated", "mfa_enforced=True", actual
            return False, "MFA not enforced", "mfa_enforced=True", actual

        # Rate Limiting
        if "002-01" in code or "rate" in act_type:
            rl = post_cfg.get("rate_limiting", {})
            actual = f"rate_limiting.enabled={rl.get('enabled')}"
            if rl.get("enabled") is True:
                return True, "Rate limiting enabled", "rate_limiting.enabled=True", actual
            return False, "Rate limiting not configured", "rate_limiting.enabled=True", actual

        # Application Isolation
        if "002-02" in code or "isolation" in act_type:
            actual = f"isolated_mode={post_cfg.get('isolated_mode')}"
            if post_cfg.get("isolated_mode") is True:
                return True, "Application isolated", "isolated_mode=True", actual
            return False, "Application isolation not verified", "isolated_mode=True", actual

        # Privilege Restriction
        if "003-01" in code or "privilege" in act_type or "sudo" in act_type:
            actual = f"least_privilege={post_cfg.get('least_privilege_enforced')}"
            if post_cfg.get("least_privilege_enforced") is True:
                return True, "Least privilege policy applied", "least_privilege_enforced=True", actual
            return False, "Least privilege not enforced", "least_privilege_enforced=True", actual

        # Network Segmentation
        if "004-01" in code or "segmentation" in act_type or "firewall" in act_type:
            seg = post_cfg.get("network_segmentation", {})
            actual = f"segmented={seg.get('segmented')}"
            if seg.get("segmented") is True:
                return True, "Micro-segmentation active", "segmented=True", actual
            return False, "Network segmentation not applied", "segmented=True", actual

        # Persistence Removal
        if "005-01" in code or "persistence" in act_type or "cron" in act_type:
            actual = f"persistence_removed={post_cfg.get('persistence_artifacts_removed')}"
            if post_cfg.get("persistence_artifacts_removed") is True:
                return True, "Persistence artifacts removed", "persistence_artifacts_removed=True", actual
            return False, "Persistence artifacts remain", "persistence_artifacts_removed=True", actual

        # Egress Restriction
        if "006-01" in code or "egress" in act_type or "dlp" in act_type:
            egress = post_cfg.get("egress_filtering", {})
            actual = f"restricted={egress.get('restricted')}"
            if egress.get("restricted") is True:
                return True, "Egress filtering active", "restricted=True", actual
            return False, "Egress filtering not active", "restricted=True", actual

        # Configuration & Baseline Hardening
        if "008-01" in code or "hardening" in act_type or "baseline" in act_type:
            actual = f"hardened={post_cfg.get('baseline_hardened')}"
            if post_cfg.get("baseline_hardened") is True:
                return True, "Baseline hardening applied", "baseline_hardened=True", actual
            return False, "Hardening configuration missing", "baseline_hardened=True", actual

        # Generic fallback verification
        # Verify that post_cfg has changed from pre_cfg
        if post_cfg != pre_cfg:
            return True, "Configuration updated as expected", "config_updated=True", "config_updated=True"
        return False, "No state change detected after action execution", "config_updated=True", "config_updated=False"

    async def get_execution_verification_summary(
        self,
        execution_id: uuid.UUID,
    ) -> RemediationVerificationSummaryResponse:
        """Retrieves and compiles regression verification summary for a given execution."""
        from fastapi import HTTPException, status
        from sqlalchemy import select

        query = (
            select(RemediationVerification)
            .where(RemediationVerification.execution_id == execution_id)
            .order_by(RemediationVerification.verified_at.asc())
        )
        verifications = (await self.session.execute(query)).scalars().all()

        execution = await self.session.get(SyntheticRemediationExecution, execution_id)
        if not execution:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"SyntheticRemediationExecution '{execution_id}' not found.",
            )

        total = len(verifications)
        passed = sum(1 for v in verifications if v.verification_status == VerificationStatus.PASSED.value)
        failed = sum(1 for v in verifications if v.verification_status == VerificationStatus.FAILED.value)
        inconclusive = sum(1 for v in verifications if v.verification_status == VerificationStatus.INCONCLUSIVE.value)

        if total > 0 and passed == total:
            overall = VerificationStatus.PASSED.value
        elif passed > 0:
            overall = VerificationStatus.PARTIALLY_PASSED.value
        elif inconclusive > 0:
            overall = VerificationStatus.INCONCLUSIVE.value
        else:
            overall = VerificationStatus.FAILED.value

        return RemediationVerificationSummaryResponse(
            execution_id=execution.id,
            remediation_plan_id=execution.remediation_plan_id,
            sandbox_id=execution.sandbox_id,
            overall_status=overall,
            total_checks=total,
            passed_checks=passed,
            failed_checks=failed,
            inconclusive_checks=inconclusive,
            verifications=[self.verification_to_response(v) for v in verifications],
        )

