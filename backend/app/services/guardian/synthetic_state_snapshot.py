"""Synthetic State Snapshot Service capturing cryptographically verified environment state."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.blue_guardian.approval_schemas import (
    SyntheticSnapshotComparisonResponse,
    SyntheticStateSnapshotResponse,
)
from app.models.guardian import SyntheticRemediationExecution, SyntheticStateSnapshot
from app.models.synthetic_asset import SyntheticAsset
from app.services.audit_service import record_audit_log

logger = logging.getLogger("aegismesh.guardian.snapshot")

SNAPSHOT_SCHEMA_VERSION = "1.0.0"


def compute_snapshot_hash(data: Dict[str, Any]) -> str:
    """Produces a deterministic SHA-256 integrity hash for snapshot payload."""
    canonical_json = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class SyntheticStateSnapshotService:
    """Captures and compares immutable synthetic target asset state snapshots."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def capture_snapshot(
        self,
        execution: SyntheticRemediationExecution,
        snapshot_type: str,  # "BEFORE" or "AFTER"
        target_asset_ids: List[str],
        actor_id: Optional[uuid.UUID] = None,
    ) -> SyntheticStateSnapshot:
        """Captures an immutable snapshot of target synthetic assets within sandbox boundaries."""
        # Query target assets within sandbox
        asset_uuids = []
        for aid in target_asset_ids:
            try:
                asset_uuids.append(uuid.UUID(str(aid)))
            except (ValueError, TypeError):
                continue

        query = select(SyntheticAsset).where(
            SyntheticAsset.sandbox_id == execution.sandbox_id,
        )
        if asset_uuids:
            query = query.where(SyntheticAsset.id.in_(asset_uuids))

        rows = (await self.session.execute(query)).scalars().all()

        # Build snapshot data payload
        assets_payload = []
        for a in rows:
            assets_payload.append({
                "asset_id": str(a.id),
                "name": a.name,
                "asset_type": a.asset_type,
                "status": a.status,
                "hostname": a.hostname,
                "ip_address": a.ip_address,
                "risk_level": a.risk_level,
                "configuration": dict(a.configuration or {}),
                "service_metadata": dict(a.service_metadata or {}),
                "os_metadata": dict(a.os_metadata or {}),
                "simulated_vulnerabilities": list(a.simulated_vulnerabilities or []),
                "connected_asset_ids": list(a.connected_asset_ids or []),
            })

        # Sort deterministically by asset_id
        assets_payload.sort(key=lambda x: x["asset_id"])

        now = datetime.now(timezone.utc)
        snapshot_data = {
            "execution_id": str(execution.id),
            "sandbox_id": str(execution.sandbox_id),
            "snapshot_type": snapshot_type.upper(),
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "captured_at": now.isoformat(),
            "asset_count": len(assets_payload),
            "assets": assets_payload,
            "is_simulated": True,
            "simulation_only": True,
        }

        integrity_hash = compute_snapshot_hash(snapshot_data)

        snapshot = SyntheticStateSnapshot(
            id=uuid.uuid4(),
            execution_id=execution.id,
            sandbox_id=execution.sandbox_id,
            snapshot_type=snapshot_type.upper(),
            snapshot_schema_version=SNAPSHOT_SCHEMA_VERSION,
            snapshot_data=snapshot_data,
            integrity_hash=integrity_hash,
            created_at=now,
        )
        self.session.add(snapshot)
        await self.session.flush()

        # Audit snapshot creation
        try:
            await record_audit_log(
                session=self.session,
                event_type="guardian.snapshot.created",
                action="guardian.snapshot",
                resource_type="synthetic_snapshot",
                actor_id=actor_id,
                resource_id=str(snapshot.id),
                decision="CAPTURED",
                event_data={
                    "snapshot_id": str(snapshot.id),
                    "execution_id": str(execution.id),
                    "snapshot_type": snapshot.snapshot_type,
                    "asset_count": len(assets_payload),
                    "integrity_hash": integrity_hash,
                },
            )
            await self.session.flush()
        except Exception as e:
            logger.warning("Audit logging failed for snapshot capture: %s", e)

        return snapshot

    @classmethod
    def snapshot_to_response(cls, snap: SyntheticStateSnapshot) -> SyntheticStateSnapshotResponse:
        return SyntheticStateSnapshotResponse(
            id=snap.id,
            execution_id=snap.execution_id,
            sandbox_id=snap.sandbox_id,
            snapshot_type=snap.snapshot_type,
            snapshot_schema_version=snap.snapshot_schema_version,
            snapshot_data=snap.snapshot_data,
            integrity_hash=snap.integrity_hash,
            created_at=snap.created_at,
        )

    @classmethod
    def compare_snapshots(
        cls,
        before: SyntheticStateSnapshot,
        after: Optional[SyntheticStateSnapshot],
    ) -> SyntheticSnapshotComparisonResponse:
        """Calculates deterministic differential between before and after snapshots."""
        if not after:
            return SyntheticSnapshotComparisonResponse(
                execution_id=before.execution_id,
                before_snapshot=cls.snapshot_to_response(before),
                after_snapshot=None,
                changes_detected=False,
                modified_assets=[],
                security_improvements=[],
                unresolved_risks=["Post-remediation snapshot has not been captured."],
            )

        before_assets = {a["asset_id"]: a for a in before.snapshot_data.get("assets", [])}
        after_assets = {a["asset_id"]: a for a in after.snapshot_data.get("assets", [])}

        modified_assets = []
        improvements: List[str] = []
        unresolved: List[str] = []

        risk_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        for aid, a_post in after_assets.items():
            a_pre = before_assets.get(aid)
            if not a_pre:
                continue

            diffs: Dict[str, Any] = {}
            # Check configuration diffs
            pre_cfg = a_pre.get("configuration", {})
            post_cfg = a_post.get("configuration", {})
            if pre_cfg != post_cfg:
                diffs["configuration_changes"] = {
                    "added_or_updated": {k: v for k, v in post_cfg.items() if pre_cfg.get(k) != v},
                }

            # Check risk level change
            pre_risk = a_pre.get("risk_level", "medium")
            post_risk = a_post.get("risk_level", "medium")
            if pre_risk != post_risk:
                diffs["risk_level"] = {"before": pre_risk, "after": post_risk}
                if risk_rank.get(post_risk, 0) < risk_rank.get(pre_risk, 0):
                    improvements.append(f"Asset '{a_post.get('name')}' risk level lowered from {pre_risk.upper()} to {post_risk.upper()}.")

            # Check simulated vulnerabilities change
            pre_vulns = len(a_pre.get("simulated_vulnerabilities", []))
            post_vulns = len(a_post.get("simulated_vulnerabilities", []))
            if post_vulns < pre_vulns:
                diffs["vulnerabilities_reduced"] = pre_vulns - post_vulns
                improvements.append(f"Asset '{a_post.get('name')}' vulnerabilities reduced from {pre_vulns} to {post_vulns}.")
            elif post_vulns > 0:
                unresolved.append(f"Asset '{a_post.get('name')}' still has {post_vulns} active simulated vulnerabilities.")

            # Check security controls in configuration
            if post_cfg.get("mfa_enforced") and not pre_cfg.get("mfa_enforced"):
                improvements.append(f"MFA enforcement enabled on asset '{a_post.get('name')}'.")
            if post_cfg.get("account_lockout_policy", {}).get("enabled"):
                improvements.append(f"Account lockout policy active on '{a_post.get('name')}'.")
            if post_cfg.get("network_segmentation", {}).get("segmented"):
                improvements.append(f"Network micro-segmentation active on '{a_post.get('name')}'.")

            if diffs:
                modified_assets.append({
                    "asset_id": aid,
                    "name": a_post.get("name"),
                    "diffs": diffs,
                })

        return SyntheticSnapshotComparisonResponse(
            execution_id=before.execution_id,
            before_snapshot=cls.snapshot_to_response(before),
            after_snapshot=cls.snapshot_to_response(after),
            changes_detected=len(modified_assets) > 0,
            modified_assets=modified_assets,
            security_improvements=improvements,
            unresolved_risks=unresolved,
        )

