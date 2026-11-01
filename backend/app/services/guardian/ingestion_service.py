"""Defensive Event Ingestion Service for Blue Guardian.

Retrieves, validates, normalizes, and idempotently persists synthetic security events
from authorized AttackRun and AttackPath execution records.
Enforces strict read-only guarantees on source evidence and rejects any cross-sandbox
or non-synthetic telemetry.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, List, Optional, Tuple
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.blue_guardian.schemas import DefensiveEventEnvelope, EpistemicClassification
from app.models.attack_path import AttackPath
from app.models.attack_path_stage import AttackPathStage
from app.models.attack_run import AttackRun
from app.models.campaign import Campaign
from app.models.guardian import DefensiveEventRecord, GuardianExecution
from app.models.sandbox import SandboxEnvironment
from app.models.synthetic_asset import SyntheticAsset

logger = logging.getLogger("aegismesh.guardian.ingestion")


class IngestionValidationError(Exception):
    """Raised when an ingested event fails security or provenance validation."""


class CrossSandboxSecurityViolation(IngestionValidationError):
    """Raised when telemetry crosses sandbox boundaries."""


class NonSyntheticEvidenceViolation(IngestionValidationError):
    """Raised when telemetry is not strictly simulated."""


def compute_payload_sha256(payload: dict[str, Any]) -> str:
    """Computes a deterministic SHA-256 digest over the canonical JSON payload."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def parse_iso_datetime(value: Any) -> datetime:
    """Safely normalizes an ISO string or datetime object to UTC datetime."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception as ex:
            logger.warning("Failed to parse datetime '%s': %s, falling back to current UTC", value, ex)
    return datetime.now(timezone.utc)


class IngestionService:
    """Service handling validation, normalization, and persistence of defensive telemetry."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_sandbox_asset_ids(self, sandbox_id: uuid.UUID) -> set[uuid.UUID]:
        """Returns the set of valid asset UUIDs belonging to the specified sandbox.
        
        Note: We do NOT exclude archived assets here because defensive analysis must be capable
        of ingesting historical events emitted by assets that were decommissioned or archived
        subsequent to the simulated attack run. Sandbox boundary isolation remains strictly enforced.
        """
        query = select(SyntheticAsset.id).where(
            SyntheticAsset.sandbox_id == sandbox_id,
        )
        result = await self.session.execute(query)
        return set(result.scalars().all())

    async def extract_source_events(
        self,
        sandbox_id: uuid.UUID,
        attack_run_id: Optional[uuid.UUID] = None,
        attack_path_id: Optional[uuid.UUID] = None,
    ) -> List[dict[str, Any]]:
        """Extracts raw event dictionaries from persisted AttackRun or AttackPath execution metadata.
        
        Strict read-only operation: does not mutate or lock source records.
        """
        raw_events: List[dict[str, Any]] = []

        if attack_run_id:
            run = await self.session.get(AttackRun, attack_run_id)
            if not run:
                raise IngestionValidationError(f"Target AttackRun '{attack_run_id}' not found.")

            # Verify campaign and sandbox association
            campaign = await self.session.get(Campaign, run.campaign_id)
            if not campaign:
                raise IngestionValidationError(f"Campaign '{run.campaign_id}' for AttackRun not found.")
            if campaign.sandbox_id != sandbox_id:
                raise CrossSandboxSecurityViolation(
                    f"AttackRun '{attack_run_id}' belongs to sandbox '{campaign.sandbox_id}', not '{sandbox_id}'."
                )

            metadata = run.execution_metadata or {}
            events = metadata.get("events", [])
            for ev in events:
                raw_events.append({
                    **ev,
                    "attack_run_id": str(run.id),
                    "campaign_id": str(campaign.id),
                    "sandbox_id": str(sandbox_id),
                    "attack_path_id": None,
                })

        elif attack_path_id:
            path = await self.session.get(AttackPath, attack_path_id)
            if not path:
                raise IngestionValidationError(f"Target AttackPath '{attack_path_id}' not found.")
            if path.sandbox_id != sandbox_id:
                raise CrossSandboxSecurityViolation(
                    f"AttackPath '{attack_path_id}' belongs to sandbox '{path.sandbox_id}', not '{sandbox_id}'."
                )

            # Query stages for this path
            stage_query = (
                select(AttackPathStage)
                .where(AttackPathStage.attack_path_id == attack_path_id)
                .order_by(AttackPathStage.sequence_number)
            )
            result = await self.session.execute(stage_query)
            stages = result.scalars().all()

            for stage in stages:
                if not stage.attack_run_id:
                    continue
                run = await self.session.get(AttackRun, stage.attack_run_id)
                if not run:
                    continue
                metadata = run.execution_metadata or {}
                events = metadata.get("events", [])
                for ev in events:
                    raw_events.append({
                        **ev,
                        "attack_run_id": str(run.id),
                        "campaign_id": str(path.campaign_id),
                        "sandbox_id": str(sandbox_id),
                        "attack_path_id": str(path.id),
                        "stage_sequence": stage.sequence_number,
                    })

        return raw_events

    def validate_and_normalize_event(
        self,
        raw_event: dict[str, Any],
        expected_sandbox_id: uuid.UUID,
        valid_asset_ids: set[uuid.UUID],
    ) -> DefensiveEventEnvelope:
        """Validates security invariants, provenance, and normalizes a single raw event into an immutable envelope."""
        # 1. Strict Simulation Flags Invariant
        is_simulated = raw_event.get("is_simulated")
        simulation_only = raw_event.get("simulation_only")
        if is_simulated is not True or simulation_only is not True:
            raise NonSyntheticEvidenceViolation(
                f"Rejected event {raw_event.get('event_id')}: Non-synthetic evidence violation "
                f"(is_simulated={is_simulated}, simulation_only={simulation_only})."
            )

        # 2. Source Event Identifier
        source_event_id = str(raw_event.get("event_id") or raw_event.get("id") or "").strip()
        if not source_event_id:
            raise IngestionValidationError("Rejected event: Missing source event_id.")

        # 3. Sandbox Boundary Isolation
        event_sandbox_str = raw_event.get("sandbox_id")
        if event_sandbox_str:
            try:
                event_sandbox_id = uuid.UUID(str(event_sandbox_str))
                if event_sandbox_id != expected_sandbox_id:
                    raise CrossSandboxSecurityViolation(
                        f"Cross-sandbox rejection: Event sandbox '{event_sandbox_id}' does not match target sandbox '{expected_sandbox_id}'."
                    )
            except ValueError as ex:
                raise IngestionValidationError(f"Invalid sandbox_id format in event: {event_sandbox_str}") from ex
        else:
            event_sandbox_id = expected_sandbox_id

        # 4. Asset Scope & Relationship Validation
        source_asset_id: Optional[uuid.UUID] = None
        destination_asset_id: Optional[uuid.UUID] = None

        raw_src = raw_event.get("source_asset_id") or raw_event.get("asset_id")
        if raw_src:
            try:
                parsed_src = uuid.UUID(str(raw_src))
                if parsed_src not in valid_asset_ids:
                    logger.warning("Source asset '%s' not found in active sandbox assets", parsed_src)
                source_asset_id = parsed_src
            except ValueError:
                logger.debug("Source asset identifier '%s' is not a standard UUID, omitting FK", raw_src)

        raw_dst = raw_event.get("destination_asset_id")
        if raw_dst:
            try:
                parsed_dst = uuid.UUID(str(raw_dst))
                if parsed_dst not in valid_asset_ids:
                    logger.warning("Destination asset '%s' not found in active sandbox assets", parsed_dst)
                destination_asset_id = parsed_dst
            except ValueError:
                logger.debug("Destination asset identifier '%s' is not a standard UUID, omitting FK", raw_dst)

        # 5. Timestamp Normalization
        original_ts = parse_iso_datetime(raw_event.get("timestamp"))

        # 6. Parse Foreign Key UUIDs
        attack_run_id: Optional[uuid.UUID] = None
        if raw_event.get("attack_run_id"):
            try:
                attack_run_id = uuid.UUID(str(raw_event["attack_run_id"]))
            except ValueError:
                pass

        attack_path_id: Optional[uuid.UUID] = None
        if raw_event.get("attack_path_id"):
            try:
                attack_path_id = uuid.UUID(str(raw_event["attack_path_id"]))
            except ValueError:
                pass

        campaign_id: Optional[uuid.UUID] = None
        if raw_event.get("campaign_id"):
            try:
                campaign_id = uuid.UUID(str(raw_event["campaign_id"]))
            except ValueError:
                pass

        # 7. Payload & Provenance
        details = raw_event.get("details") or {}
        event_metadata = raw_event.get("event_metadata") or {}
        raw_payload = {
            "message": raw_event.get("message", ""),
            "details": details,
            "event_metadata": event_metadata,
        }
        sha256_hash = compute_payload_sha256(raw_payload)

        provenance_metadata = {
            "ingested_at": datetime.now(timezone.utc).isoformat(),
            "original_event_type": raw_event.get("event_type", "generic_simulated_event"),
            "stage_sequence": raw_event.get("stage_sequence"),
        }

        return DefensiveEventEnvelope(
            source_event_id=source_event_id,
            attack_run_id=attack_run_id,
            attack_path_id=attack_path_id,
            campaign_id=campaign_id,
            sandbox_id=expected_sandbox_id,
            scenario_id=raw_event.get("scenario_id"),
            timestamp=original_ts,
            event_type=raw_event.get("event_type", "generic_simulated_event"),
            severity=str(raw_event.get("severity", "info")).lower(),
            source_asset_id=source_asset_id,
            destination_asset_id=destination_asset_id,
            raw_payload=raw_payload,
            provenance_metadata=provenance_metadata,
            is_simulated=True,
            simulation_only=True,
            sha256_hash=sha256_hash,
            classification=EpistemicClassification.OBSERVED,
        )

    async def ingest_events_for_execution(
        self,
        execution: GuardianExecution,
        correlation_window_seconds: int = 300,
    ) -> List[DefensiveEventRecord]:
        """Ingests, validates, sorts, and persists defensive records for a GuardianExecution.
        
        Guarantees idempotency and deterministic sorting.
        """
        sandbox_id = execution.sandbox_id
        valid_asset_ids = await self.get_sandbox_asset_ids(sandbox_id)

        raw_events = await self.extract_source_events(
            sandbox_id=sandbox_id,
            attack_run_id=execution.attack_run_id,
            attack_path_id=execution.attack_path_id,
        )

        envelopes: List[DefensiveEventEnvelope] = []
        seen_source_event_ids: set[str] = set()

        for raw_ev in raw_events:
            src_id = str(raw_ev.get("event_id") or raw_ev.get("id") or "")
            if src_id in seen_source_event_ids:
                continue
            seen_source_event_ids.add(src_id)

            envelope = self.validate_and_normalize_event(
                raw_event=raw_ev,
                expected_sandbox_id=sandbox_id,
                valid_asset_ids=valid_asset_ids,
            )
            envelopes.append(envelope)

        # Deterministic Sorting: by original timestamp ascending, tie-break by source_event_id
        envelopes.sort(key=lambda env: (env.timestamp.isoformat(), env.source_event_id))

        # Retrieve already ingested event IDs for this execution to guarantee database idempotency
        existing_query = select(DefensiveEventRecord.source_event_id).where(
            DefensiveEventRecord.guardian_execution_id == execution.id
        )
        existing_res = await self.session.execute(existing_query)
        existing_ids = set(existing_res.scalars().all())

        persisted_records: List[DefensiveEventRecord] = []
        for env in envelopes:
            if env.source_event_id in existing_ids:
                continue

            record = DefensiveEventRecord(
                guardian_execution_id=execution.id,
                sandbox_id=env.sandbox_id,
                source_event_id=env.source_event_id,
                attack_run_id=env.attack_run_id,
                campaign_id=env.campaign_id,
                attack_path_id=env.attack_path_id,
                scenario_id=env.scenario_id,
                source_asset_id=env.source_asset_id,
                destination_asset_id=env.destination_asset_id,
                event_type=env.event_type,
                severity=env.severity,
                original_timestamp=env.timestamp,
                ingested_at=datetime.now(timezone.utc),
                is_simulated=True,
                simulation_only=True,
                sha256_hash=env.sha256_hash,
                raw_payload=env.raw_payload,
                provenance_metadata=env.provenance_metadata,
            )
            self.session.add(record)
            persisted_records.append(record)

        await self.session.flush()

        # Update execution metrics
        execution.events_ingested = len(existing_ids) + len(persisted_records)
        await self.session.flush()

        # Fetch complete ordered list of ingested records for this execution
        complete_query = (
            select(DefensiveEventRecord)
            .where(DefensiveEventRecord.guardian_execution_id == execution.id)
            .order_by(DefensiveEventRecord.original_timestamp, DefensiveEventRecord.source_event_id)
        )
        result = await self.session.execute(complete_query)
        return list(result.scalars().all())
