"""Durable, tamper-evident PostgreSQL audit persistence service with hash-chain integrity."""

from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
from typing import Any, Optional
import uuid
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.audit_log import AuditLog

logger = logging.getLogger("aegismesh.audit.persistence")

# Defined genesis hash representing the origin of the audit chain
GENESIS_HASH = "0" * 64

# Deterministic 64-bit integer for PostgreSQL transaction advisory locking
AUDIT_ADVISORY_LOCK_ID = 847291047192

# Sensitive keys and patterns stripped recursively from event payloads
SENSITIVE_KEYS = frozenset(
    {
        "password",
        "hashed_password",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "authorization",
        "api_key",
        "apikey",
        "private_key",
        "credentials",
    }
)
SENSITIVE_PATTERNS = ("password", "token", "secret", "api_key", "apikey", "private_key", "authorization", "credentials")


def is_sensitive_key(key: Any) -> bool:
    """Detects whether a dictionary key represents sensitive security credentials or tokens."""
    normalized = str(key).lower().replace("-", "_")
    if normalized in SENSITIVE_KEYS:
        return True
    return any(pattern in normalized for pattern in SENSITIVE_PATTERNS)


def sanitize_event_data(data: Any) -> Any:
    """Recursively removes sensitive credentials and token fields from audit payloads."""
    if isinstance(data, dict):
        return {
            k: sanitize_event_data(v)
            for k, v in data.items()
            if not is_sensitive_key(k)
        }
    elif isinstance(data, list):
        return [sanitize_event_data(item) for item in data]
    return data


def compute_canonical_payload(
    event_id: uuid.UUID,
    event_type: str,
    actor_id: Optional[uuid.UUID],
    actor_role: Optional[str],
    action: str,
    resource_type: str,
    resource_id: Optional[str],
    decision: Optional[str],
    event_data: dict[str, Any],
    created_at: datetime,
) -> str:
    """Produces a deterministic, canonical JSON representation of the event payload."""
    if created_at.tzinfo is None:
        created_at_utc = created_at.replace(tzinfo=timezone.utc)
    else:
        created_at_utc = created_at.astimezone(timezone.utc)

    payload = {
        "id": str(event_id),
        "event_type": event_type,
        "actor_id": str(actor_id) if actor_id else None,
        "actor_role": actor_role,
        "action": action,
        "resource_type": resource_type,
        "resource_id": str(resource_id) if resource_id else None,
        "decision": decision,
        "event_data": sanitize_event_data(event_data),
        "created_at": created_at_utc.isoformat(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_event_hash(previous_hash: str, canonical_payload: str) -> str:
    """Computes SHA-256 hash chaining the previous hash with the canonical payload."""
    combined = f"{previous_hash}{canonical_payload}".encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def verify_event_hash(audit_log: AuditLog) -> bool:
    """Verifies that an individual audit log record matches its computed hash."""
    canonical = compute_canonical_payload(
        event_id=audit_log.id,
        event_type=audit_log.event_type,
        actor_id=audit_log.actor_id,
        actor_role=audit_log.actor_role,
        action=audit_log.action,
        resource_type=audit_log.resource_type,
        resource_id=audit_log.resource_id,
        decision=audit_log.decision,
        event_data=audit_log.event_data,
        created_at=audit_log.created_at,
    )
    expected_hash = compute_event_hash(audit_log.previous_hash, canonical)
    return hmac.compare_digest(expected_hash, audit_log.event_hash)


def verify_audit_chain(logs: list[AuditLog]) -> tuple[bool, Optional[str]]:
    """Verifies the unbroken cryptographic chain across an ordered sequence of audit logs."""
    if not logs:
        return True, None

    for i, log in enumerate(logs):
        if not verify_event_hash(log):
            return False, f"Hash mismatch at index {i} (id={log.id})"

        if i > 0:
            previous_log = logs[i - 1]
            if log.previous_hash != previous_log.event_hash:
                return (
                    False,
                    f"Broken chain link at index {i} (id={log.id}): "
                    f"previous_hash '{log.previous_hash}' does not match predecessor event_hash '{previous_log.event_hash}'",
                )

    return True, None


async def record_audit_log(
    session: AsyncSession,
    event_type: str,
    action: str,
    resource_type: str,
    actor_id: Optional[uuid.UUID] = None,
    actor_role: Optional[str] = None,
    resource_id: Optional[str] = None,
    decision: Optional[str] = None,
    event_data: Optional[dict[str, Any]] = None,
) -> AuditLog:
    """Atomically appends an immutable audit log entry into PostgreSQL with tamper-evident hash chaining.

    Uses PostgreSQL transaction-level advisory locks to guarantee strict write serialization
    under concurrent execution.
    """
    # Acquire transaction-scoped advisory lock to serialize audit writes.
    # In PostgreSQL, this lock guarantees that concurrent transactions are strictly queued.
    # If using PostgreSQL, failure to acquire the lock must raise and abort.
    try:
        await session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id);"),
            {"lock_id": AUDIT_ADVISORY_LOCK_ID},
        )
    except Exception as lock_err:
        bind = session.get_bind()
        dialect_name = bind.dialect.name if bind else "postgresql"
        if dialect_name == "postgresql":
            logger.critical("MANDATORY ADVISORY LOCK FAILED on PostgreSQL: %s", lock_err)
            raise
        logger.debug("Advisory lock skipped for non-PostgreSQL dialect %s: %s", dialect_name, lock_err)

    # Query the most recent audit entry to link its hash
    latest_query = (
        select(AuditLog.event_hash)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(1)
    )
    result = await session.execute(latest_query)
    latest_hash = result.scalar_one_or_none()
    previous_hash = latest_hash if latest_hash is not None else GENESIS_HASH

    event_id = uuid.uuid4()
    created_at = datetime.now(timezone.utc)
    clean_data = sanitize_event_data(event_data or {})

    canonical_payload = compute_canonical_payload(
        event_id=event_id,
        event_type=event_type,
        actor_id=actor_id,
        actor_role=actor_role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        decision=decision,
        event_data=clean_data,
        created_at=created_at,
    )
    event_hash = compute_event_hash(previous_hash, canonical_payload)

    entry = AuditLog(
        id=event_id,
        event_type=event_type,
        actor_id=actor_id,
        actor_role=actor_role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        decision=decision,
        event_data=clean_data,
        previous_hash=previous_hash,
        event_hash=event_hash,
        created_at=created_at,
    )

    session.add(entry)
    await session.flush()
    return entry


async def get_audit_logs(
    session: AsyncSession,
    page: int = 1,
    page_size: int = 50,
    event_type: Optional[str] = None,
    actor_id: Optional[uuid.UUID] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
) -> tuple[list[AuditLog], int]:
    """Retrieves paginated audit log entries with optional filters and stable descending order."""
    query = select(AuditLog)
    count_query = select(func.count(AuditLog.id))

    if event_type:
        query = query.where(AuditLog.event_type == event_type)
        count_query = count_query.where(AuditLog.event_type == event_type)

    if actor_id:
        query = query.where(AuditLog.actor_id == actor_id)
        count_query = count_query.where(AuditLog.actor_id == actor_id)

    if start_date:
        query = query.where(AuditLog.created_at >= start_date)
        count_query = count_query.where(AuditLog.created_at >= start_date)

    if end_date:
        query = query.where(AuditLog.created_at <= end_date)
        count_query = count_query.where(AuditLog.created_at <= end_date)

    total_result = await session.execute(count_query)
    total_count = total_result.scalar_one() or 0

    offset = (page - 1) * page_size
    query = query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).offset(offset).limit(page_size)

    result = await session.execute(query)
    items = list(result.scalars().all())

    return items, total_count

