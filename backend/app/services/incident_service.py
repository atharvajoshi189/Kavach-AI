"""Data access and repository services for Incidents, PolicyVersions, and Approvals."""

from datetime import datetime, timezone
from typing import Optional
import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.approval import Approval
from app.models.incident import Incident
from app.models.policy_version import PolicyVersion


# --- Incidents ---

async def create_incident(
    session: AsyncSession,
    title: str,
    severity: str = "medium",
    status: str = "open",
    description: Optional[str] = None,
    source: str = "system",
    campaign_id: Optional[uuid.UUID] = None,
) -> Incident:
    """Creates a new security incident."""
    incident = Incident(
        title=title,
        severity=severity,
        status=status,
        description=description,
        source=source,
        campaign_id=campaign_id,
    )
    session.add(incident)
    await session.flush()
    return incident


async def get_incident_by_id(
    session: AsyncSession,
    incident_id: uuid.UUID,
) -> Optional[Incident]:
    """Retrieves an Incident by UUID."""
    result = await session.execute(select(Incident).where(Incident.id == incident_id))
    return result.scalar_one_or_none()


async def update_incident_status(
    session: AsyncSession,
    incident_id: uuid.UUID,
    status: str,
    resolved_at: Optional[datetime] = None,
) -> Optional[Incident]:
    """Updates an incident status and resolution timestamp."""
    incident = await get_incident_by_id(session, incident_id)
    if not incident:
        return None
    incident.status = status
    if status.lower() == "resolved" and resolved_at is None:
        incident.resolved_at = datetime.now(timezone.utc)
    elif resolved_at:
        incident.resolved_at = resolved_at
    await session.flush()
    return incident


async def list_incidents(
    session: AsyncSession,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
) -> list[Incident]:
    """Lists incidents with optional filtering."""
    query = select(Incident)
    if severity:
        query = query.where(Incident.severity == severity)
    if status:
        query = query.where(Incident.status == status)
    query = query.order_by(Incident.created_at.desc()).offset(skip).limit(limit)
    result = await session.execute(query)
    return list(result.scalars().all())


# --- Policy Versions ---

async def create_policy_version(
    session: AsyncSession,
    version: str,
    policy_content: str,
    created_by: Optional[uuid.UUID] = None,
    status: str = "draft",
) -> PolicyVersion:
    """Creates a versioned policy entity."""
    policy = PolicyVersion(
        version=version,
        policy_content=policy_content,
        created_by=created_by,
        status=status,
    )
    session.add(policy)
    await session.flush()
    return policy


async def get_policy_version_by_id(
    session: AsyncSession,
    policy_version_id: uuid.UUID,
) -> Optional[PolicyVersion]:
    """Retrieves a PolicyVersion by ID."""
    result = await session.execute(
        select(PolicyVersion).where(PolicyVersion.id == policy_version_id)
    )
    return result.scalar_one_or_none()


# --- Approvals ---

async def create_approval_request(
    session: AsyncSession,
    requested_by: uuid.UUID,
    incident_id: Optional[uuid.UUID] = None,
    policy_version_id: Optional[uuid.UUID] = None,
    approval_reason: Optional[str] = None,
    expires_at: Optional[datetime] = None,
) -> Approval:
    """Submits a human approval request for a sensitive action or policy."""
    approval = Approval(
        requested_by=requested_by,
        incident_id=incident_id,
        policy_version_id=policy_version_id,
        approval_reason=approval_reason,
        expires_at=expires_at,
        status="pending",
    )
    session.add(approval)
    await session.flush()
    return approval


async def resolve_approval(
    session: AsyncSession,
    approval_id: uuid.UUID,
    approved_by: uuid.UUID,
    status: str,
    reason: Optional[str] = None,
) -> Optional[Approval]:
    """Resolves (approves or rejects) an approval request."""
    result = await session.execute(select(Approval).where(Approval.id == approval_id))
    approval = result.scalar_one_or_none()
    if not approval:
        return None
    approval.status = status
    approval.approved_by = approved_by
    approval.approved_at = datetime.now(timezone.utc)
    if reason:
        approval.approval_reason = reason
    await session.flush()
    return approval


async def get_approval_by_id(
    session: AsyncSession,
    approval_id: uuid.UUID,
) -> Optional[Approval]:
    """Retrieves an Approval request by primary key."""
    result = await session.execute(select(Approval).where(Approval.id == approval_id))
    return result.scalar_one_or_none()

