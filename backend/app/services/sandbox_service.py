"""Sandbox Environment Management Service for AegisMesh 2.0.

Provides controlled access and lifecycle management for simulated sandbox execution
environments and their associated synthetic assets. Enforces strict sandbox isolation
boundaries and forbids any execution on the host operating system.
"""

import logging
from typing import Any, Optional
import uuid

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.sandbox import SandboxEnvironment
from app.models.synthetic_asset import SyntheticAsset
from app.models.user import User, UserRole

logger = logging.getLogger("aegismesh.services.sandbox")


def verify_sandbox_access(sandbox: SandboxEnvironment, user: User) -> bool:
    """Verifies whether an authenticated user is authorized to access a given sandbox.

    Rules:
    - Inactive users are strictly denied.
    - Administrators (ADMIN) have platform-wide access to all sandboxes.
    - User-assigned sandboxes (owner_id is not None): accessible strictly by the owner and ADMINs.
    - System/shared sandboxes (owner_id is None): accessible strictly by ADMIN, SECURITY_OPERATOR,
      and SECURITY_ANALYST. VIEWER role is denied access to synthetic sandbox infrastructure.
    """
    if not user.is_active:
        return False

    role_str = user.role.value if hasattr(user.role, "value") else str(user.role)

    # Admins always have access
    if role_str == UserRole.ADMIN.value:
        return True

    # User-assigned sandbox: caller must be the designated owner
    if sandbox.owner_id is not None:
        return sandbox.owner_id == user.id

    # System/shared sandbox: security operators and security analysts are authorized; viewer is denied
    if role_str in [UserRole.SECURITY_OPERATOR.value, UserRole.SECURITY_ANALYST.value]:
        return True

    return False


async def create_sandbox(
    session: AsyncSession,
    name: str,
    description: Optional[str] = None,
    isolation_mode: str = "simulated",
    configuration: Optional[dict[str, Any]] = None,
    owner_id: Optional[uuid.UUID] = None,
) -> SandboxEnvironment:
    """Creates a new sandbox environment record with optional ownership assignment."""
    sandbox = SandboxEnvironment(
        name=name.strip(),
        description=description,
        status="active",
        isolation_mode=isolation_mode,
        configuration=configuration or {},
        owner_id=owner_id,
    )
    session.add(sandbox)
    await session.commit()
    await session.refresh(sandbox)
    logger.info("Created SandboxEnvironment '%s' (%s, owner=%s)", sandbox.name, sandbox.id, owner_id)
    return sandbox


async def list_sandboxes(
    session: AsyncSession,
    skip: int = 0,
    limit: int = 100,
    user: Optional[User] = None,
) -> list[SandboxEnvironment]:
    """Retrieves paginated list of sandbox environments filtered by caller authorization.

    Admins see all sandboxes. Non-admins see only sandboxes they own plus system sandboxes
    (if their role is permitted). Viewers cannot access system sandboxes.
    """
    stmt = (
        select(SandboxEnvironment)
        .order_by(SandboxEnvironment.created_at.desc())
        .offset(max(0, skip))
        .limit(max(1, min(limit, 100)))
    )

    if user is not None:
        role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
        if role_str != UserRole.ADMIN.value:
            if role_str in [UserRole.SECURITY_OPERATOR.value, UserRole.SECURITY_ANALYST.value]:
                # Operators/Analysts see their own sandboxes + system sandboxes
                stmt = stmt.where(
                    or_(
                        SandboxEnvironment.owner_id == user.id,
                        SandboxEnvironment.owner_id.is_(None),
                    )
                )
            else:
                # Viewers or unprivileged users see only sandboxes explicitly assigned to them
                stmt = stmt.where(SandboxEnvironment.owner_id == user.id)

    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_sandbox_by_id(
    session: AsyncSession,
    sandbox_id: uuid.UUID,
) -> Optional[SandboxEnvironment]:
    """Retrieves a sandbox environment by its UUID."""
    stmt = select(SandboxEnvironment).where(SandboxEnvironment.id == sandbox_id)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def get_sandbox_by_name(
    session: AsyncSession,
    name: str,
) -> Optional[SandboxEnvironment]:
    """Retrieves a sandbox environment by its unique name."""
    stmt = select(SandboxEnvironment).where(SandboxEnvironment.name == name.strip())
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def register_asset(
    session: AsyncSession,
    sandbox_id: uuid.UUID,
    asset_data: dict[str, Any],
) -> SyntheticAsset:
    """Registers a synthetic asset inside a specified sandbox environment."""
    sandbox = await get_sandbox_by_id(session, sandbox_id)
    if not sandbox:
        raise ValueError(f"Sandbox '{sandbox_id}' not found.")

    asset = SyntheticAsset(
        id=asset_data.get("id", uuid.uuid4()),
        sandbox_id=sandbox_id,
        name=asset_data["name"],
        asset_type=asset_data["asset_type"],
        description=asset_data.get("description"),
        environment=asset_data.get("environment", "sandbox"),
        status=asset_data.get("status", "online"),
        hostname=asset_data["hostname"],
        ip_address=asset_data["ip_address"],
        os_metadata=asset_data.get("os_metadata", {}),
        service_metadata=asset_data.get("service_metadata", {}),
        configuration=asset_data.get("configuration", {}),
        simulated_vulnerabilities=asset_data.get("simulated_vulnerabilities", []),
        risk_level=asset_data.get("risk_level", "low"),
        connected_asset_ids=asset_data.get("connected_asset_ids", []),
    )
    session.add(asset)
    await session.commit()
    await session.refresh(asset)
    return asset


async def list_assets_in_sandbox(
    session: AsyncSession,
    sandbox_id: uuid.UUID,
    asset_type: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
) -> list[SyntheticAsset]:
    """Lists synthetic assets belonging strictly to the specified sandbox."""
    stmt = (
        select(SyntheticAsset)
        .where(SyntheticAsset.sandbox_id == sandbox_id)
        .order_by(SyntheticAsset.name.asc())
        .offset(max(0, skip))
        .limit(max(1, min(limit, 100)))
    )
    if asset_type:
        stmt = stmt.where(SyntheticAsset.asset_type == asset_type.strip().lower())

    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_asset_in_sandbox(
    session: AsyncSession,
    sandbox_id: uuid.UUID,
    asset_id: uuid.UUID,
) -> Optional[SyntheticAsset]:
    """Retrieves an asset by ID, ensuring it belongs strictly to the given sandbox."""
    stmt = (
        select(SyntheticAsset)
        .where(SyntheticAsset.id == asset_id)
        .where(SyntheticAsset.sandbox_id == sandbox_id)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def get_asset_by_id(
    session: AsyncSession,
    asset_id: uuid.UUID,
) -> Optional[SyntheticAsset]:
    """Retrieves an asset by primary key UUID across any sandbox."""
    result = await session.execute(select(SyntheticAsset).where(SyntheticAsset.id == asset_id))
    return result.scalar_one_or_none()


async def validate_asset_sandbox_boundary(
    session: AsyncSession,
    sandbox_id: uuid.UUID,
    asset_id: uuid.UUID,
) -> bool:
    """Verifies that an asset belongs to the specified sandbox environment."""
    asset = await get_asset_in_sandbox(session, sandbox_id, asset_id)
    return asset is not None


async def archive_sandbox(
    session: AsyncSession,
    sandbox_id: uuid.UUID,
    user: Optional[User] = None,
) -> SandboxEnvironment:
    """Safely transitions a sandbox to 'archived' status.

    Preserves all synthetic assets and metadata for forensic auditability and replay.
    Disallows target operations while guaranteeing forensic evidence retention.
    """
    sandbox = await get_sandbox_by_id(session, sandbox_id)
    if not sandbox:
        raise ValueError(f"Sandbox '{sandbox_id}' not found.")

    if user is not None:
        role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
        if role_str != UserRole.ADMIN.value and sandbox.owner_id != user.id:
            raise PermissionError("Forbidden: Only an admin or the sandbox owner can archive this environment.")

    sandbox.status = "archived"
    await session.commit()
    await session.refresh(sandbox)
    logger.info("Archived SandboxEnvironment '%s' (%s) - forensic records preserved", sandbox.name, sandbox.id)
    return sandbox


async def delete_sandbox(
    session: AsyncSession,
    sandbox_id: uuid.UUID,
    user: Optional[User] = None,
) -> None:
    """Destructively deletes a sandbox environment and its synthetic assets.

    Restricted strictly to administrators. Forensic archival (archive_sandbox)
    is strongly recommended to preserve historical forensic evidence.
    """
    sandbox = await get_sandbox_by_id(session, sandbox_id)
    if not sandbox:
        raise ValueError(f"Sandbox '{sandbox_id}' not found.")

    if user is not None:
        role_str = user.role.value if hasattr(user.role, "value") else str(user.role)
        if role_str != UserRole.ADMIN.value:
            raise PermissionError("Forbidden: Destructive deletion of sandboxes is restricted to administrators.")

    await session.delete(sandbox)
    await session.commit()
    logger.warning("Destructively deleted SandboxEnvironment '%s' (%s)", sandbox.name, sandbox.id)

