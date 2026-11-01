"""SQLAlchemy model representing a platform user with role-based access controls."""

from datetime import datetime, timezone
import enum
from typing import TYPE_CHECKING
import uuid
from sqlalchemy import Boolean, DateTime, Enum, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.approval import Approval
    from app.models.audit_log import AuditLog
    from app.models.policy_version import PolicyVersion


class UserRole(str, enum.Enum):
    """Platform roles following principle of least privilege."""

    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    SECURITY_OPERATOR = "security_operator"
    VIEWER = "viewer"


class User(Base):
    """Platform user entity."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )
    username: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role", native_enum=False),
        default=UserRole.VIEWER,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="actor",
        foreign_keys="AuditLog.actor_id",
        passive_deletes="all",
    )
    policy_versions_created: Mapped[list["PolicyVersion"]] = relationship(
        "PolicyVersion",
        back_populates="creator",
        foreign_keys="PolicyVersion.created_by",
    )
    policy_versions_approved: Mapped[list["PolicyVersion"]] = relationship(
        "PolicyVersion",
        back_populates="approver",
        foreign_keys="PolicyVersion.approved_by",
    )
    approvals_requested: Mapped[list["Approval"]] = relationship(
        "Approval",
        back_populates="requester",
        foreign_keys="Approval.requested_by",
    )
    approvals_received: Mapped[list["Approval"]] = relationship(
        "Approval",
        back_populates="approver",
        foreign_keys="Approval.approved_by",
    )

    def __repr__(self) -> str:
        return f"<User {self.username} (role={self.role})>"

