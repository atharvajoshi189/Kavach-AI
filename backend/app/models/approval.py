"""SQLAlchemy model representing human-in-the-loop approval workflows."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
import uuid
from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.policy_version import PolicyVersion
    from app.models.user import User


class Approval(Base):
    """Approval request for privileged operations (e.g. remediation, policy promotion)."""

    __tablename__ = "approvals"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    incident_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    policy_version_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("policy_versions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    requested_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    approved_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
        index=True,
    )
    approval_reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    incident: Mapped[Optional["Incident"]] = relationship(
        "Incident",
        back_populates="approvals",
    )
    policy_version: Mapped[Optional["PolicyVersion"]] = relationship(
        "PolicyVersion",
        back_populates="approvals",
    )
    requester: Mapped["User"] = relationship(
        "User",
        back_populates="approvals_requested",
        foreign_keys=[requested_by],
    )
    approver: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="approvals_received",
        foreign_keys=[approved_by],
    )

    def __repr__(self) -> str:
        return f"<Approval {self.id} (status={self.status}, requester={self.requested_by})>"

