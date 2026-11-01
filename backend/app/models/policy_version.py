"""SQLAlchemy model representing versioned OPA/Rego security policies."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
import uuid
from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.approval import Approval
    from app.models.user import User


class PolicyVersion(Base):
    """Immutable or staged policy document version for audit and evaluation."""

    __tablename__ = "policy_versions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    version: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    policy_content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="draft",
        index=True,
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    approved_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    approved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    creator: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="policy_versions_created",
        foreign_keys=[created_by],
    )
    approver: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="policy_versions_approved",
        foreign_keys=[approved_by],
    )
    approvals: Mapped[list["Approval"]] = relationship(
        "Approval",
        back_populates="policy_version",
    )

    def __repr__(self) -> str:
        return f"<PolicyVersion {self.version} (status={self.status})>"

