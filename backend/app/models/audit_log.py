"""SQLAlchemy model representing immutable, tamper-evident security audit logs."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
import uuid
from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.user import User


class AuditLog(Base):
    """Cryptographically chained, tamper-evident persistent security audit entry."""

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    event_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    actor_role: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    action: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    resource_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    resource_id: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    decision: Mapped[Optional[str]] = mapped_column(
        String(32),
        nullable=True,
    )
    event_data: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    previous_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    event_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Explicit relationship avoiding cascading deletion of audit records
    actor: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="audit_logs",
        foreign_keys=[actor_id],
    )

    def __repr__(self) -> str:
        return f"<AuditLog {self.event_type} action={self.action} hash={self.event_hash[:8]}...>"

