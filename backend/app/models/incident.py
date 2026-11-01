"""SQLAlchemy model representing a security incident detected or raised during operations."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
import uuid
from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.approval import Approval
    from app.models.campaign import Campaign


class Incident(Base):
    """Security incident entity representing detected risks, alerts, or anomalies."""

    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    campaign_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    severity: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="medium",
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="open",
        index=True,
    )
    source: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="system",
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
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Relationships
    campaign: Mapped[Optional["Campaign"]] = relationship(
        "Campaign",
        back_populates="incidents",
    )
    approvals: Mapped[list["Approval"]] = relationship(
        "Approval",
        back_populates="incident",
    )

    def __repr__(self) -> str:
        return f"<Incident {self.title} (severity={self.severity}, status={self.status})>"

