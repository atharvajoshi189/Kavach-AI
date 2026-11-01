"""SQLAlchemy model representing a security attack execution run within a campaign."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
import uuid
from sqlalchemy import DateTime, Float, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.campaign import Campaign


class AttackRun(Base):
    """Specific offensive technique or test execution executed under a campaign."""

    __tablename__ = "attack_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    technique: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    scenario: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    outcome: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    risk_score: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    execution_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    campaign: Mapped["Campaign"] = relationship(
        "Campaign",
        back_populates="attack_runs",
    )

    def __repr__(self) -> str:
        return f"<AttackRun {self.technique} (outcome={self.outcome})>"

