"""SQLAlchemy model representing defensive and offensive benchmark metrics for campaigns."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
import uuid
from sqlalchemy import DateTime, Float, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.campaign import Campaign


class Evaluation(Base):
    """Calculated efficacy, detection, and latency metrics for security campaigns."""

    __tablename__ = "evaluations"

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
    detection_rate: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    attack_success_rate: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    false_positive_rate: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    false_negative_rate: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    utility_rate: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    mean_latency_ms: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    metrics: Mapped[dict[str, Any]] = mapped_column(
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
        back_populates="evaluations",
    )

    def __repr__(self) -> str:
        return f"<Evaluation campaign={self.campaign_id} (detection={self.detection_rate}, asr={self.attack_success_rate})>"

