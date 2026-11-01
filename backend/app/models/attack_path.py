"""SQLAlchemy model representing a multi-stage synthetic attack path."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

if TYPE_CHECKING:
    from app.models.campaign import Campaign
    from app.models.sandbox import SandboxEnvironment
    from app.models.synthetic_asset import SyntheticAsset
    from app.models.attack_path_stage import AttackPathStage


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    campaign_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("campaigns.id", ondelete="RESTRICT"), nullable=False, index=True)
    sandbox_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("sandbox_environments.id", ondelete="RESTRICT"), nullable=False, index=True)
    source_asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("synthetic_assets.id", ondelete="RESTRICT"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="planned", index=True)
    # planned, validating, ready, running, completed, partially_completed, failed, cancelled
    execution_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="exploratory")
    # exploratory, targeted
    total_stages: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completed_stages: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_stages: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    path_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    execution_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    simulation_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    stages: Mapped[list["AttackPathStage"]] = relationship("AttackPathStage", back_populates="attack_path", order_by="AttackPathStage.sequence_number", cascade="all, delete-orphan", lazy="selectin")
    campaign: Mapped["Campaign"] = relationship("Campaign")
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")
    source_asset: Mapped["SyntheticAsset"] = relationship("SyntheticAsset", foreign_keys=[source_asset_id])
