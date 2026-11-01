"""SQLAlchemy model representing a single stage within a multi-stage attack path."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

if TYPE_CHECKING:
    from app.models.attack_path import AttackPath
    from app.models.synthetic_asset import SyntheticAsset
    from app.models.attack_run import AttackRun


class AttackPathStage(Base):
    __tablename__ = "attack_path_stages"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    attack_path_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False, index=True)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    scenario_id: Mapped[str] = mapped_column(String(255), nullable=False)
    source_asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("synthetic_assets.id", ondelete="RESTRICT"), nullable=False)
    destination_asset_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("synthetic_assets.id", ondelete="RESTRICT"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending", index=True)
    # pending, validating, running, completed, failed, skipped
    prerequisites: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    attack_run_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("attack_runs.id", ondelete="SET NULL"), nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(nullable=True)
    stage_metadata: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    simulation_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_simulated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Relationships
    attack_path: Mapped["AttackPath"] = relationship("AttackPath", back_populates="stages")
    source_asset: Mapped["SyntheticAsset"] = relationship("SyntheticAsset", foreign_keys=[source_asset_id])
    destination_asset: Mapped[Optional["SyntheticAsset"]] = relationship("SyntheticAsset", foreign_keys=[destination_asset_id])
    attack_run: Mapped[Optional["AttackRun"]] = relationship("AttackRun")

