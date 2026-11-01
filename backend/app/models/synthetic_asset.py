"""SQLAlchemy model representing a synthetic target asset."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
import uuid

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

if TYPE_CHECKING:
    from app.models.sandbox import SandboxEnvironment


class SyntheticAsset(Base):
    """Synthetic asset representing fictional target infrastructure inside a sandbox."""

    __tablename__ = "synthetic_assets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    asset_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )  # server, database, web_application, api, network_device
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    environment: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="sandbox",
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="online",
        index=True,
    )
    hostname: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    ip_address: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
        index=True,
    )
    os_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    service_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    configuration: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    simulated_vulnerabilities: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    risk_level: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="low",
        index=True,
    )  # low, medium, high, critical
    connected_asset_ids: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
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

    # Relationships
    sandbox: Mapped["SandboxEnvironment"] = relationship(
        "SandboxEnvironment",
        back_populates="assets",
    )

