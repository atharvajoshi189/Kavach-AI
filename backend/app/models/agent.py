"""SQLAlchemy model representing an autonomous security agent entity."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
import uuid
from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.campaign import Campaign
    from app.models.tool_action import ToolAction


class Agent(Base):
    """Autonomous agent definition with capabilities and operational bounds."""

    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    agent_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    capabilities: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="idle",
    )
    environment: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="sandbox",
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
    campaigns: Mapped[list["Campaign"]] = relationship(
        "Campaign",
        back_populates="agent",
    )
    tool_actions: Mapped[list["ToolAction"]] = relationship(
        "ToolAction",
        back_populates="agent",
    )

    def __repr__(self) -> str:
        return f"<Agent {self.name} (type={self.agent_type}, status={self.status})>"

