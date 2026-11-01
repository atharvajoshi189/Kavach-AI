"""SQLAlchemy model tracking actions attempted or executed by agents and MCP tools."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
import uuid
from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.campaign import Campaign


class ToolAction(Base):
    """Granular action record detailing decisions, execution status, and audit context."""

    __tablename__ = "tool_actions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    agent_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("agents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    campaign_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action_name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    resource: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )
    decision: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    executed: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    environment: Mapped[str] = mapped_column(
        String(32),
        default="sandbox",
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    agent: Mapped[Optional["Agent"]] = relationship(
        "Agent",
        back_populates="tool_actions",
    )
    campaign: Mapped[Optional["Campaign"]] = relationship(
        "Campaign",
        back_populates="tool_actions",
    )

    def __repr__(self) -> str:
        return f"<ToolAction {self.action_name} on {self.resource} (decision={self.decision}, executed={self.executed})>"

