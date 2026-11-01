"""SQLAlchemy model representing a security campaign execution run."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
import uuid
from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database.base import Base

if TYPE_CHECKING:
    from app.models.agent import Agent
    from app.models.attack_run import AttackRun
    from app.models.evaluation import Evaluation
    from app.models.incident import Incident
    from app.models.tool_action import ToolAction


class Campaign(Base):
    """Execution campaign coordinating agents, tool actions, and evaluations."""

    __tablename__ = "campaigns"

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
    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )
    trigger_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="pending",
    )
    environment: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="sandbox",
    )
    configuration: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    agent: Mapped[Optional["Agent"]] = relationship(
        "Agent",
        back_populates="campaigns",
    )
    attack_runs: Mapped[list["AttackRun"]] = relationship(
        "AttackRun",
        back_populates="campaign",
        passive_deletes="all",
    )
    tool_actions: Mapped[list["ToolAction"]] = relationship(
        "ToolAction",
        back_populates="campaign",
    )
    incidents: Mapped[list["Incident"]] = relationship(
        "Incident",
        back_populates="campaign",
    )
    evaluations: Mapped[list["Evaluation"]] = relationship(
        "Evaluation",
        back_populates="campaign",
        passive_deletes="all",
    )

    @property
    def sandbox_id(self) -> Optional[uuid.UUID]:
        """Convenience property returning the associated sandbox UUID if configured."""
        if not self.configuration:
            return None
        sid = self.configuration.get("sandbox_id")
        if sid:
            try:
                return uuid.UUID(str(sid))
            except (ValueError, TypeError):
                return None
        return None

    def __repr__(self) -> str:
        return f"<Campaign {self.name} (status={self.status}, env={self.environment})>"

