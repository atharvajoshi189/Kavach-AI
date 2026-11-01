"""SQLAlchemy model for persisting immutable AI analyses and forensic evidence."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional
import uuid

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base

if TYPE_CHECKING:
    from app.models.guardian import GuardianExecution
    from app.models.sandbox import SandboxEnvironment
    from app.models.user import User


class AIAnalysisRecord(Base):
    """Immutable record of an AI analysis or explanation generated for an AegisMesh entity."""

    __tablename__ = "ai_analysis_records"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    sandbox_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("sandbox_environments.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    guardian_execution_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("guardian_executions.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    analysis_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    source_entity_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    source_entity_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
        index=True,
    )
    source_version: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    provider: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="gemini",
    )
    model: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    prompt_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="v1.0",
    )
    response_content: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    evidence_references: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
    )
    fallback_used: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    fallback_reason: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
    )
    tokens_used: Mapped[Optional[int]] = mapped_column(
        Integer,
        nullable=True,
    )
    latency_ms: Mapped[Optional[float]] = mapped_column(
        Float,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    sandbox: Mapped["SandboxEnvironment"] = relationship("SandboxEnvironment")
    guardian_execution: Mapped[Optional["GuardianExecution"]] = relationship("GuardianExecution")
    creator: Mapped[Optional["User"]] = relationship("User")

    __table_args__ = (
        Index("ix_ai_analysis_sandbox_type", "sandbox_id", "analysis_type"),
        Index("ix_ai_analysis_source", "source_entity_id", "analysis_type"),
    )

