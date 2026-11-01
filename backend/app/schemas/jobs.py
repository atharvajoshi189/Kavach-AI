"""Pydantic schemas for Celery job submission and status monitoring."""

from typing import Any
from pydantic import BaseModel, Field


class JobSubmissionResponse(BaseModel):
    """Response returned upon successfully enqueueing a background job."""

    task_id: str = Field(..., description="Unique Celery task identifier")
    status: str = Field(default="queued", description="Initial queueing state")


class JobStatusResponse(BaseModel):
    """Response returned when polling job state and results."""

    task_id: str = Field(..., description="Unique Celery task identifier")
    status: str = Field(..., description="Current Celery state (e.g. PENDING, STARTED, SUCCESS, FAILURE)")
    ready: bool = Field(..., description="Whether task execution has finished")
    successful: bool | None = Field(default=None, description="Whether the task succeeded, if finished")
    result: Any = Field(default=None, description="Result payload returned by task if completed")
    error: str | None = Field(default=None, description="Error message if task failed")

