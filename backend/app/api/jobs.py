"""Background jobs API endpoints for task dispatch and status retrieval."""

import logging
from celery.result import AsyncResult
from fastapi import APIRouter, Depends, HTTPException, status
from app.core.permissions import get_current_user, require_security_operator
from app.core.redis import redis_client
from app.models.user import User, UserRole
from app.schemas.jobs import JobStatusResponse, JobSubmissionResponse
from app.security.gateway import authorize_action
from app.workers.celery_app import celery_app
from app.workers.tasks import health_check_task

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/jobs", tags=["Jobs"])


@router.post(
    "/health-check",
    response_model=JobSubmissionResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Enqueue Background Health Check",
    description="Dispatches a demonstration health check task. Requires Security Operator role and Security Gateway policy approval.",
)
async def submit_health_check_job(
    current_user: User = Depends(require_security_operator),
) -> JobSubmissionResponse:
    """Enqueues health_check_task after passing RBAC and Security Gateway authorization."""
    # Centralized Security Gateway check through OPA
    decision = await authorize_action(
        user=current_user,
        operation="task.submit",
        capability="scan",
        resource_type="job",
        resource_id="health_check_task",
        environment="sandbox",
    )

    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Action prohibited by policy: {decision.reason}",
        )

    async_result = health_check_task.delay()
    logger.info("User [%s] enqueued task [%s] after gateway clearance", current_user.username, async_result.id)

    # Store task ownership in Redis with 24h TTL
    await redis_client.setex(f"job_owner:{async_result.id}", 86400, str(current_user.id))

    return JobSubmissionResponse(task_id=async_result.id, status="queued")


@router.get(
    "/{task_id}",
    response_model=JobStatusResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Background Job Status",
    description="Polls execution state. Caller must be the task owner or an administrator.",
)
async def get_job_status(
    task_id: str,
    current_user: User = Depends(get_current_user),
) -> JobStatusResponse:
    """Retrieves non-blocking status of a background task after enforcing ownership access control."""
    # Enforce task ownership: only owner or Admin can inspect
    task_owner = await redis_client.get(f"job_owner:{task_id}")
    if task_owner and task_owner != str(current_user.id) and current_user.role != UserRole.ADMIN:
        logger.warning(
            "User [%s] denied access to task [%s] owned by [%s]",
            current_user.username,
            task_id,
            task_owner,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: you do not have permission to inspect this task.",
        )

    try:
        async_result = AsyncResult(task_id, app=celery_app)
        state = async_result.state
        is_ready = async_result.ready()
        is_successful = async_result.successful() if is_ready else None

        result_payload = None
        error_msg = None

        if is_ready:
            if is_successful:
                result_payload = async_result.result
            else:
                error_msg = str(async_result.result) if async_result.result else "Task failed"

        return JobStatusResponse(
            task_id=task_id,
            status=state,
            ready=is_ready,
            successful=is_successful,
            result=result_payload,
            error=error_msg,
        )
    except Exception as e:
        logger.error("Failed to inspect task [%s]: %s", task_id, type(e).__name__)
        return JobStatusResponse(
            task_id=task_id,
            status="UNKNOWN",
            ready=False,
            successful=None,
            result=None,
            error="Could not retrieve task status",
        )
