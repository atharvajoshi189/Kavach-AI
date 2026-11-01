"""API router definitions for AegisMesh API v1."""

from fastapi import APIRouter
from app.api.ai import router as ai_router
from app.api.arena import router as arena_router
from app.api.attack_paths import router as attack_paths_router
from app.api.audit import router as audit_router
from app.api.auth import router as auth_router
from app.api.guardian import router as guardian_router
from app.api.health import router as health_router
from app.api.integrations_email import router as integrations_email_router
from app.api.jobs import router as jobs_router
from app.api.orchestration import router as orchestration_router
from app.api.red_team import router as red_team_router
from app.api.sandboxes import router as sandboxes_router
from app.api.security import router as security_router

api_router = APIRouter()
api_router.include_router(ai_router)
api_router.include_router(arena_router)
api_router.include_router(attack_paths_router)
api_router.include_router(audit_router)
api_router.include_router(auth_router)
api_router.include_router(guardian_router)
api_router.include_router(health_router, tags=["Health"])
api_router.include_router(integrations_email_router)
api_router.include_router(jobs_router)
api_router.include_router(orchestration_router)
api_router.include_router(red_team_router)
api_router.include_router(sandboxes_router)
api_router.include_router(security_router)

__all__ = ["api_router"]
