"""AegisMesh API Application Entry Point.

Initializes FastAPI with standard configurations, Swagger documentation,
lifespan event hooks, and routes.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import api_router
from app.core.config import settings
from app.core.lifecycle import lifespan


def create_application() -> FastAPI:
    """FastAPI application factory."""
    application = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.VERSION,
        docs_url=settings.DOCS_URL,
        openapi_url=settings.OPENAPI_URL,
        description="Autonomous AI Security Operations Platform",
        lifespan=lifespan,
    )

    # Attach CORS middleware for frontend access
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API v1 routes
    application.include_router(api_router, prefix=settings.API_V1_STR)

    @application.get(
        "/",
        tags=["Root"],
        summary="API Root Information",
        description="Returns basic application metadata and navigation links.",
    )
    async def root():
        return {
            "application": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "status": "online",
            "docs_url": settings.DOCS_URL,
            "health_url": f"{settings.API_V1_STR}/health",
        }

    return application


app = create_application()
