"""Application configuration managed via Pydantic Settings.

Keeps configuration and environment variable loading strictly separate from application logic.
Sensitive credentials and secrets are loaded from the environment and never hardcoded.
"""

from functools import lru_cache
from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """AegisMesh API application settings."""

    PROJECT_NAME: str = "Kavach AI API"
    VERSION: str = "2.0.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    DOCS_URL: str = "/docs"
    OPENAPI_URL: str = "/openapi.json"

    # PostgreSQL Database settings
    POSTGRES_USER: str = Field(
        default="aegis",
        validation_alias=AliasChoices("POSTGRES_USER", "DB_USER"),
    )
    POSTGRES_PASSWORD: str = Field(
        default="",
        validation_alias=AliasChoices("POSTGRES_PASSWORD", "DB_PASSWORD"),
    )
    POSTGRES_SERVER: str = Field(
        default="localhost",
        validation_alias=AliasChoices("POSTGRES_SERVER", "POSTGRES_HOST", "DB_HOST"),
    )
    POSTGRES_PORT: int = Field(
        default=5433,
        validation_alias=AliasChoices("POSTGRES_PORT", "DB_PORT"),
    )
    POSTGRES_DB: str = Field(
        default="aegismesh",
        validation_alias=AliasChoices("POSTGRES_DB", "DB_NAME"),
    )
    DATABASE_URL: str | None = None

    # Redis settings
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for async client",
    )

    # Celery settings
    CELERY_BROKER_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Celery message broker URL",
    )
    CELERY_RESULT_BACKEND: str = Field(
        default="redis://localhost:6379/1",
        description="Celery task result storage backend URL",
    )

    # Authentication & JWT settings
    JWT_SECRET_KEY: str = Field(
        default="aegismesh-dev-secret-key-must-be-replaced-in-production-min32bytes!",
        validation_alias=AliasChoices("JWT_SECRET_KEY", "SECRET_KEY"),
        description="HMAC secret key used for signing JWTs",
    )
    JWT_ALGORITHM: str = Field(
        default="HS256",
        description="Cryptographic algorithm for JWT signing",
    )
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=30,
        description="Access token validity lifetime in minutes",
    )
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
        default=7,
        description="Refresh token validity lifetime in days",
    )
    PUBLIC_REGISTRATION_ENABLED: bool = Field(
        default=True,
        description="Whether public self-registration is permitted",
    )

    # Open Policy Agent (OPA) settings
    OPA_URL: str = Field(
        default="http://localhost:8181",
        validation_alias=AliasChoices("OPA_URL", "OPA_HOST"),
        description="Open Policy Agent service endpoint URL",
    )
    OPA_POLICY_PATH: str = Field(
        default="/v1/data/aegis/decision",
        description="OPA data endpoint for evaluating AegisMesh authorization decisions",
    )

    # Model Context Protocol (MCP) Server settings
    MCP_SERVER_HOST: str = Field(
        default="127.0.0.1",
        validation_alias=AliasChoices("MCP_SERVER_HOST", "MCP_HOST"),
        description="Host interface for the dedicated MCP server process (defaults to loopback)",
    )
    MCP_SERVER_PORT: int = Field(
        default=8001,
        validation_alias=AliasChoices("MCP_SERVER_PORT", "MCP_PORT"),
        description="Port for the dedicated MCP server process",
    )
    MCP_SERVER_PATH: str = Field(
        default="/mcp",
        description="Endpoint path for Streamable HTTP transport",
    )
    MCP_SERVER_NAME: str = Field(
        default="aegismesh-mcp",
        description="Name identifier of the AegisMesh MCP server",
    )
    MCP_SERVER_VERSION: str = Field(
        default="2.0.0",
        description="Version string of the AegisMesh MCP server",
    )

    # Gemini AI Provider & Intelligence Gateway settings
    GEMINI_API_KEY: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GEMINI_API_KEY", "GOOGLE_API_KEY"),
        description="API key for authenticating with Google Gemini AI",
    )
    GEMINI_MODEL: str = Field(
        default="gemini-2.5-flash",
        validation_alias=AliasChoices("GEMINI_MODEL", "GEMINI_MODEL_ID"),
        description="Default Gemini model identifier for intelligence generation",
    )
    GEMINI_ENABLED: bool = Field(
        default=False,
        validation_alias=AliasChoices("GEMINI_ENABLED"),
        description="Master switch to permit calls to Google Gemini AI provider",
    )
    GEMINI_TIMEOUT_SECONDS: int = Field(
        default=30,
        validation_alias=AliasChoices("GEMINI_TIMEOUT_SECONDS"),
        description="Timeout in seconds for outbound Gemini provider calls",
    )
    GEMINI_MAX_RETRIES: int = Field(
        default=2,
        validation_alias=AliasChoices("GEMINI_MAX_RETRIES"),
        description="Maximum retry count for transient Gemini provider errors",
    )
    GEMINI_MAX_OUTPUT_TOKENS: int = Field(
        default=2048,
        validation_alias=AliasChoices("GEMINI_MAX_OUTPUT_TOKENS"),
        description="Maximum output token budget for Gemini responses",
    )

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        """Constructs database URL and validates security invariants."""
        if not self.DATABASE_URL:
            self.DATABASE_URL = (
                f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
                f"@{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
            )

        # Disallow insecure JWT algorithm 'none'
        if self.JWT_ALGORITHM.lower() == "none":
            raise ValueError("JWT_ALGORITHM cannot be 'none'")

        # Ensure strong key in production
        if self.ENVIRONMENT == "production":
            if "dev-secret" in self.JWT_SECRET_KEY or len(self.JWT_SECRET_KEY) < 32:
                raise ValueError("JWT_SECRET_KEY must be a secure, random >=32 character key in production")

        return self


@lru_cache
def get_settings() -> Settings:
    """Returns a cached instance of application Settings."""
    return Settings()


settings = get_settings()
