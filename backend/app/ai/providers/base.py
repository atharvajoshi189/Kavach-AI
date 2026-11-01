"""Abstract base class and error hierarchies for AI model providers."""

from abc import ABC, abstractmethod
import logging
from typing import Any, Optional, Type
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class AIProviderError(Exception):
    """Base exception for all AI provider interactions."""

    def __init__(self, message: str, provider: str = "generic"):
        self.message = message
        self.provider = provider
        super().__init__(f"[{provider}] {message}")


class AIProviderUnavailableError(AIProviderError):
    """Raised when the AI provider is disabled, unconfigured, or unreachable."""
    pass


class AIAuthenticationError(AIProviderError):
    """Raised when provider credentials are invalid or missing."""
    pass


class AIProviderTimeoutError(AIProviderError):
    """Raised when an outbound AI call exceeds its allocated deadline."""
    pass


class AIRateLimitError(AIProviderError):
    """Raised when provider quotas or rate limits are exceeded."""
    pass


class AIValidationError(AIProviderError):
    """Raised when model output fails structural or semantic validation."""
    pass


class BaseAIProvider(ABC):
    """Abstract interface defining required provider capabilities."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Name of the provider implementation."""
        pass

    @property
    @abstractmethod
    def model_name(self) -> str:
        """Identifier of the default model."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Checks if the provider is fully configured, enabled, and ready."""
        pass

    @abstractmethod
    async def generate_structured_response(
        self,
        system_instruction: str,
        prompt: str,
        response_schema: Optional[Type[BaseModel]] = None,
        timeout_seconds: Optional[int] = None,
    ) -> tuple[dict[str, Any], Optional[int], Optional[int], float]:
        """Generates a structured dictionary response conforming to response_schema.

        Returns:
            Tuple of (parsed_dict, prompt_tokens, completion_tokens, latency_ms)
        """
        pass

