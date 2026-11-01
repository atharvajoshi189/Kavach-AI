"""Google Gemini AI Provider implementation using the official google-genai SDK."""

import asyncio
import json
import logging
import re
import time
from typing import Any, Optional, Type
from pydantic import BaseModel

from app.ai.providers.base import (
    AIAuthenticationError,
    AIProviderError,
    AIProviderTimeoutError,
    AIProviderUnavailableError,
    AIRateLimitError,
    AIValidationError,
    BaseAIProvider,
)
from app.core.config import settings

logger = logging.getLogger(__name__)

# Pattern to extract JSON if enclosed in markdown code fences
JSON_BLOCK_REGEX = re.compile(r"```(?:json)?\s*([\s\S]*?)\s*```")


class GeminiProvider(BaseAIProvider):
    """Integrates Google Gemini models for cybersecurity intelligence analysis."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_name: Optional[str] = None,
        enabled: Optional[bool] = None,
        timeout_seconds: Optional[int] = None,
        max_retries: Optional[int] = None,
        max_output_tokens: Optional[int] = None,
    ):
        self._api_key = api_key if api_key is not None else settings.GEMINI_API_KEY
        self._model_name = model_name or settings.GEMINI_MODEL
        self._enabled = enabled if enabled is not None else settings.GEMINI_ENABLED
        self._timeout_seconds = (
            timeout_seconds if timeout_seconds is not None else settings.GEMINI_TIMEOUT_SECONDS
        )
        self._max_retries = (
            max_retries if max_retries is not None else settings.GEMINI_MAX_RETRIES
        )
        self._max_output_tokens = (
            max_output_tokens
            if max_output_tokens is not None
            else settings.GEMINI_MAX_OUTPUT_TOKENS
        )
        self._client: Any = None

    @property
    def provider_name(self) -> str:
        return "gemini"

    @property
    def model_name(self) -> str:
        return self._model_name

    def is_available(self) -> bool:
        """Returns True only when Gemini is explicitly enabled and API key is set."""
        return bool(self._enabled and self._api_key and self._api_key.strip())

    def _get_client(self) -> Any:
        """Initializes or returns the official google-genai client."""
        if not self.is_available():
            raise AIProviderUnavailableError(
                "Gemini AI provider is not enabled or API key is missing.",
                provider=self.provider_name,
            )
        if self._client is None:
            try:
                from google import genai

                self._client = genai.Client(api_key=self._api_key)
            except Exception as e:
                logger.error("Failed to initialize Google Gen AI client: %s", type(e).__name__)
                raise AIProviderUnavailableError(
                    f"Initialization failure: {type(e).__name__}",
                    provider=self.provider_name,
                ) from e
        return self._client

    async def generate_structured_response(
        self,
        system_instruction: str,
        prompt: str,
        response_schema: Optional[Type[BaseModel]] = None,
        timeout_seconds: Optional[int] = None,
    ) -> tuple[dict[str, Any], Optional[int], Optional[int], float]:
        """Queries Gemini with structured output requirements and timing/token telemetry."""
        if not self.is_available():
            raise AIProviderUnavailableError(
                "Gemini provider is not available or disabled by configuration.",
                provider=self.provider_name,
            )

        client = self._get_client()
        timeout = timeout_seconds or self._timeout_seconds

        from google.genai import types

        config_kwargs: dict[str, Any] = {
            "system_instruction": system_instruction,
            "response_mime_type": "application/json",
            "temperature": 0.1,
            "max_output_tokens": self._max_output_tokens,
        }
        if response_schema is not None:
            config_kwargs["response_schema"] = response_schema

        config = types.GenerateContentConfig(**config_kwargs)

        last_exception: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            start_time = time.perf_counter()
            try:
                # Wrap with asyncio.wait_for for strict timeout enforcement
                coro = client.aio.models.generate_content(
                    model=self._model_name,
                    contents=prompt,
                    config=config,
                )
                response = await asyncio.wait_for(coro, timeout=float(timeout))
                latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)

                prompt_tokens: Optional[int] = None
                completion_tokens: Optional[int] = None
                if hasattr(response, "usage_metadata") and response.usage_metadata:
                    prompt_tokens = getattr(response.usage_metadata, "prompt_token_count", None)
                    completion_tokens = getattr(
                        response.usage_metadata, "candidates_token_count", None
                    )

                # Parse JSON payload
                parsed_data = self._parse_response_content(response)
                return parsed_data, prompt_tokens, completion_tokens, latency_ms

            except asyncio.TimeoutError as e:
                latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                logger.warning("Gemini call timed out after %ss (attempt %d/%d)", timeout, attempt + 1, self._max_retries + 1)
                last_exception = AIProviderTimeoutError(
                    f"Gemini provider call exceeded deadline of {timeout}s",
                    provider=self.provider_name,
                )
            except Exception as e:
                latency_ms = round((time.perf_counter() - start_time) * 1000.0, 2)
                err_str = str(e).lower()
                err_type = type(e).__name__

                if "429" in err_str or "resource_exhausted" in err_str or "quota" in err_str:
                    logger.warning("Gemini rate limit exceeded: %s", err_type)
                    last_exception = AIRateLimitError(
                        "Gemini rate limit or quota exceeded.",
                        provider=self.provider_name,
                    )
                elif "401" in err_str or "403" in err_str or "api_key" in err_str:
                    logger.error("Gemini authentication failure: %s", err_type)
                    last_exception = AIAuthenticationError(
                        "Gemini authentication failed. Verify API key configuration.",
                        provider=self.provider_name,
                    )
                    # No retry on auth errors
                    raise last_exception
                elif isinstance(e, (AIValidationError, json.JSONDecodeError)):
                    logger.warning("Gemini returned invalid structured output: %s", err_type)
                    last_exception = AIValidationError(
                        f"Failed to parse structured JSON: {str(e)}",
                        provider=self.provider_name,
                    )
                else:
                    logger.warning("Gemini invocation error (%s): %s", err_type, err_str)
                    last_exception = AIProviderError(
                        f"Gemini provider invocation error: {err_type}",
                        provider=self.provider_name,
                    )

                if attempt < self._max_retries:
                    await asyncio.sleep(0.5 * (2**attempt))

        if last_exception:
            raise last_exception
        raise AIProviderError("Gemini provider failed after retries.", provider=self.provider_name)

    def _parse_response_content(self, response: Any) -> dict[str, Any]:
        """Extracts and parses JSON dictionary from Gemini response object."""
        # 1. Check if parsed Pydantic object is already present on response
        if hasattr(response, "parsed") and response.parsed is not None:
            if isinstance(response.parsed, BaseModel):
                return response.parsed.model_dump()
            if isinstance(response.parsed, dict):
                return response.parsed

        # 2. Extract text and parse JSON
        text = getattr(response, "text", "")
        if not text:
            raise AIValidationError("Gemini response contained empty text content.", provider=self.provider_name)

        clean_text = text.strip()
        match = JSON_BLOCK_REGEX.search(clean_text)
        if match:
            clean_text = match.group(1).strip()

        try:
            parsed = json.loads(clean_text)
            if not isinstance(parsed, dict):
                raise AIValidationError("Expected top-level JSON object from model.", provider=self.provider_name)
            return parsed
        except json.JSONDecodeError as exc:
            raise AIValidationError(f"Invalid JSON emitted by Gemini: {exc}", provider=self.provider_name) from exc

