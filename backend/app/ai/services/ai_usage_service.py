"""Aggregated telemetry and usage tracking for the AI Intelligence Gateway."""

import logging
from threading import Lock
from typing import Optional
from app.ai.schemas.ai_responses import AIUsageMetricsResponse
from app.core.config import settings

logger = logging.getLogger(__name__)


class AIUsageService:
    """Thread-safe usage monitoring tracking token consumption, latencies, and fallbacks."""

    def __init__(self):
        self._lock = Lock()
        self._total_requests = 0
        self._successful_requests = 0
        self._failed_requests = 0
        self._fallback_requests = 0
        self._total_tokens_used = 0
        self._prompt_tokens = 0
        self._completion_tokens = 0
        self._total_latency_ms = 0.0
        self._per_capability_counts: dict[str, int] = {}

    def record_request(
        self,
        capability: str,
        success: bool,
        fallback_used: bool,
        prompt_tokens: Optional[int] = None,
        completion_tokens: Optional[int] = None,
        latency_ms: float = 0.0,
    ) -> None:
        """Records an AI gateway operation."""
        with self._lock:
            self._total_requests += 1
            if success:
                self._successful_requests += 1
            else:
                self._failed_requests += 1

            if fallback_used:
                self._fallback_requests += 1

            if prompt_tokens:
                self._prompt_tokens += prompt_tokens
                self._total_tokens_used += prompt_tokens
            if completion_tokens:
                self._completion_tokens += completion_tokens
                self._total_tokens_used += completion_tokens

            self._total_latency_ms += max(0.0, latency_ms)
            self._per_capability_counts[capability] = (
                self._per_capability_counts.get(capability, 0) + 1
            )

    def get_metrics(self) -> AIUsageMetricsResponse:
        """Computes and returns aggregated AI usage metrics."""
        with self._lock:
            req_count = self._total_requests
            fallback_rate = (
                round((self._fallback_requests / req_count) * 100.0, 2)
                if req_count > 0
                else 0.0
            )
            avg_latency = (
                round(self._total_latency_ms / req_count, 2)
                if req_count > 0
                else 0.0
            )

            # Determine provider status
            if not settings.GEMINI_ENABLED:
                provider_status = "disabled"
            elif not settings.GEMINI_API_KEY:
                provider_status = "fallback_only"
            else:
                provider_status = "online"

            return AIUsageMetricsResponse(
                provider_status=provider_status,
                gemini_enabled=settings.GEMINI_ENABLED,
                gemini_model=settings.GEMINI_MODEL,
                total_requests=self._total_requests,
                successful_requests=self._successful_requests,
                failed_requests=self._failed_requests,
                fallback_requests=self._fallback_requests,
                fallback_rate_pct=fallback_rate,
                total_tokens_used=self._total_tokens_used,
                prompt_tokens=self._prompt_tokens,
                completion_tokens=self._completion_tokens,
                average_latency_ms=avg_latency,
                per_capability_counts=dict(self._per_capability_counts),
            )

    def reset(self) -> None:
        """Resets all metrics (primarily for clean testing)."""
        with self._lock:
            self._total_requests = 0
            self._successful_requests = 0
            self._failed_requests = 0
            self._fallback_requests = 0
            self._total_tokens_used = 0
            self._prompt_tokens = 0
            self._completion_tokens = 0
            self._total_latency_ms = 0.0
            self._per_capability_counts.clear()


# Global singleton instance
ai_usage = AIUsageService()

