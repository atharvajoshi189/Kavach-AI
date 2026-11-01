"""Forensic, version-aware caching service for AI analyses."""

import hashlib
import json
import logging
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)


class AICacheService:
    """Provides high-performance in-memory caching keyed by entity versions."""

    def __init__(self, default_ttl_seconds: int = 3600):
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._default_ttl = default_ttl_seconds

    @staticmethod
    def build_cache_key(
        analysis_type: str,
        source_entity_id: str,
        source_version: str = "v1",
        model: str = "gemini-2.5-flash",
    ) -> str:
        """Derives a deterministic SHA-256 cache key including source version."""
        raw = f"{analysis_type}:{source_entity_id}:{source_version}:{model}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get(self, cache_key: str) -> Optional[dict[str, Any]]:
        """Retrieves cached response if present and not expired."""
        if cache_key not in self._cache:
            return None

        expiry, data = self._cache[cache_key]
        if time.time() > expiry:
            del self._cache[cache_key]
            return None

        logger.debug("AI analysis cache HIT for key %s", cache_key)
        return data

    def set(
        self,
        cache_key: str,
        data: dict[str, Any],
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Stores analysis response in cache with TTL."""
        ttl = ttl_seconds or self._default_ttl
        expiry = time.time() + ttl
        self._cache[cache_key] = (expiry, data)
        logger.debug("AI analysis cached with key %s (TTL: %ss)", cache_key, ttl)

    def invalidate(self, cache_key: str) -> None:
        """Removes a specific cache key."""
        self._cache.pop(cache_key, None)

    def clear(self) -> None:
        """Clears all cached entries."""
        self._cache.clear()


# Global singleton cache instance
ai_cache = AICacheService()

