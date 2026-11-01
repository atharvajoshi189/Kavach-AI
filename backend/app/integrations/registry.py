"""Integration provider registry for AegisMesh 2.0.

Provides controlled, deterministic discovery and lifecycle management of registered external service
providers. Protects against secret exposure and unauthorized provider instantiation.
"""

import logging
from typing import Dict, List, Optional
from app.integrations.base import BaseEmailProvider, ProviderStatus

logger = logging.getLogger("aegismesh.integrations.registry")


class IntegrationRegistry:
    """Thread-safe registry for external service providers."""

    def __init__(self) -> None:
        self._email_providers: Dict[str, BaseEmailProvider] = {}

    def register_email_provider(self, name: str, provider: BaseEmailProvider) -> None:
        """Registers an email provider adapter under a canonical identifier."""
        canonical_name = name.lower().strip()
        if not isinstance(provider, BaseEmailProvider):
            raise TypeError(f"Provider '{name}' must implement BaseEmailProvider")
        self._email_providers[canonical_name] = provider
        logger.info("Registered email provider adapter: '%s'", canonical_name)

    def get_email_provider(self, name: str) -> BaseEmailProvider:
        """Retrieves a registered email provider by canonical name."""
        canonical_name = name.lower().strip()
        if canonical_name not in self._email_providers:
            available = list(self._email_providers.keys())
            raise KeyError(
                f"Email provider '{name}' is not registered. Available providers: {available}"
            )
        return self._email_providers[canonical_name]

    def has_email_provider(self, name: str) -> bool:
        """Checks if an email provider is registered."""
        return name.lower().strip() in self._email_providers

    def list_email_providers(self) -> List[str]:
        """Lists canonical names of all registered email providers."""
        return sorted(list(self._email_providers.keys()))

    async def get_all_provider_statuses(self) -> Dict[str, ProviderStatus]:
        """Queries health status across all registered email providers."""
        statuses: Dict[str, ProviderStatus] = {}
        for name, provider in self._email_providers.items():
            try:
                statuses[name] = await provider.check_health()
            except Exception as e:
                logger.error("Failed to query health for provider '%s': %s", name, type(e).__name__)
                statuses[name] = ProviderStatus(
                    provider_name=name,
                    is_configured=False,
                    mode="unknown",
                    status="error",
                    details={"error": "Failed to determine provider health"},
                )
        return statuses


# Global integration registry singleton
integration_registry = IntegrationRegistry()
