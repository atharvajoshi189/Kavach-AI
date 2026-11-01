"""External integration framework for AegisMesh 2.0 / Kavach AI.

Provides modular, secure provider abstractions and integration registries for
external platforms (Email, File Storage, Cloud, SIEM).
"""

from app.integrations.base import BaseEmailProvider, DeliveryResult, ProviderStatus
from app.integrations.registry import IntegrationRegistry, integration_registry

__all__ = [
    "BaseEmailProvider",
    "DeliveryResult",
    "ProviderStatus",
    "IntegrationRegistry",
    "integration_registry",
]
