"""Asynchronous client for interacting with Open Policy Agent (OPA)."""

import logging
import httpx
from app.core.config import settings
from app.security.schemas import AuthorizationDecision, PolicyInput

logger = logging.getLogger(__name__)

# Reusable asynchronous HTTP client for OPA evaluations
_opa_client: httpx.AsyncClient | None = None


def get_opa_client() -> httpx.AsyncClient:
    """Returns or initializes the shared httpx.AsyncClient for OPA."""
    global _opa_client
    if _opa_client is None or _opa_client.is_closed:
        _opa_client = httpx.AsyncClient(
            base_url=settings.OPA_URL,
            timeout=httpx.Timeout(connect=2.0, read=3.0, write=2.0, pool=5.0),
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=50),
        )
    return _opa_client


async def close_opa_client() -> None:
    """Gracefully closes the shared OPA client connection pool."""
    global _opa_client
    if _opa_client is not None and not _opa_client.is_closed:
        logger.info("Closing OPA HTTP client connection pool.")
        await _opa_client.aclose()
        _opa_client = None


async def check_opa_health() -> bool:
    """Probes the OPA service health endpoint."""
    try:
        client = get_opa_client()
        response = await client.get("/health")
        return response.status_code == 200
    except Exception as e:
        logger.error("OPA health probe failed: %s", type(e).__name__)
        return False


async def evaluate_policy(policy_input: PolicyInput) -> AuthorizationDecision:
    """Submits a policy evaluation envelope to OPA.

    Guarantees FAIL-CLOSED behavior: any transport failure, timeout, or unexpected
    response immediately yields a deny decision without exposing system internals.
    """
    client = get_opa_client()
    request_payload = {"input": policy_input.model_dump()}

    try:
        response = await client.post(
            settings.OPA_POLICY_PATH,
            json=request_payload,
        )

        if response.status_code == 200:
            data = response.json()
            result = data.get("result")
            if isinstance(result, dict) and "allowed" in result:
                return AuthorizationDecision(
                    allowed=bool(result.get("allowed", False)),
                    decision=str(result.get("decision", "deny")),
                    reason=str(result.get("reason", "Action not authorized by policy.")),
                    policy_version=str(result.get("policy_version", "1.0.0")),
                )
            logger.warning("OPA response missing structured decision document: %s", data)
        else:
            logger.error("OPA returned non-200 status code: %d", response.status_code)

    except (httpx.ConnectError, httpx.ConnectTimeout) as e:
        logger.critical("Failed to connect to OPA daemon at %s: %s", settings.OPA_URL, type(e).__name__)
    except httpx.TimeoutException as e:
        logger.critical("OPA policy evaluation timed out: %s", type(e).__name__)
    except Exception as e:
        logger.error("Unexpected error during OPA policy evaluation: %s", type(e).__name__)

    # Default Fail-Closed
    return AuthorizationDecision(
        allowed=False,
        decision="deny",
        reason="Authorization service unavailable (fail-closed)",
        policy_version="1.0.0",
    )

