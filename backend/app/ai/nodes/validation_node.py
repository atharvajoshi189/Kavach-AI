"""Input validation node for LangGraph multi-agent security graph.

Neutralizes prompt injection attempts, validates reference IDs, and produces
sanitized execution context.
"""

import logging
from typing import Any

from app.ai.safety.input_validator import InputValidator, sanitize_untrusted_text
from app.ai.state.state import AegisAIState

logger = logging.getLogger("aegismesh.ai.nodes.validation")


async def input_validation_node(state: AegisAIState) -> dict[str, Any]:
    """Validates inputs, sanitizes freeform text, and verifies reference IDs."""
    logger.info("Executing input validation node for graph %s", state.get("graph_execution_id"))
    errors: list[str] = []

    user_query = state.get("user_query")
    sanitized_query = None
    if user_query:
        sanitized_query = sanitize_untrusted_text(user_query)
        if "[REDACTED_INJECTION_ATTEMPT]" in sanitized_query:
            logger.warning("Prompt injection pattern detected and neutralized in user_query")

    evidence = state.get("evidence_records", {})
    known_ids: set[str] = set()

    for category, items in evidence.items():
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict) and "id" in item:
                    known_ids.add(str(item["id"]))

    input_refs = state.get("input_reference_ids") or []
    invalid_refs = [ref for ref in input_refs if ref not in known_ids]
    if invalid_refs:
        logger.info("Some input references were not found in current sandbox: %s", invalid_refs)

    validated_context = {
        "valid_reference_count": len(input_refs) - len(invalid_refs),
        "unmatched_references": invalid_refs,
        "sanitized_query_present": bool(sanitized_query),
        "known_entity_count": len(known_ids),
    }

    return {
        "user_query": sanitized_query,
        "validated_context": validated_context,
    }

