"""Output schema validation for AI responses."""

import logging
from typing import Any, Type, TypeVar
from pydantic import BaseModel, ValidationError
from app.ai.providers.base import AIValidationError

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)


def validate_ai_output(data: dict[str, Any], schema: Type[T]) -> T:
    """Validates raw dictionary output against a strict Pydantic model.

    Raises:
        AIValidationError if the dictionary fails schema constraints.
    """
    try:
        return schema.model_validate(data)
    except ValidationError as e:
        logger.warning("Output validation failed for %s: %s", schema.__name__, e.errors())
        raise AIValidationError(
            f"Output failed strict schema validation for {schema.__name__}: {e.error_count()} errors",
            provider="output_validator",
        ) from e

