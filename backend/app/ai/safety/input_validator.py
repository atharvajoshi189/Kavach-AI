"""Input sanitization and prompt injection defense."""

import re
from typing import Any

# Dangerous prompt injection patterns to neutralize
INJECTION_PATTERNS = [
    re.compile(r"(?i)ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions"),
    re.compile(r"(?i)system\s+prompt\s*override"),
    re.compile(r"(?i)you\s+are\s+now\s+(?:an?\s+)?(?:unfiltered|jailbroken|dan)"),
    re.compile(r"(?i)<\s*/?\s*system\s*>"),
    re.compile(r"(?i)###\s*(?:instruction|system|override):?"),
    re.compile(r"(?i)disregard\s+(?:the\s+)?(?:system|safety)\s+rules"),
    re.compile(r"(?i)override\s+(?:all\s+)?security\s+controls"),
    re.compile(r"(?i)execute\s+(?:bash|sh|cmd|powershell|sql|rm\s+-rf)"),
]

MAX_INPUT_TEXT_LENGTH = 10000
MAX_QUESTION_LENGTH = 1000


def sanitize_untrusted_text(text: str, max_length: int = MAX_INPUT_TEXT_LENGTH) -> str:
    """Sanitizes user or synthetic telemetry strings before prompt inclusion.

    - Truncates oversized input to prevent context exhaustion attacks.
    - Neutralizes known adversarial prompt injection directives.
    - Strips non-printable ASCII control characters.
    """
    if not text:
        return ""

    # Truncate to bound length
    sanitized = text[:max_length]

    # Strip dangerous ASCII control characters except standard whitespace
    sanitized = "".join(ch for ch in sanitized if ch in ("\n", "\r", "\t") or (ord(ch) >= 32 and ord(ch) != 127))

    # Neutralize injection directives with safe defanged placeholders
    for pattern in INJECTION_PATTERNS:
        sanitized = pattern.sub("[REDACTED_INJECTION_ATTEMPT]", sanitized)

    return sanitized.strip()


def sanitize_evidence_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Recursively sanitizes dictionary payloads used as evidence in prompts."""
    sanitized: dict[str, Any] = {}
    for key, value in payload.items():
        clean_key = str(key)[:128]
        if isinstance(value, str):
            sanitized[clean_key] = sanitize_untrusted_text(value, max_length=2000)
        elif isinstance(value, dict):
            sanitized[clean_key] = sanitize_evidence_payload(value)
        elif isinstance(value, list):
            sanitized[clean_key] = [
                sanitize_untrusted_text(item, max_length=1000) if isinstance(item, str)
                else sanitize_evidence_payload(item) if isinstance(item, dict)
                else item
                for item in value[:50]
            ]
        else:
            sanitized[clean_key] = value
    return sanitized


class InputValidator:
    """Class wrapper providing static sanitization methods."""

    sanitize_untrusted_text = staticmethod(sanitize_untrusted_text)
    sanitize_evidence_payload = staticmethod(sanitize_evidence_payload)


