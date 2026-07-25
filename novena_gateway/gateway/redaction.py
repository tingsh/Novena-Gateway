"""Shared redaction helpers for customer-safe diagnostics."""

from copy import deepcopy


REDACTED = "[REDACTED]"
SENSITIVE_KEY_PARTS = (
    "password",
    "token",
    "claim_code",
    "claimcode",
    "secret",
    "privatekey",
    "private_key",
    "authorization",
    "bearer",
    "keyfile",
)


def is_sensitive_key(key) -> bool:
    key_text = str(key).replace("-", "_").lower()
    return any(part in key_text for part in SENSITIVE_KEY_PARTS)


def redact_secrets(value):
    """Return a deep redacted copy of dictionaries/lists containing secrets."""
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            if is_sensitive_key(key):
                result[key] = REDACTED if child not in (None, "") else child
            else:
                result[key] = redact_secrets(child)
        return result
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return deepcopy(value)


def redact_text(text: str) -> str:
    """Redact common inline secret assignments from log text."""
    if not isinstance(text, str):
        return text

    redacted = text
    for key in SENSITIVE_KEY_PARTS:
        for sep in ("=", ":"):
            marker = f"{key}{sep}"
            lower = redacted.lower()
            idx = lower.find(marker)
            while idx != -1:
                start = idx + len(marker)
                end = start
                while end < len(redacted) and redacted[end] not in (" ", ",", ";", "}", "]"):
                    end += 1
                redacted = redacted[:start] + REDACTED + redacted[end:]
                lower = redacted.lower()
                idx = lower.find(marker, start + len(REDACTED))
    return redacted


def redact_diagnostics(value):
    """Redact both sensitive keys and inline assignments in diagnostic evidence."""
    if isinstance(value, dict):
        return {
            key: (
                REDACTED
                if is_sensitive_key(key) and child not in (None, "")
                else redact_diagnostics(child)
            )
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [redact_diagnostics(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return deepcopy(value)
