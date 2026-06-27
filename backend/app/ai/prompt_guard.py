"""Prompt injection defense for LLM inputs.

Guards both user-supplied chat messages and DB-sourced values embedded in system prompts.
"""

from __future__ import annotations

import re

# ─── Injection patterns ───────────────────────────────────────────────────────
# Combined set covering the most common prompt injection and jailbreak patterns.

_INJECTION_PATTERNS: list[str] = [
    r"ignore\s+(all\s+)?previous\s+instructions?",
    r"disregard\s+(all\s+)?previous\s+instructions?",
    r"forget\s+(all\s+)?previous\s+instructions?",
    r"forget\s+everything",
    r"you\s+are\s+now\s+",
    r"new\s+instructions?\s*:",
    r"override\s+(your\s+)?(instructions?|system\s+prompt)",
    r"system\s*prompt\s*:",
    r"<\s*system\s*>",
    r"<\s*/?\s*system\s*>",
    r"##\s*system",
    r"\[SYSTEM\]",
    r"act\s+as\s+(if\s+you\s+are\s+)?",
    r"pretend\s+(you\s+are|to\s+be)\s+",
    r"role\s*play\s+as\s+",
    r"jailbreak",
    r"DAN\s+mode",
    r"developer\s+mode",
    r"assistant\s*:",
    r"human\s*:",
    r"\bGPT\s*-?\s*4\b.*?(ignore|bypass)",
    r"---\s*new\s+session",
    r"==\s*new\s+conversation",
]

_INJECTION_RE = re.compile(
    "|".join(_INJECTION_PATTERNS),
    flags=re.IGNORECASE,
)

_MAX_USER_MESSAGE_LEN = 4000
_MAX_FIELD_LEN = 500


def sanitize_user_message(text: str, max_len: int = _MAX_USER_MESSAGE_LEN) -> str:
    """
    Sanitize a user-supplied chat message before passing to the LLM.
    - Truncates to max_len
    - Strips control characters that break prompt structure
    - Replaces injection patterns with [REDACTED]
    """
    text = text[:max_len]
    # Normalize invisible separators and special whitespace that could be used
    # to hide injection text from simple scanners.
    text = text.replace("\x00", "").replace("\r", " ")
    # Replace newlines with spaces to prevent multiline role injection
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = _INJECTION_RE.sub("[REDACTED]", text)
    return text.strip()


def sanitize_field(value: str | None, max_len: int = _MAX_FIELD_LEN) -> str | None:
    """Strip prompt injection attempts from a single data field embedded in a prompt."""
    if value is None:
        return None
    value = value[:max_len]
    value = value.replace("\n", " ").replace("\r", " ")
    value = _INJECTION_RE.sub("[REDACTED]", value)
    return value.strip() or None
