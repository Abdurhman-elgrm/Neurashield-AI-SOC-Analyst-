from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import structlog
from anthropic import AsyncAnthropic, APIError, RateLimitError

log = structlog.get_logger(__name__)


@dataclass
class ModelState:
    name: str
    error_count: int = 0
    cooldown_until: datetime | None = None

    def is_available(self) -> bool:
        if self.cooldown_until is None:
            return True
        if datetime.now(tz=timezone.utc) >= self.cooldown_until:
            self.cooldown_until = None
            self.error_count = 0
            return True
        return False

    def record_error(self) -> None:
        self.error_count += 1
        if self.error_count >= 3:
            self.cooldown_until = datetime.now(tz=timezone.utc) + timedelta(minutes=10)
            log.warning("llm_model_cooldown", model=self.name, until=str(self.cooldown_until))

    def record_success(self) -> None:
        self.error_count = 0
        self.cooldown_until = None


class LLMManager:
    def __init__(self, api_key: str) -> None:
        self._client = AsyncAnthropic(api_key=api_key)
        self._models = [
            ModelState(name="claude-haiku-4-5-20251001"),
            ModelState(name="claude-sonnet-4-6"),
        ]

    async def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        max_tokens: int = 1024,
        model_override: str | None = None,
    ) -> str:
        """Generate a response. Tries primary model first, falls back on error."""
        if model_override:
            t0 = time.monotonic()
            try:
                response = await self._client.messages.create(
                    model=model_override,
                    max_tokens=max_tokens,
                    system=system_prompt,
                    messages=[{"role": "user", "content": prompt}],
                )
                latency = time.monotonic() - t0
                log.info(
                    "llm_call_success",
                    model=model_override,
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    latency_ms=int(latency * 1000),
                )
                return response.content[0].text
            except (RateLimitError, APIError) as exc:
                raise RuntimeError(f"Model {model_override} unavailable: {exc}") from exc

        last_exc: Exception = RuntimeError("No models configured")
        for model_state in self._models:
            if not model_state.is_available():
                continue
            t0 = time.monotonic()
            try:
                response = await self._client.messages.create(
                    model=model_state.name,
                    max_tokens=max_tokens,
                    system=system_prompt,
                    messages=[{"role": "user", "content": prompt}],
                )
                latency = time.monotonic() - t0
                model_state.record_success()
                log.info(
                    "llm_call_success",
                    model=model_state.name,
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    latency_ms=int(latency * 1000),
                )
                return response.content[0].text
            except (RateLimitError, APIError) as exc:
                model_state.record_error()
                last_exc = exc
                log.warning("llm_call_failed", model=model_state.name, error=str(exc)[:120])
                continue

        raise RuntimeError(f"All LLM models unavailable. Last error: {last_exc}")

    async def health(self) -> dict:
        """Return current model states for monitoring."""
        return {
            "models": [
                {
                    "name": m.name,
                    "available": m.is_available(),
                    "error_count": m.error_count,
                    "cooldown_until": m.cooldown_until.isoformat() if m.cooldown_until else None,
                }
                for m in self._models
            ]
        }


_manager: LLMManager | None = None


def get_llm_manager() -> LLMManager:
    global _manager
    if _manager is None:
        from app.core.config import get_settings
        settings = get_settings()
        if not settings.ANTHROPIC_API_KEY:
            raise RuntimeError("ANTHROPIC_API_KEY not configured")
        _manager = LLMManager(api_key=settings.ANTHROPIC_API_KEY)
    return _manager
