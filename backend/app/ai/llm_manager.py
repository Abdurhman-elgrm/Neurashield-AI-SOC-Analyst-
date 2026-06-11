from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import structlog

log = structlog.get_logger(__name__)


@dataclass
class ModelState:
    name: str
    provider: str  # "groq" | "gemini"
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
    def __init__(self, groq_api_key: str, gemini_api_key: str) -> None:
        self._groq_key = groq_api_key
        self._gemini_key = gemini_api_key
        self._models = [
            ModelState(name="llama-3.3-70b-versatile", provider="groq"),
            ModelState(name="gemini-2.0-flash", provider="gemini"),
        ]
        self._groq_client = None
        self._gemini_client = None
        self._initialized = False

    def _init_clients(self) -> None:
        if self._initialized:
            return
        if self._groq_key:
            from groq import AsyncGroq
            self._groq_client = AsyncGroq(api_key=self._groq_key)
        if self._gemini_key:
            from google import genai
            self._gemini_client = genai.Client(api_key=self._gemini_key)
        self._initialized = True

    async def _call_groq(
        self,
        model_name: str,
        prompt: str,
        system_prompt: str,
        max_tokens: int,
    ) -> str:
        if not self._groq_client:
            raise RuntimeError("Groq client not initialized — GROQ_API_KEY missing")
        response = await self._groq_client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.2,
        )
        return response.choices[0].message.content or ""

    async def _call_gemini(
        self,
        prompt: str,
        system_prompt: str,
        max_tokens: int,
    ) -> str:
        if not self._gemini_client:
            raise RuntimeError("Gemini client not initialized — GEMINI_API_KEY missing")
        from google.genai import types
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        response = await self._gemini_client.aio.models.generate_content(
            model="gemini-2.0-flash",
            contents=full_prompt,
            config=types.GenerateContentConfig(
                max_output_tokens=max_tokens,
                temperature=0.2,
            ),
        )
        return response.text or ""

    async def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        max_tokens: int = 1024,
        model_override: str | None = None,
    ) -> str:
        """Generate a response. Tries Groq first, falls back to Gemini on error."""
        self._init_clients()
        start = time.monotonic()

        for model_state in self._models:
            if not model_state.is_available():
                continue
            try:
                if model_state.provider == "groq":
                    result = await self._call_groq(
                        model_state.name, prompt, system_prompt, max_tokens
                    )
                else:
                    result = await self._call_gemini(prompt, system_prompt, max_tokens)

                model_state.record_success()
                log.info(
                    "llm_generate_success",
                    model=model_state.name,
                    provider=model_state.provider,
                    latency_ms=round((time.monotonic() - start) * 1000),
                )
                return result

            except Exception as exc:
                model_state.record_error()
                log.warning(
                    "llm_model_error",
                    model=model_state.name,
                    provider=model_state.provider,
                    error=str(exc)[:200],
                )
                continue

        raise RuntimeError("All LLM models unavailable or misconfigured")

    async def health(self) -> dict:
        """Return current model states for monitoring."""
        return {
            "models": [
                {
                    "name": m.name,
                    "provider": m.provider,
                    "available": m.is_available(),
                    "error_count": m.error_count,
                    "cooldown_until": str(m.cooldown_until) if m.cooldown_until else None,
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
        if not settings.GROQ_API_KEY and not settings.GEMINI_API_KEY:
            raise RuntimeError(
                "No LLM API keys configured — set GROQ_API_KEY or GEMINI_API_KEY in .env"
            )
        _manager = LLMManager(
            groq_api_key=settings.GROQ_API_KEY,
            gemini_api_key=settings.GEMINI_API_KEY,
        )
    return _manager
