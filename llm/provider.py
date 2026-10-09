"""Provider-agnostic LLM interface (spec 33).

    LLMProvider
    ├── OpenAI
    ├── Anthropic
    ├── Local (OpenAI-compatible endpoint)
    └── Disabled

The system must remain fully operational with the LLM disabled, so
``DisabledProvider`` is the default and is a first-class implementation rather
than an error path: it returns a structured refusal that the analyst layer
turns into the deterministic rationale.

No provider is imported until it is selected, so the dependency is genuinely
optional.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from core.config import MakarConfig


@dataclass
class LLMResponse:
    text: str
    provider: str
    model: str = ""
    available: bool = True
    error: str | None = None


@runtime_checkable
class LLMProvider(Protocol):
    name: str

    def complete(self, system: str, prompt: str, *, max_tokens: int, temperature: float) -> LLMResponse:
        ...


class DisabledProvider:
    """The default. Returns an explicit unavailable response."""

    name = "disabled"

    def complete(self, system: str, prompt: str, *, max_tokens: int, temperature: float) -> LLMResponse:
        return LLMResponse(
            text="",
            provider=self.name,
            available=False,
            error=(
                "The LLM analyst is disabled. Set MAKAR_LLM_PROVIDER and "
                "MAKAR_LLM_API_KEY to enable it; the deterministic explanation "
                "below is the system's own reasoning and is always available."
            ),
        )


class OpenAIProvider:
    name = "openai"

    def __init__(self, model: str, api_key: str, base_url: str | None = None) -> None:
        self.model = model or "gpt-4o-mini"
        self._api_key = api_key
        self._base_url = base_url

    def complete(self, system: str, prompt: str, *, max_tokens: int, temperature: float) -> LLMResponse:
        try:
            from openai import OpenAI
        except ImportError:
            return LLMResponse(
                "", self.name, self.model, False, "the openai package is not installed"
            )
        try:
            client = OpenAI(api_key=self._api_key, base_url=self._base_url)
            completion = client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            )
            return LLMResponse(
                completion.choices[0].message.content or "", self.name, self.model
            )
        except Exception as exc:  # noqa: BLE001 - never let the analyst break the API
            return LLMResponse("", self.name, self.model, False, str(exc))


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str, api_key: str, base_url: str | None = None) -> None:
        self.model = model or "claude-sonnet-4-5"
        self._api_key = api_key
        self._base_url = base_url

    def complete(self, system: str, prompt: str, *, max_tokens: int, temperature: float) -> LLMResponse:
        try:
            from anthropic import Anthropic
        except ImportError:
            return LLMResponse(
                "", self.name, self.model, False, "the anthropic package is not installed"
            )
        try:
            kwargs = {"api_key": self._api_key}
            if self._base_url:
                kwargs["base_url"] = self._base_url
            client = Anthropic(**kwargs)
            message = client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            text = "".join(
                block.text for block in message.content if getattr(block, "type", "") == "text"
            )
            return LLMResponse(text, self.name, self.model)
        except Exception as exc:  # noqa: BLE001
            return LLMResponse("", self.name, self.model, False, str(exc))


def build_provider(cfg: MakarConfig) -> LLMProvider:
    """Select a provider from config and environment.

    Environment wins over config so the same config file works with and
    without credentials present.
    """
    name = (os.environ.get("MAKAR_LLM_PROVIDER") or cfg.get("llm.provider", "disabled") or "disabled").lower()
    model = os.environ.get("MAKAR_LLM_MODEL") or cfg.get("llm.model", "") or ""
    api_key = os.environ.get("MAKAR_LLM_API_KEY", "")
    base_url = os.environ.get("MAKAR_LLM_BASE_URL") or None

    if name in ("disabled", "none", "off", ""):
        return DisabledProvider()
    if name == "openai":
        if not api_key:
            return DisabledProvider()
        return OpenAIProvider(model, api_key, base_url)
    if name == "anthropic":
        if not api_key:
            return DisabledProvider()
        return AnthropicProvider(model, api_key, base_url)
    if name == "local":
        # An OpenAI-compatible local server (llama.cpp, vLLM, Ollama).
        return OpenAIProvider(model or "local-model", api_key or "not-needed", base_url or "http://localhost:11434/v1")
    return DisabledProvider()
