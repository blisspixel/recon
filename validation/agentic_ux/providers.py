"""Multi-provider chat adapter for agentic UX validation.

The harness needs to drive identical persona prompts across multiple
LLM providers (Anthropic, OpenAI, xAI Grok) so the v1.9.2 rubric
findings are not Anthropic-specific. Each provider's SDK is imported
lazily so installing only one of them is enough; selecting an
unavailable provider raises a clear ``ProviderError`` instead of an
``ImportError``.

Pricing table values are best-effort public defaults at the time of
authoring (May 2026). Operators are expected to override them via
``--input-price`` / ``--output-price`` flags on the runner, and the
report records realized usage straight from the API response so a
stale default never silently mis-states a run's cost.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence


Role = Literal["system", "user", "assistant"]


@dataclass(frozen=True)
class ChatMessage:
    """Single turn in a chat conversation."""

    role: Role
    content: str


@dataclass(frozen=True)
class ChatResponse:
    """Result of a single chat call.

    ``cost_usd`` is computed at the call site from realized usage so
    re-priced runs (e.g. a model with surprising output volume) report
    the actual spend rather than a pre-trip estimate.
    """

    text: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    model: str
    provider: str


class ProviderError(RuntimeError):
    """Raised when a provider cannot be constructed or its call fails."""


class ChatProvider(Protocol):
    """Minimal chat-completion contract the runner depends on."""

    name: str
    model: str

    def chat(
        self,
        system: str,
        messages: Sequence[ChatMessage],
        *,
        max_tokens: int,
    ) -> ChatResponse:
        """Submit a single chat completion and return a normalized response."""
        ...


# --- Pricing -----------------------------------------------------------------

# Per-million-token list prices in USD. Best-effort public values at the
# time of authoring; the runner accepts overrides on the command line.
PRICING_USD_PER_MTOK: dict[str, tuple[float, float]] = {
    # Anthropic
    "claude-opus-4-7": (15.0, 75.0),
    "claude-sonnet-4-6": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
    # OpenAI
    "gpt-5": (5.0, 15.0),
    "gpt-5-mini": (1.0, 4.0),
    "gpt-4.1": (2.0, 8.0),
    # xAI
    "grok-4": (3.0, 15.0),
    "grok-4-mini": (0.6, 2.4),
}


def estimate_cost(
    input_tokens: int,
    output_tokens: int,
    model: str,
    *,
    input_price: float | None = None,
    output_price: float | None = None,
) -> float:
    """Compute USD cost for a call given token counts and a model name.

    When the model is not in the pricing table and no overrides are
    supplied the function returns ``0.0`` rather than raising — it is
    used both for live cost reporting (where we want a number even on
    surprising model strings) and for tests (where a pricing miss
    should not be a failure).
    """
    if input_price is None or output_price is None:
        default_in, default_out = PRICING_USD_PER_MTOK.get(model, (0.0, 0.0))
        in_price = input_price if input_price is not None else default_in
        out_price = output_price if output_price is not None else default_out
    else:
        in_price = input_price
        out_price = output_price
    return (input_tokens * in_price + output_tokens * out_price) / 1_000_000


# --- Anthropic ---------------------------------------------------------------


class AnthropicProvider:
    """Adapter over the official ``anthropic`` SDK."""

    name = "anthropic"

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        input_price: float | None = None,
        output_price: float | None = None,
    ) -> None:
        try:
            import anthropic  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - exercised via mock in tests
            raise ProviderError(
                "anthropic SDK not installed. `pip install anthropic` to use this provider.",
            ) from exc

        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ProviderError(
                "ANTHROPIC_API_KEY is not set. Export it or pass --api-key.",
            )

        self.model = model
        self._client = anthropic.Anthropic(api_key=key)
        self._input_price = input_price
        self._output_price = output_price

    def chat(
        self,
        system: str,
        messages: Sequence[ChatMessage],
        *,
        max_tokens: int,
    ) -> ChatResponse:
        payload = [{"role": m.role, "content": m.content} for m in messages if m.role != "system"]
        try:
            response = self._client.messages.create(
                model=self.model,
                system=system,
                messages=payload,
                max_tokens=max_tokens,
            )
        except Exception as exc:  # pragma: no cover - real network failure path
            raise ProviderError(f"anthropic call failed: {exc}") from exc

        text = "".join(block.text for block in response.content if getattr(block, "type", "") == "text")
        usage = response.usage
        in_tok = int(getattr(usage, "input_tokens", 0))
        out_tok = int(getattr(usage, "output_tokens", 0))
        cost = estimate_cost(
            in_tok,
            out_tok,
            self.model,
            input_price=self._input_price,
            output_price=self._output_price,
        )
        return ChatResponse(
            text=text,
            input_tokens=in_tok,
            output_tokens=out_tok,
            cost_usd=cost,
            model=self.model,
            provider=self.name,
        )


# --- OpenAI / xAI ------------------------------------------------------------


class _OpenAICompatibleProvider:
    """Shared adapter for OpenAI-compatible chat APIs.

    The xAI Grok API is OpenAI-compatible apart from its base URL and
    auth header, so subclassing here keeps the parsing logic in one
    place. The two concrete classes below differ only in defaults.
    """

    name = "openai"
    default_base_url: str | None = None
    api_key_env: str = "OPENAI_API_KEY"

    def __init__(
        self,
        model: str,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        input_price: float | None = None,
        output_price: float | None = None,
    ) -> None:
        try:
            import openai  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - exercised via mock in tests
            raise ProviderError(
                "openai SDK not installed. `pip install openai` to use this provider.",
            ) from exc

        key = api_key or os.environ.get(self.api_key_env)
        if not key:
            raise ProviderError(
                f"{self.api_key_env} is not set. Export it or pass --api-key.",
            )

        self.model = model
        client_kwargs: dict[str, str] = {"api_key": key}
        url = base_url or self.default_base_url
        if url:
            client_kwargs["base_url"] = url
        self._client = openai.OpenAI(**client_kwargs)
        self._input_price = input_price
        self._output_price = output_price

    def chat(
        self,
        system: str,
        messages: Sequence[ChatMessage],
        *,
        max_tokens: int,
    ) -> ChatResponse:
        payload: list[dict[str, str]] = [{"role": "system", "content": system}]
        payload.extend({"role": m.role, "content": m.content} for m in messages if m.role != "system")

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=payload,
                max_tokens=max_tokens,
            )
        except Exception as exc:  # pragma: no cover - real network failure path
            raise ProviderError(f"{self.name} call failed: {exc}") from exc

        choice = response.choices[0]
        text = choice.message.content or ""
        usage = response.usage
        in_tok = int(getattr(usage, "prompt_tokens", 0))
        out_tok = int(getattr(usage, "completion_tokens", 0))
        cost = estimate_cost(
            in_tok,
            out_tok,
            self.model,
            input_price=self._input_price,
            output_price=self._output_price,
        )
        return ChatResponse(
            text=text,
            input_tokens=in_tok,
            output_tokens=out_tok,
            cost_usd=cost,
            model=self.model,
            provider=self.name,
        )


class OpenAIProvider(_OpenAICompatibleProvider):
    """Adapter over the official ``openai`` SDK."""

    name = "openai"
    api_key_env = "OPENAI_API_KEY"


class XAIProvider(_OpenAICompatibleProvider):
    """Adapter over xAI's OpenAI-compatible Grok API."""

    name = "xai"
    default_base_url = "https://api.x.ai/v1"
    api_key_env = "XAI_API_KEY"


# --- Registry ----------------------------------------------------------------

PROVIDER_REGISTRY: dict[str, type[ChatProvider]] = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "xai": XAIProvider,
}


def get_provider(
    name: str,
    model: str,
    **kwargs: object,
) -> ChatProvider:
    """Construct a provider by name. Raises ``ProviderError`` on misconfiguration."""
    cls = PROVIDER_REGISTRY.get(name)
    if cls is None:
        known = ", ".join(sorted(PROVIDER_REGISTRY))
        raise ProviderError(f"unknown provider {name!r}; expected one of: {known}")
    return cls(model=model, **kwargs)  # type: ignore[arg-type]
