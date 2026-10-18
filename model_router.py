from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class ProviderError(RuntimeError):
    pass


class RetryableProviderError(ProviderError):
    pass


class FatalProviderError(ProviderError):
    pass


class VerificationError(FatalProviderError):
    pass


class Capability(str, Enum):
    TEXT = "text"
    VISION = "vision"


@dataclass(frozen=True)
class LLMRequest:
    messages: list[dict[str, Any]]
    model: str | None = None
    capability: Capability = Capability.TEXT
    temperature: float | None = None
    max_tokens: int | None = None


@dataclass(frozen=True)
class LLMResponse:
    provider: str
    model: str
    text: str
    raw: dict[str, Any] = field(repr=False)


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    base_url: str
    model: str
    api_key: str | None = None
    capabilities: frozenset[Capability] = frozenset({Capability.TEXT})
    kind: str = "openai"
    timeout_seconds: float = 20.0


class HTTPTransport:
    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str],
        timeout: float,
    ) -> tuple[int, bytes]:
        request = urllib.request.Request(
            url=url,
            method="POST",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", **headers},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return int(response.status), response.read()
        except urllib.error.HTTPError as exc:
            return int(exc.code), exc.read()
        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            raise RetryableProviderError(f"network failure: {exc}") from exc


class Provider:
    def __init__(self, config: ProviderConfig, transport: HTTPTransport | None = None):
        self.config = config
        self.transport = transport or HTTPTransport()

    @property
    def name(self) -> str:
        return self.config.name

    def supports(self, capability: Capability) -> bool:
        return capability in self.config.capabilities

    def complete(self, request: LLMRequest) -> LLMResponse:
        if not self.supports(request.capability):
            raise FatalProviderError(
                f"{self.name} does not support capability={request.capability.value}"
            )
        if self.config.kind == "ollama":
            return self._complete_ollama(request)
        if self.config.kind == "openai":
            return self._complete_openai(request)
        raise FatalProviderError(f"unsupported provider kind={self.config.kind!r}")

    def _complete_openai(self, request: LLMRequest) -> LLMResponse:
        model = request.model or self.config.model
        payload: dict[str, Any] = {
            "model": model,
            "messages": request.messages,
            "stream": False,
        }
        if request.temperature is not None:
            payload["temperature"] = request.temperature
        if request.max_tokens is not None:
            payload["max_tokens"] = request.max_tokens

        headers: dict[str, str] = {}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        status, body = self.transport.post_json(
            self.config.base_url.rstrip("/") + "/chat/completions",
            payload,
            headers,
            self.config.timeout_seconds,
        )
        data = _decode_response(self.name, status, body)

        try:
            text = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise VerificationError(
                f"{self.name} returned an invalid OpenAI-compatible response"
            ) from exc

        if not isinstance(text, str) or not text.strip():
            raise VerificationError(f"{self.name} returned empty content")

        return LLMResponse(provider=self.name, model=model, text=text, raw=data)

    def _complete_ollama(self, request: LLMRequest) -> LLMResponse:
        model = request.model or self.config.model
        payload: dict[str, Any] = {
            "model": model,
            "messages": request.messages,
            "stream": False,
        }
        if request.temperature is not None:
            payload["options"] = {"temperature": request.temperature}

        status, body = self.transport.post_json(
            self.config.base_url.rstrip("/") + "/api/chat",
            payload,
            {},
            self.config.timeout_seconds,
        )
        data = _decode_response(self.name, status, body)

        try:
            text = data["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise VerificationError(
                f"{self.name} returned an invalid Ollama response"
            ) from exc

        if not isinstance(text, str) or not text.strip():
            raise VerificationError(f"{self.name} returned empty content")

        return LLMResponse(provider=self.name, model=model, text=text, raw=data)


def _decode_response(provider: str, status: int, body: bytes) -> dict[str, Any]:
    if status in {408, 409, 425, 429} or 500 <= status <= 599:
        raise RetryableProviderError(f"{provider} returned retryable HTTP {status}")
    if status < 200 or status >= 300:
        raise FatalProviderError(f"{provider} returned fatal HTTP {status}")

    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise VerificationError(f"{provider} returned invalid JSON") from exc

    if not isinstance(data, dict):
        raise VerificationError(f"{provider} returned a non-object JSON response")
    return data


class ModelRouter:
    def __init__(self, providers: Iterable[Provider]):
        self.providers = tuple(providers)
        if not self.providers:
            raise ValueError("ModelRouter requires at least one provider")

    def complete(self, request: LLMRequest) -> LLMResponse:
        eligible = [p for p in self.providers if p.supports(request.capability)]
        if not eligible:
            raise FatalProviderError(
                f"no provider supports capability={request.capability.value}"
            )

        failures: list[str] = []
        for provider in eligible:
            try:
                return provider.complete(request)
            except RetryableProviderError as exc:
                failures.append(f"{provider.name}: {exc}")
                continue
            except FatalProviderError:
                raise

        raise RetryableProviderError(
            "all eligible providers failed retryably: " + "; ".join(failures)
        )


def providers_from_environment() -> list[Provider]:
    providers: list[Provider] = []

    ollama_model = os.environ.get("OLLAMA_MODEL", "gpt-oss:20b")
    providers.append(
        Provider(
            ProviderConfig(
                name="ollama",
                base_url=os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"),
                model=ollama_model,
                kind="ollama",
                capabilities=frozenset({Capability.TEXT}),
                timeout_seconds=float(os.environ.get("OLLAMA_TIMEOUT_SECONDS", "8")),
            )
        )
    )

    specs = [
        (
            "groq",
            "GROQ_API_KEY",
            "https://api.groq.com/openai/v1",
            os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b"),
            {Capability.TEXT},
        ),
        (
            "cerebras",
            "CEREBRAS_API_KEY",
            "https://api.cerebras.ai/v1",
            os.environ.get("CEREBRAS_MODEL", "gpt-oss-120b"),
            {Capability.TEXT},
        ),
        (
            "openrouter",
            "OPENROUTER_API_KEY",
            "https://openrouter.ai/api/v1",
            os.environ.get("OPENROUTER_MODEL", "openai/gpt-oss-20b:free"),
            {Capability.TEXT},
        ),
        (
            "gemini",
            "GEMINI_OPENAI_API_KEY",
            os.environ.get(
                "GEMINI_OPENAI_BASE_URL",
                "https://generativelanguage.googleapis.com/v1beta/openai",
            ),
            os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"),
            {Capability.TEXT, Capability.VISION},
        ),
    ]

    for name, key_env, base_url, model, capabilities in specs:
        api_key = os.environ.get(key_env)
        if not api_key:
            continue
        providers.append(
            Provider(
                ProviderConfig(
                    name=name,
                    base_url=base_url,
                    model=model,
                    api_key=api_key,
                    kind="openai",
                    capabilities=frozenset(capabilities),
                    timeout_seconds=float(
                        os.environ.get(f"{name.upper()}_TIMEOUT_SECONDS", "20")
                    ),
                )
            )
        )

    return providers
