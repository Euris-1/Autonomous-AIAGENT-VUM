"""Ollama HTTP client wrapper.

Talks to a locally-running Ollama daemon (default http://localhost:11434) using
the simple ``/api/generate`` and ``/api/chat`` endpoints. No external API calls,
no API keys, no outbound traffic - everything runs on the user's machine.

Why not the `ollama` Python package? Keeping this small keeps the deps tight
and the behavior explicit. We already have ``httpx`` for NVD/EPSS.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

import httpx

logger = logging.getLogger(__name__)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
# First-run model load on CPU can take 60-180s for an 8B parameter model.
# Give it real headroom; subsequent calls are much faster because the model
# stays resident in memory.
OLLAMA_TIMEOUT_S = float(os.getenv("OLLAMA_TIMEOUT_S", "600"))
OLLAMA_WARMUP_TIMEOUT_S = float(os.getenv("OLLAMA_WARMUP_TIMEOUT_S", "300"))


class OllamaError(RuntimeError):
    """Raised when the Ollama daemon is unreachable or returns an error."""


@dataclass
class OllamaResult:
    """Structured result from a generation call."""

    text: str
    model: str
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_duration_ms: Optional[float] = None

    @property
    def total_tokens(self) -> Optional[int]:
        if self.prompt_tokens is not None and self.completion_tokens is not None:
            return self.prompt_tokens + self.completion_tokens
        return None


def is_available() -> bool:
    """Return True if the Ollama daemon responds on the configured host."""
    try:
        with httpx.Client(timeout=3.0) as client:
            response = client.get(f"{OLLAMA_HOST}/api/tags")
            response.raise_for_status()
        return True
    except httpx.HTTPError:
        return False


_WARMED_MODELS: set = set()


def warmup(model: Optional[str] = None) -> bool:
    """Load the model into memory with a tiny throwaway prompt.

    Subsequent real requests are dramatically faster because Ollama keeps the
    weights resident. Idempotent - no-op if we've already warmed this model.
    """
    model_name = model or OLLAMA_MODEL
    if model_name in _WARMED_MODELS:
        return True
    try:
        with httpx.Client(timeout=OLLAMA_WARMUP_TIMEOUT_S) as client:
            response = client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={
                    "model": model_name,
                    "prompt": "hi",
                    "stream": False,
                    "options": {"num_predict": 1},
                    "keep_alive": "30m",
                },
            )
            response.raise_for_status()
        _WARMED_MODELS.add(model_name)
        return True
    except httpx.HTTPError as exc:
        logger.warning("Ollama warmup failed for %s: %s", model_name, exc)
        return False


def list_models() -> List[str]:
    """Return the names of models installed on the local Ollama daemon."""
    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.get(f"{OLLAMA_HOST}/api/tags")
            response.raise_for_status()
            data = response.json()
        return [m.get("name", "") for m in (data.get("models") or []) if m.get("name")]
    except httpx.HTTPError as exc:
        logger.warning("Failed to list Ollama models: %s", exc)
        return []


def generate(
    prompt: str,
    *,
    system: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: Optional[int] = None,
) -> OllamaResult:
    """Generate a completion from a single prompt.

    Uses the ``/api/generate`` endpoint with ``stream=False`` for a single
    JSON response. Raises :class:`OllamaError` if the daemon is unreachable or
    returns an error.
    """
    body: Dict[str, object] = {
        "model": model or OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature},
    }
    if system:
        body["system"] = system
    if max_tokens is not None:
        body["options"]["num_predict"] = max_tokens  # type: ignore[index]

    try:
        with httpx.Client(timeout=OLLAMA_TIMEOUT_S) as client:
            response = client.post(f"{OLLAMA_HOST}/api/generate", json=body)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPError as exc:
        raise OllamaError(f"Ollama request failed: {exc}") from exc

    text = (data.get("response") or "").strip()
    return OllamaResult(
        text=text,
        model=data.get("model", body["model"]),  # type: ignore[arg-type]
        prompt_tokens=data.get("prompt_eval_count"),
        completion_tokens=data.get("eval_count"),
        total_duration_ms=(
            data.get("total_duration", 0) / 1_000_000
            if data.get("total_duration")
            else None
        ),
    )


def chat(
    messages: List[Dict[str, str]],
    *,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: Optional[int] = None,
) -> OllamaResult:
    """Multi-turn chat via the ``/api/chat`` endpoint.

    ``messages`` follows the OpenAI-style ``[{"role": "user", "content": "..."}]``
    convention. Ollama supports ``system``, ``user``, and ``assistant`` roles.
    """
    body: Dict[str, object] = {
        "model": model or OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "options": {"temperature": temperature},
    }
    if max_tokens is not None:
        body["options"]["num_predict"] = max_tokens  # type: ignore[index]

    try:
        with httpx.Client(timeout=OLLAMA_TIMEOUT_S) as client:
            response = client.post(f"{OLLAMA_HOST}/api/chat", json=body)
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPError as exc:
        raise OllamaError(f"Ollama chat request failed: {exc}") from exc

    message = data.get("message") or {}
    text = (message.get("content") or "").strip()
    return OllamaResult(
        text=text,
        model=data.get("model", body["model"]),  # type: ignore[arg-type]
        prompt_tokens=data.get("prompt_eval_count"),
        completion_tokens=data.get("eval_count"),
        total_duration_ms=(
            data.get("total_duration", 0) / 1_000_000
            if data.get("total_duration")
            else None
        ),
    )


def stream_generate(
    prompt: str,
    *,
    system: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.2,
) -> Iterable[str]:
    """Yield streamed text chunks. Used by server-sent events for the UI."""
    body: Dict[str, object] = {
        "model": model or OLLAMA_MODEL,
        "prompt": prompt,
        "stream": True,
        "options": {"temperature": temperature},
    }
    if system:
        body["system"] = system

    try:
        with httpx.Client(timeout=OLLAMA_TIMEOUT_S) as client:
            with client.stream(
                "POST", f"{OLLAMA_HOST}/api/generate", json=body
            ) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    chunk = event.get("response")
                    if chunk:
                        yield chunk
                    if event.get("done"):
                        break
    except httpx.HTTPError as exc:
        raise OllamaError(f"Ollama stream failed: {exc}") from exc
