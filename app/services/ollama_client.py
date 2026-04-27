"""LLM client with Ollama (local) and Groq (cloud fallback).

Priority:
  1. Local Ollama daemon (http://localhost:11434) — no API key, fully private.
  2. Groq cloud API — requires GROQ_API_KEY env var. Used automatically when
     Ollama is not reachable, making the deployed demo work without any local
     setup for visitors.

Same public interface as before so callers (ai_agent, routes) are unchanged.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
OLLAMA_TIMEOUT_S = float(os.getenv("OLLAMA_TIMEOUT_S", "600"))
OLLAMA_WARMUP_TIMEOUT_S = float(os.getenv("OLLAMA_WARMUP_TIMEOUT_S", "300"))

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
GROQ_TIMEOUT_S = float(os.getenv("GROQ_TIMEOUT_S", "60"))


# ---------------------------------------------------------------------------
# Shared types
# ---------------------------------------------------------------------------


class OllamaError(RuntimeError):
    """Raised when no LLM backend is reachable or returns an error."""


@dataclass
class OllamaResult:
    """Structured result from a generation call (same shape for both backends)."""

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


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------


def _ollama_reachable() -> bool:
    try:
        with httpx.Client(timeout=3.0) as client:
            response = client.get(f"{OLLAMA_HOST}/api/tags")
            response.raise_for_status()
        return True
    except httpx.HTTPError:
        return False


def _groq_available() -> bool:
    return bool(GROQ_API_KEY)


def is_available() -> bool:
    """Return True if any LLM backend is usable (Ollama or Groq)."""
    return _ollama_reachable() or _groq_available()


def get_active_model() -> str:
    """Return the model name that will be used for the next generation."""
    if _ollama_reachable():
        return OLLAMA_MODEL
    if _groq_available():
        return GROQ_MODEL
    return OLLAMA_MODEL


def get_active_backend() -> str:
    """Return 'ollama' or 'groq' depending on which backend is active."""
    if _ollama_reachable():
        return "ollama"
    if _groq_available():
        return "groq"
    return "none"


# ---------------------------------------------------------------------------
# Ollama helpers (unchanged internals)
# ---------------------------------------------------------------------------

_WARMED_MODELS: set = set()


def warmup(model: Optional[str] = None) -> bool:
    """Load the Ollama model into memory. No-op when Groq is the active backend."""
    if not _ollama_reachable():
        return _groq_available()

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
    """Return installed model names. Returns the Groq model when Ollama is absent."""
    if _ollama_reachable():
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{OLLAMA_HOST}/api/tags")
                response.raise_for_status()
                data = response.json()
            return [m.get("name", "") for m in (data.get("models") or []) if m.get("name")]
        except httpx.HTTPError as exc:
            logger.warning("Failed to list Ollama models: %s", exc)
            return []
    if _groq_available():
        return [GROQ_MODEL]
    return []


# ---------------------------------------------------------------------------
# Groq backend
# ---------------------------------------------------------------------------


def _groq_chat_call(
    messages: List[Dict[str, str]],
    *,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: Optional[int] = None,
) -> OllamaResult:
    body: Dict[str, object] = {
        "model": model or GROQ_MODEL,
        "messages": messages,
        "temperature": temperature,
    }
    if max_tokens is not None:
        body["max_tokens"] = max_tokens

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    try:
        with httpx.Client(timeout=GROQ_TIMEOUT_S) as client:
            response = client.post(
                f"{GROQ_BASE_URL}/chat/completions",
                json=body,
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()
    except httpx.HTTPError as exc:
        raise OllamaError(f"Groq request failed: {exc}") from exc

    choices = data.get("choices") or [{}]
    text = (choices[0].get("message", {}).get("content") or "").strip()
    usage = data.get("usage") or {}
    return OllamaResult(
        text=text,
        model=data.get("model", str(body["model"])),
        prompt_tokens=usage.get("prompt_tokens"),
        completion_tokens=usage.get("completion_tokens"),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate(
    prompt: str,
    *,
    system: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: Optional[int] = None,
) -> OllamaResult:
    """Generate a completion. Uses Ollama if available, otherwise Groq."""
    if _ollama_reachable():
        return _ollama_generate(prompt, system=system, model=model,
                                temperature=temperature, max_tokens=max_tokens)
    if _groq_available():
        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        return _groq_chat_call(messages, model=model, temperature=temperature,
                               max_tokens=max_tokens)
    raise OllamaError(
        "No LLM backend available. Install Ollama locally or set GROQ_API_KEY."
    )


def chat(
    messages: List[Dict[str, str]],
    *,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: Optional[int] = None,
) -> OllamaResult:
    """Multi-turn chat. Uses Ollama if available, otherwise Groq."""
    if _ollama_reachable():
        return _ollama_chat(messages, model=model, temperature=temperature,
                            max_tokens=max_tokens)
    if _groq_available():
        return _groq_chat_call(messages, model=model, temperature=temperature,
                               max_tokens=max_tokens)
    raise OllamaError(
        "No LLM backend available. Install Ollama locally or set GROQ_API_KEY."
    )


def stream_generate(
    prompt: str,
    *,
    system: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.2,
) -> Iterable[str]:
    """Yield streamed text chunks. Falls back to a single chunk via Groq."""
    if _ollama_reachable():
        yield from _ollama_stream_generate(prompt, system=system, model=model,
                                           temperature=temperature)
        return
    if _groq_available():
        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        result = _groq_chat_call(messages, model=model, temperature=temperature)
        yield result.text
        return
    raise OllamaError(
        "No LLM backend available. Install Ollama locally or set GROQ_API_KEY."
    )


# ---------------------------------------------------------------------------
# Ollama internals (kept private — callers use generate/chat/stream_generate)
# ---------------------------------------------------------------------------


def _ollama_generate(
    prompt: str,
    *,
    system: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: Optional[int] = None,
) -> OllamaResult:
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


def _ollama_chat(
    messages: List[Dict[str, str]],
    *,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: Optional[int] = None,
) -> OllamaResult:
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


def _ollama_stream_generate(
    prompt: str,
    *,
    system: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.2,
) -> Iterable[str]:
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
