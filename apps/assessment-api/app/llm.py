"""Provider-neutral text-only model clients. Agents never get tools or credentials; they send text and get text back.

Providers: `ollama` (self-hosted), `openai` (Responses API), `vertex` (Gemini on Vertex AI) and `bedrock` (AWS adapters).
Select with TAAD_LLM_PROVIDER=vertex plus TAAD_VERTEX_MODEL / TAAD_VERTEX_LOCATION / GOOGLE_CLOUD_PROJECT.
"""
from __future__ import annotations

import os
from typing import Any

DEFAULT_VERTEX_MODEL = "gemini-2.5-flash"


class VertexModelClient:
    """Gemini via the google-genai SDK in Vertex mode (uses the Cloud Run service account; no API keys)."""

    def __init__(self, model_id: str | None = None, project: str | None = None, location: str | None = None,
                 client: Any = None) -> None:
        self.model_id = model_id or os.environ.get("TAAD_VERTEX_MODEL", DEFAULT_VERTEX_MODEL)
        if client is None:
            from google import genai  # lazy: optional dependency
            from google.genai import types
            client = genai.Client(vertexai=True, project=project or os.environ["GOOGLE_CLOUD_PROJECT"],
                                  location=location or os.environ.get("TAAD_VERTEX_LOCATION", "europe-west1"),
                                  http_options=types.HttpOptions(timeout=60_000))
        self.client = client

    def complete(self, system: str, user: str, max_tokens: int = 600) -> str:
        from google.genai import types
        cfg: dict[str, Any] = {"system_instruction": system, "temperature": 0, "max_output_tokens": max_tokens,
                               "response_mime_type": "application/json"}
        if "flash" in self.model_id:  # 2.5 "thinking" tokens would otherwise eat the output budget and truncate the JSON
            cfg["thinking_config"] = types.ThinkingConfig(thinking_budget=0)
        response = self.client.models.generate_content(model=self.model_id, contents=user,
                                                       config=types.GenerateContentConfig(**cfg))
        text = getattr(response, "text", None)
        if not text:
            raise ValueError("model response did not contain text")
        return text


def provider() -> str:
    """Active provider name, or '' when no model is configured (deterministic mode)."""
    explicit = os.environ.get("TAAD_LLM_PROVIDER", "").strip().lower()
    if explicit:
        return explicit
    if os.environ.get("TAAD_SWASKA_MODEL") == "bedrock" or os.environ.get("TRUSTOPS_AGENT_MODEL_ID", "").strip():
        return "bedrock"
    return ""


def vertex_client() -> VertexModelClient | None:
    return VertexModelClient() if provider() == "vertex" else None


class OpenAIModelClient:
    """Text-only Responses API adapter. Keys stay on the server; agents receive no tools or credentials."""

    def __init__(self, model_id: str | None = None, api_key: str | None = None, opener: Any = None) -> None:
        from pathlib import Path
        from urllib.request import HTTPRedirectHandler, build_opener

        self.model_id = model_id or os.environ.get("TAAD_OPENAI_MODEL", "gpt-6-luna")
        self.reasoning = os.environ.get("TAAD_OPENAI_REASONING", "none")
        key = api_key or os.environ.get("OPENAI_API_KEY", "")
        if not key and os.environ.get("OPENAI_API_KEY_FILE"):
            with Path(os.environ["OPENAI_API_KEY_FILE"]).open() as secret:
                key = secret.read(4097)
        self._key = key.strip()
        if not self._key or len(self._key) > 4096 or any(c in self._key for c in "\r\n"):
            raise ValueError("Configure a valid server-side OPENAI_API_KEY or OPENAI_API_KEY_FILE")

        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None  # Never forward the server credential to a redirected destination.

        self._opener = opener or build_opener(NoRedirect())

    def complete(self, system: str, user: str, max_tokens: int = 600) -> str:
        import json
        from urllib.error import HTTPError
        from urllib.request import Request

        if not 1 <= max_tokens <= 16000:
            raise ValueError("Output token budget must be between 1 and 16000")
        payload = {"model": self.model_id, "store": False, "instructions": system + "\nReturn one JSON object only.",
                   "input": user, "max_output_tokens": max_tokens, "reasoning": {"effort": self.reasoning},
                   "text": {"format": {"type": "json_object"}}}
        request = Request("https://api.openai.com/v1/responses", method="POST", data=json.dumps(payload).encode(),
                          headers={"Authorization": f"Bearer {self._key}", "Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=60) as response:
                raw = response.read(2_000_001)
        except HTTPError as exc:
            code = exc.code
            exc.close()
            raise RuntimeError(f"OpenAI request failed (HTTP {code}); check server credentials, model access and account quota") from None
        if len(raw) > 2_000_000:
            raise ValueError("OpenAI response exceeded the permitted size")
        result = json.loads(raw)
        if result.get("status") != "completed":
            raise ValueError("OpenAI response did not complete; no analysis was accepted")
        parts = []
        for item in result.get("output", []):
            if item.get("type") != "message":
                continue
            for block in item.get("content", []):
                if block.get("type") == "refusal":
                    raise ValueError("OpenAI declined this request; no analysis was accepted")
                if block.get("type") == "output_text" and isinstance(block.get("text"), str):
                    parts.append(block["text"])
        text = "".join(parts)
        if not isinstance(json.loads(text), dict):
            raise ValueError("OpenAI did not return a JSON object")
        return text


def configured_model_id() -> str | None:
    active = provider()
    if active == "ollama":
        return os.environ.get("TAAD_OLLAMA_MODEL", "qwen3:4b")
    if active == "openai":
        return os.environ.get("TAAD_OPENAI_MODEL", "gpt-6-luna")
    if active == "vertex":
        return os.environ.get("TAAD_VERTEX_MODEL", DEFAULT_VERTEX_MODEL)
    if active == "bedrock":
        return os.environ.get("TRUSTOPS_AGENT_MODEL_ID") or os.environ.get("TAAD_BEDROCK_MODEL_ID")
    return None



class OllamaModelClient:
    """Private co-located model. No provider key, cloud models, tools, redirects or outbound proxy."""

    def __init__(self, model_id: str | None = None, base_url: str | None = None, opener: Any = None) -> None:
        from urllib.parse import urlparse
        from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

        self.model_id = model_id or os.environ.get("TAAD_OLLAMA_MODEL", "qwen3:4b")
        self.base_url = (base_url or os.environ.get("TAAD_OLLAMA_URL", "http://127.0.0.1:11434")).rstrip("/")
        url = urlparse(self.base_url)
        if url.scheme != "http" or url.hostname not in ("localhost", "127.0.0.1", "::1", "ollama") or any(
                (url.username, url.password, url.path, url.query, url.fragment)):
            raise ValueError("Ollama must use the private loopback or Docker-network endpoint")
        if self.model_id.endswith(":cloud") or "/" in self.model_id:
            raise ValueError("Use an installed local model tag, not a cloud model")
        self.timeout = float(os.environ.get("TAAD_OLLAMA_TIMEOUT", "240"))
        if not 1 <= self.timeout <= 600:
            raise ValueError("Ollama timeout must be between 1 and 600 seconds")

        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        self._opener = opener or build_opener(ProxyHandler({}), NoRedirect())

    def complete(self, system: str, user: str, max_tokens: int = 600) -> str:
        return self._complete(system, user, max_tokens, "json")

    def complete_json(self, system: str, user: str, max_tokens: int = 600, *, schema: dict) -> str:
        import json
        return self._complete(system + "\nRequired output schema: " + json.dumps(schema), user, max_tokens, schema)

    def _complete(self, system: str, user: str, max_tokens: int, output_format) -> str:
        import json
        from urllib.error import HTTPError
        from urllib.request import Request

        if not 1 <= max_tokens <= 16000:
            raise ValueError("Output token budget must be between 1 and 16000")
        payload = {"model": self.model_id, "messages": [{"role": "system", "content": system + "\nReturn one JSON object only."},
                                                         {"role": "user", "content": user}],
                   "format": output_format, "stream": False, "think": False, "keep_alive": "10m",
                   "options": {"temperature": 0, "num_predict": max_tokens, "num_ctx": 32768}}
        request = Request(self.base_url + "/api/chat", method="POST", data=json.dumps(payload).encode(),
                          headers={"Content-Type": "application/json"})
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                raw = response.read(2_000_001)
        except HTTPError as exc:
            code = exc.code
            exc.close()
            raise RuntimeError(f"Self-hosted model request failed (HTTP {code}); check the model server and installed model") from None
        if len(raw) > 2_000_000:
            raise ValueError("Self-hosted model response exceeded the permitted size")
        result = json.loads(raw)
        if result.get("done") is not True or result.get("done_reason") != "stop":
            raise ValueError("Self-hosted model output was incomplete; no analysis was accepted")
        message = result.get("message", {})
        if message.get("tool_calls"):
            raise ValueError("Model tools are not permitted")
        text = message.get("content", "")
        if not isinstance(text, str) or not isinstance(json.loads(text), dict):
            raise ValueError("Self-hosted model did not return a JSON object")
        return text
