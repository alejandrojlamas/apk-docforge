from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import httpx

from apk_docforge.config import Settings, get_settings


SECRET_VALUE_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|client[_-]?secret)(['\"\s:=]+)([A-Za-z0-9_\-./+=]{8,})"
)


@dataclass(frozen=True)
class LLMResult:
    enabled: bool
    provider: str
    status: str
    content: str | None = None
    error: str | None = None
    model: str | None = None


class DeepSeekDocumentationClient:
    """Small DeepSeek Chat Completions client for bounded documentation summaries."""

    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()

    def available(self) -> bool:
        return (
            self.settings.documentation_provider.lower() == "deepseek"
            and bool(self.settings.deepseek_api_key)
        )

    def explain_unavailable(self) -> str:
        if self.settings.documentation_provider.lower() != "deepseek":
            return "Documentation provider is local."
        if not self.settings.deepseek_api_key:
            return "DeepSeek documentation is disabled because DEEPSEEK_API_KEY is not set."
        return "DeepSeek documentation provider is unavailable."

    def generate_markdown(self, bounded_context: dict[str, Any], timeout: int = 120) -> LLMResult:
        if not self.available():
            return LLMResult(
                enabled=False,
                provider="deepseek",
                status="disabled",
                error=self.explain_unavailable(),
                model=self.settings.deepseek_model,
            )
        payload = self._payload(bounded_context)
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(
                    f"{self.settings.deepseek_base_url.rstrip('/')}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.settings.deepseek_api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
                response.raise_for_status()
                body = response.json()
        except Exception as exc:
            return LLMResult(
                enabled=True,
                provider="deepseek",
                status="failed",
                error=str(exc),
                model=self.settings.deepseek_model,
            )
        content = (
            body.get("choices", [{}])[0]
            .get("message", {})
            .get("content")
        )
        return LLMResult(
            enabled=True,
            provider="deepseek",
            status="completed" if content else "empty",
            content=content,
            model=self.settings.deepseek_model,
        )

    def _payload(self, bounded_context: dict[str, Any]) -> dict[str, Any]:
        context_json = redact_secrets(json.dumps(bounded_context, ensure_ascii=False, indent=2))
        return {
            "model": self.settings.deepseek_model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Eres un redactor técnico de auditorías Android. Usa solo la evidencia JSON. "
                        "No inventes datos. Marca unknown cuando falte evidencia. "
                        "No propongas bypasses de login, pagos, DRM, licencias, certificate pinning ni controles de seguridad."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        "Genera documentación Markdown concisa y estructurada para esta app Android. "
                        "Incluye evidencia y confidence_score donde aplique.\n\n"
                        f"{context_json}"
                    ),
                },
            ],
            "temperature": 0.2,
            "stream": False,
        }


def redact_secrets(text: str) -> str:
    return SECRET_VALUE_RE.sub(r"\1\2[REDACTED]", text)
