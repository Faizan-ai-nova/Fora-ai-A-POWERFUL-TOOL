"""
Concrete AI provider implementations.

Each provider is a thin wrapper that, once given a real API key, calls out
to the respective LLM API and asks it to return structured JSON findings.
Until a key is supplied, `is_configured` is False and the analyzer simply
skips the AI pass and relies on the deterministic rule engine.

All network calls are wrapped in try/except so a provider outage never
crashes a scan - it just quietly contributes zero extra findings.
"""

import json
import logging

from .base import AIProvider

logger = logging.getLogger(__name__)


AI_SYSTEM_PROMPT = """You are a senior application security engineer performing a static
code review. Analyze the given source code for security vulnerabilities including but not
limited to: SQL Injection, XSS, CSRF, hardcoded secrets, command injection, path traversal,
insecure deserialization, broken authentication, missing security headers, dangerous
functions, and OWASP Top 10 issues.

Respond ONLY with a JSON array of issue objects, each with exactly these keys:
title, category, severity (one of: critical, high, medium, low, info), owasp_reference,
description, why_dangerous, recommended_fix, secure_code_example, line_number.

If there are no issues, return an empty JSON array: []
"""


class OpenAIProvider(AIProvider):
    name = 'openai'

    def analyze(self, code: str, filename: str, language: str) -> list[dict]:
        if not self.is_configured:
            return []
        try:
            import openai
            client = openai.OpenAI(api_key=self.api_key)
            response = client.chat.completions.create(
                model='gpt-4o-mini',
                messages=[
                    {'role': 'system', 'content': AI_SYSTEM_PROMPT},
                    {'role': 'user', 'content': f'File: {filename}\nLanguage: {language}\n\n```\n{code[:8000]}\n```'},
                ],
                temperature=0.1,
                response_format={'type': 'json_object'},
            )
            content = response.choices[0].message.content
            return _safe_parse_json_list(content)
        except Exception as exc:  # pragma: no cover - network dependent
            logger.warning('OpenAI provider failed: %s', exc)
            return []


class GeminiProvider(AIProvider):
    name = 'gemini'

    def analyze(self, code: str, filename: str, language: str) -> list[dict]:
        if not self.is_configured:
            return []
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            prompt = f'{AI_SYSTEM_PROMPT}\n\nFile: {filename}\nLanguage: {language}\n\n```\n{code[:8000]}\n```'
            response = model.generate_content(prompt)
            return _safe_parse_json_list(response.text)
        except Exception as exc:  # pragma: no cover - network dependent
            logger.warning('Gemini provider failed: %s', exc)
            return []


class ClaudeProvider(AIProvider):
    name = 'claude'

    def analyze(self, code: str, filename: str, language: str) -> list[dict]:
        if not self.is_configured:
            return []
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=self.api_key)
            message = client.messages.create(
                model='claude-sonnet-4-6',
                max_tokens=2000,
                system=AI_SYSTEM_PROMPT,
                messages=[
                    {'role': 'user', 'content': f'File: {filename}\nLanguage: {language}\n\n```\n{code[:8000]}\n```'}
                ],
            )
            content = ''.join(block.text for block in message.content if hasattr(block, 'text'))
            return _safe_parse_json_list(content)
        except Exception as exc:  # pragma: no cover - network dependent
            logger.warning('Claude provider failed: %s', exc)
            return []


class GroqProvider(AIProvider):
    name = 'groq'

    def analyze(self, code: str, filename: str, language: str) -> list[dict]:
        if not self.is_configured:
            return []
        try:
            from groq import Groq
            client = Groq(api_key=self.api_key)
            response = client.chat.completions.create(
                model='llama-3.3-70b-versatile',
                messages=[
                    {'role': 'system', 'content': AI_SYSTEM_PROMPT},
                    {'role': 'user', 'content': f'File: {filename}\nLanguage: {language}\n\n```\n{code[:8000]}\n```'},
                ],
                temperature=0.1,
            )
            content = response.choices[0].message.content
            return _safe_parse_json_list(content)
        except Exception as exc:  # pragma: no cover - network dependent
            logger.warning('Groq provider failed: %s', exc)
            return []


class MockProvider(AIProvider):
    """
    Default provider - no external API calls, no key required.
    Returns an empty list so the analyzer relies entirely on the
    deterministic rule engine. Swap AI_PROVIDER env var to enable
    a real backend once you add an API key.
    """
    name = 'mock'

    @property
    def is_configured(self) -> bool:
        return False

    def analyze(self, code: str, filename: str, language: str) -> list[dict]:
        return []


def _safe_parse_json_list(text: str) -> list[dict]:
    if not text:
        return []
    text = text.strip()
    # Strip markdown code fences some models wrap JSON in
    if text.startswith('```'):
        text = text.strip('`')
        text = text.replace('json\n', '', 1)
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get('issues', data.get('findings', []))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, TypeError):
        logger.warning('Could not parse AI provider response as JSON')
        return []


PROVIDER_REGISTRY = {
    'mock': MockProvider,
    'openai': OpenAIProvider,
    'gemini': GeminiProvider,
    'claude': ClaudeProvider,
    'groq': GroqProvider,
}


def get_provider() -> AIProvider:
    """Factory: build the configured AI provider from the admin-managed
    AIConfiguration (if enabled), falling back to Django settings/env vars."""
    from django.conf import settings

    provider_name = getattr(settings, 'AI_PROVIDER', 'mock')

    try:
        from ..models import AIConfiguration
        config = AIConfiguration.objects.first()
        if config and config.use_database_override:
            provider_name = config.active_provider
    except Exception:
        # Table may not exist yet (e.g. before first migration) - fall back to env var
        pass

    provider_cls = PROVIDER_REGISTRY.get(provider_name, MockProvider)

    key_map = {
        'openai': settings.OPENAI_API_KEY,
        'gemini': settings.GEMINI_API_KEY,
        'claude': settings.ANTHROPIC_API_KEY,
        'groq': settings.GROQ_API_KEY,
        'mock': '',
    }
    api_key = key_map.get(provider_name, '')
    return provider_cls(api_key=api_key)
