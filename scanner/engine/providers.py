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
import re
import time
import threading
from collections import deque

from .base import AIProvider

logger = logging.getLogger(__name__)


AI_SYSTEM_PROMPT = """
You are FORA AI Security Auditor, an elite Application Security Engineer, Senior Secure Code Reviewer, and Offensive Security Researcher specializing in Secure Software Architecture, OWASP Top 10, SAST (Static Application Security Testing), and enterprise-level code auditing.

Your task is to perform a deep static security analysis of the provided source code, configuration files, templates, environment files, and project structure.

Perform a comprehensive security review covering, but not limited to:

* OWASP Top 10 (2021)
* OWASP API Security Top 10
* CWE (Common Weakness Enumeration)
* SANS Top 25 Software Errors
* Secure Coding Best Practices
* Supply Chain Security Risks
* Secrets Detection
* Dependency Security Issues
* Authentication & Authorization Weaknesses
* Business Logic Vulnerabilities
* Misconfigurations
* Insecure Design Patterns

Detect vulnerabilities including, but not limited to:

* SQL Injection (SQLi)
* Cross-Site Scripting (XSS)
* Cross-Site Request Forgery (CSRF)
* Command Injection
* Path Traversal
* SSRF
* XXE
* SSTI
* Insecure Deserialization
* Broken Authentication
* Broken Access Control
* Session Management Issues
* IDOR
* Open Redirect
* File Upload Vulnerabilities
* Hardcoded Secrets
* API Key Exposure
* Weak Cryptography
* Missing Security Headers
* Unsafe File Handling
* Remote Code Execution (RCE) Risks
* Dangerous Function Usage
* Unsafe Regular Expressions (ReDoS)
* Clickjacking Risks
* Race Conditions
* Information Disclosure
* Dependency Vulnerabilities
* Security Misconfigurations
* Improper Input Validation
* Unsafe Third-Party Libraries
* Sensitive Data Exposure
* Privilege Escalation Risks
* Logging and Monitoring Weaknesses
* Rate Limiting Issues
* Denial of Service Risks
* Insecure Cookie Configurations
* Insecure CORS Configurations
* Insecure JWT Implementations
* Insecure Cloud or Deployment Configurations
* AI/LLM Security Risks (when applicable)

For every vulnerability found:

1. Analyze the vulnerable code.
2. Determine its severity.
3. Map it to OWASP and CWE references whenever possible.
4. Explain the security impact.
5. Explain possible attack scenarios.
6. Provide secure remediation guidance.
7. Provide production-ready secure code examples.
8. Include the affected line number whenever available.
9. Provide concise and technically accurate explanations.

Severity levels MUST be one of:

* critical
* high
* medium
* low
* info

IMPORTANT OUTPUT RULES:

* Return ONLY valid JSON.
* Do NOT include Markdown.
* Do NOT include code fences.
* Do NOT include explanations outside the JSON response.
* Do NOT include additional keys.
* Wrap your findings in a single JSON object with exactly one top-level key, "issues", whose value is a JSON array of issue objects.
* Example shape: {"issues": [ { ... }, { ... } ]}
* If no security vulnerabilities are found, return EXACTLY: {"issues": []}
* Every issue object MUST contain EXACTLY the following keys and no others:

{
"title": "",
"category": "",
"severity": "",
"owasp_reference": "",
"description": "",
"why_dangerous": "",
"recommended_fix": "",
"secure_code_example": "",
"line_number": ""
}

Field Requirements:

* title: Short vulnerability title.
* category: Vulnerability category.
* severity: One of the allowed severity values.
* owasp_reference: Relevant OWASP or CWE reference.
* description: Technical explanation of the issue.
* why_dangerous: Real-world security impact.
* recommended_fix: Specific remediation steps.
* secure_code_example: Secure, production-ready example code.
* line_number: Exact line number if identifiable, otherwise "unknown".

Additional Requirements:

* Never report false positives when confidence is low.
* Prefer accuracy over quantity.
* Group related vulnerabilities separately.
* Use secure coding standards for the detected programming language.
* Assume the code may be intended for production environments.
* Provide production-grade remediation recommendations.
* Prioritize exploitable vulnerabilities.
* Detect multiple issues on the same line when applicable.

Your response MUST always be a single valid JSON object of the shape {"issues": [...]}, and nothing else - no preamble, no code fences, no trailing commentary.

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
            return _safe_parse_json_list(content, provider='openai')
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
            model = genai.GenerativeModel(
                'gemini-1.5-flash',
                generation_config={'response_mime_type': 'application/json'},
            )
            prompt = f'{AI_SYSTEM_PROMPT}\n\nFile: {filename}\nLanguage: {language}\n\n```\n{code[:8000]}\n```'
            response = model.generate_content(prompt)
            return _safe_parse_json_list(response.text, provider='gemini')
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
                max_tokens=8192,
                system=AI_SYSTEM_PROMPT,
                messages=[
                    {'role': 'user', 'content': f'File: {filename}\nLanguage: {language}\n\n```\n{code[:8000]}\n```'}
                ],
            )
            content = ''.join(block.text for block in message.content if hasattr(block, 'text'))
            if message.stop_reason == 'max_tokens':
                logger.warning('Claude response was truncated at max_tokens for file %s', filename)
            return _safe_parse_json_list(content, provider='claude')
        except Exception as exc:  # pragma: no cover - network dependent
            logger.warning('Claude provider failed: %s', exc)
            return []


class _RateLimiter:
    """
    Simple in-process sliding-window throttle: at most `max_calls` calls
    within any `period` seconds. Thread-safe so it works correctly even if
    gunicorn is running multiple sync workers/threads hitting the same
    provider concurrently during a zip scan.
    """

    def __init__(self, max_calls: int, period: float):
        self.max_calls = max_calls
        self.period = period
        self.calls = deque()
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            now = time.time()
            while self.calls and now - self.calls[0] > self.period:
                self.calls.popleft()

            if len(self.calls) >= self.max_calls:
                sleep_time = self.period - (now - self.calls[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)
                now = time.time()
                while self.calls and now - self.calls[0] > self.period:
                    self.calls.popleft()

            self.calls.append(time.time())


def _extract_retry_after(exc) -> float | None:
    """Groq's 429 response usually carries a Retry-After header - prefer it
    over a blind exponential backoff when it's available."""
    try:
        response = getattr(exc, 'response', None)
        if response is not None:
            retry_after = response.headers.get('retry-after')
            if retry_after:
                return float(retry_after)
    except Exception:
        pass
    return None


# Groq's free tier is roughly ~30 requests/min depending on the model.
# We cap ourselves at 25/min to leave headroom instead of riding the edge.
_groq_rate_limiter = _RateLimiter(max_calls=25, period=60)


class GroqProvider(AIProvider):
    name = 'groq'
    MAX_RETRIES = 3

    def analyze(self, code: str, filename: str, language: str) -> list[dict]:
        if not self.is_configured:
            return []

        try:
            from groq import Groq, RateLimitError
        except ImportError as exc:  # pragma: no cover - dependency issue
            logger.warning('Groq SDK import failed: %s', exc)
            return []

        client = Groq(api_key=self.api_key)

        for attempt in range(self.MAX_RETRIES):
            _groq_rate_limiter.wait()  # throttle before every attempt, not just retries
            try:
                response = client.chat.completions.create(
                    model='llama-3.3-70b-versatile',
                    messages=[
                        {'role': 'system', 'content': AI_SYSTEM_PROMPT},
                        {'role': 'user', 'content': f'File: {filename}\nLanguage: {language}\n\n```\n{code[:8000]}\n```'},
                    ],
                    temperature=0.1,
                    max_tokens=8000,
                    response_format={'type': 'json_object'},
                )
                content = response.choices[0].message.content
                finish_reason = response.choices[0].finish_reason
                if finish_reason == 'length':
                    logger.warning('Groq response was truncated (finish_reason=length) for file %s', filename)
                return _safe_parse_json_list(content, provider='groq')

            except RateLimitError as exc:
                wait_time = _extract_retry_after(exc) or (2 ** attempt)
                logger.warning(
                    'Groq rate limited (attempt %d/%d) for %s - retrying in %.1fs',
                    attempt + 1, self.MAX_RETRIES, filename, wait_time,
                )
                time.sleep(wait_time)
                continue

            except Exception as exc:  # pragma: no cover - network dependent
                logger.warning('Groq provider failed: %s', exc)
                return []

        logger.warning(
            'Groq gave up after %d retries for %s - skipping AI findings for this file',
            self.MAX_RETRIES, filename,
        )
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


_JSON_BLOCK_RE = re.compile(r'(\{.*\}|\[.*\])', re.DOTALL)


def _safe_parse_json_list(text: str, provider: str = 'unknown') -> list[dict]:
    """
    Robustly parse an AI provider's response into a list of issue dicts.

    Handles:
    - Plain JSON array or object responses.
    - Responses wrapped in ```json ... ``` or ``` ... ``` fences, with or
      without a language label, with or without a trailing newline.
    - Responses with stray preamble/trailing prose around the JSON.
    - Object responses using "issues" / "findings" / "vulnerabilities" /
      "results" as the wrapper key.
    """
    if not text:
        return []

    original = text
    text = text.strip()

    # Strip a leading/trailing code fence regardless of language label or spacing
    text = re.sub(r'^```[a-zA-Z]*\s*', '', text)
    text = re.sub(r'\s*```$', '', text)
    text = text.strip()

    # If the model added any preamble/trailing commentary, pull out the
    # outermost JSON object/array instead of assuming the whole string is JSON.
    if not (text.startswith('{') or text.startswith('[')):
        match = _JSON_BLOCK_RE.search(text)
        if match:
            text = match.group(1)

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        logger.warning(
            'Could not parse %s provider response as JSON. Raw response (first 1500 chars): %s',
            provider, original[:1500],
        )
        return []

    if isinstance(data, dict):
        for key in ('issues', 'findings', 'vulnerabilities', 'results'):
            if key in data:
                data = data[key]
                break
        else:
            logger.warning(
                '%s provider returned a JSON object with no recognized issues key: %s',
                provider, list(data.keys()),
            )
            data = []

    return data if isinstance(data, list) else []


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
