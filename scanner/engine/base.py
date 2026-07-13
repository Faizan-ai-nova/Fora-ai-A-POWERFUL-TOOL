"""
Pluggable AI provider interface.

Fora AI's scanning pipeline is provider-agnostic: the analyzer always
runs the deterministic rule engine (rules.py) first so the product works
out of the box with zero API keys. If an AI_PROVIDER is configured with
a valid API key, its `analyze()` result is merged in for deeper/contextual
findings (business-logic issues, auth flaws, novel patterns the static
rules can't see).

To add a real provider, subclass AIProvider and implement `analyze()`,
then register it in providers.py's PROVIDER_REGISTRY.
"""

from abc import ABC, abstractmethod


class AIProvider(ABC):
    """Base class every AI backend (OpenAI, Gemini, Claude, Groq) must implement."""

    name = 'base'

    def __init__(self, api_key: str = ''):
        self.api_key = api_key

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    @abstractmethod
    def analyze(self, code: str, filename: str, language: str) -> list[dict]:
        """
        Analyze a single file's source code and return a list of issue dicts:

        {
            "title": str,
            "category": str,
            "severity": "critical"|"high"|"medium"|"low"|"info",
            "owasp_reference": str,
            "description": str,
            "why_dangerous": str,
            "recommended_fix": str,
            "secure_code_example": str,
            "line_number": int | None,
            "code_snippet": str,
        }

        Implementations should never raise - catch provider/network
        errors internally and return an empty list so a flaky AI call
        never breaks a scan that the rule engine already completed.
        """
        raise NotImplementedError
