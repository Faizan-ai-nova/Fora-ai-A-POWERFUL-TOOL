"""
Minimal multi-provider chat-completion client for AI Agent Testing.

Deliberately separate from scanner/engine/providers.py — that module forces
a JSON-only security-audit prompt shape. This one sends whatever
system/user prompt the person is testing with and returns the raw text
reply plus token usage, so it works for arbitrary agent/prompt testing.

Everything goes over plain HTTP via `requests` (already a dependency) so
no extra packages are required to run a test.
"""

import logging
import time

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

DEFAULT_MODELS = {
    'groq': 'llama-3.3-70b-versatile',
    'openai': 'gpt-4o-mini',
    'gemini': 'gemini-1.5-flash',
    'claude': 'claude-sonnet-4-6',
}

# Per-model pricing (USD per 1M tokens) — used ONLY to show a ballpark
# estimated cost in the UI, not wired to any billing system. Groq prices
# verified against console.groq.com/docs/models; update as prices change.
PRICING_PER_1M = {
    ('groq', 'llama-3.3-70b-versatile'): {'input': 0.59, 'output': 0.79},
    ('groq', 'llama-3.1-8b-instant'): {'input': 0.05, 'output': 0.08},
    ('groq', 'openai/gpt-oss-120b'): {'input': 0.15, 'output': 0.60},
    ('groq', 'openai/gpt-oss-20b'): {'input': 0.075, 'output': 0.30},
    ('groq', 'openai/gpt-oss-safeguard-20b'): {'input': 0.075, 'output': 0.30},
    ('groq', 'qwen/qwen3.6-27b'): {'input': 0.60, 'output': 3.00},
    ('groq', 'meta-llama/llama-prompt-guard-2-86m'): {'input': 0.04, 'output': 0.04},
    ('openai', 'gpt-4o-mini'): {'input': 0.15, 'output': 0.60},
    ('openai', 'gpt-4o'): {'input': 2.50, 'output': 10.00},
    ('gemini', 'gemini-1.5-flash'): {'input': 0.075, 'output': 0.30},
    ('gemini', 'gemini-1.5-pro'): {'input': 1.25, 'output': 5.00},
    ('claude', 'claude-sonnet-4-6'): {'input': 3.00, 'output': 15.00},
    ('claude', 'claude-3-5-haiku-20241022'): {'input': 0.80, 'output': 4.00},
}

# Fallback if a specific model isn't in the table above (e.g. groq/compound,
# which doesn't publish per-token pricing) — per-provider ballpark rate.
PROVIDER_FALLBACK_PRICING = {
    'groq': {'input': 0.20, 'output': 0.40},
    'openai': {'input': 0.15, 'output': 0.60},
    'gemini': {'input': 0.075, 'output': 0.30},
    'claude': {'input': 3.00, 'output': 15.00},
}

REQUEST_TIMEOUT = 30

PROVIDER_URLS = {
    'groq': 'https://api.groq.com/openai/v1/chat/completions',
    'openai': 'https://api.openai.com/v1/chat/completions',
}


class AgentTestError(Exception):
    """Raised when a provider call fails or the provider isn't configured."""


def _api_key_for(provider: str) -> str:
    return {
        'groq': getattr(settings, 'GROQ_API_KEY', ''),
        'openai': getattr(settings, 'OPENAI_API_KEY', ''),
        'gemini': getattr(settings, 'GEMINI_API_KEY', ''),
        'claude': getattr(settings, 'ANTHROPIC_API_KEY', ''),
    }.get(provider, '')


def estimate_cost_usd(provider: str, model: str, prompt_tokens: int, completion_tokens: int) -> float:
    rates = PRICING_PER_1M.get((provider, model)) or PROVIDER_FALLBACK_PRICING.get(
        provider, {'input': 0.50, 'output': 1.50}
    )
    cost = (prompt_tokens / 1_000_000) * rates['input'] + (completion_tokens / 1_000_000) * rates['output']
    return round(cost, 6)


def _call_openai_compatible(url: str, api_key: str, model: str, system_prompt: str, input_prompt: str) -> dict:
    """Works for Groq, OpenAI, and any other OpenAI-compatible /chat/completions endpoint."""
    messages = []
    if system_prompt:
        messages.append({'role': 'system', 'content': system_prompt})
    messages.append({'role': 'user', 'content': input_prompt})

    resp = requests.post(
        url,
        headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
        json={'model': model, 'messages': messages, 'temperature': 0.3, 'max_tokens': 2000},
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()
    text = data['choices'][0]['message']['content'].strip()
    usage = data.get('usage', {})
    return {
        'text': text,
        'prompt_tokens': usage.get('prompt_tokens', 0),
        'completion_tokens': usage.get('completion_tokens', 0),
    }


def _call_claude(api_key: str, model: str, system_prompt: str, input_prompt: str) -> dict:
    resp = requests.post(
        'https://api.anthropic.com/v1/messages',
        headers={
            'x-api-key': api_key,
            'anthropic-version': '2023-06-01',
            'Content-Type': 'application/json',
        },
        json={
            'model': model,
            'max_tokens': 2000,
            'system': system_prompt or '',
            'messages': [{'role': 'user', 'content': input_prompt}],
        },
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()
    text = ''.join(block.get('text', '') for block in data.get('content', []))
    usage = data.get('usage', {})
    return {
        'text': text.strip(),
        'prompt_tokens': usage.get('input_tokens', 0),
        'completion_tokens': usage.get('output_tokens', 0),
    }


def _call_gemini(api_key: str, model: str, system_prompt: str, input_prompt: str) -> dict:
    url = f'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}'
    payload = {'contents': [{'parts': [{'text': input_prompt}]}]}
    if system_prompt:
        payload['systemInstruction'] = {'parts': [{'text': system_prompt}]}

    resp = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    data = resp.json()
    candidates = data.get('candidates', [])
    text = ''
    if candidates:
        parts = candidates[0].get('content', {}).get('parts', [])
        text = ''.join(p.get('text', '') for p in parts)
    usage = data.get('usageMetadata', {})
    return {
        'text': text.strip(),
        'prompt_tokens': usage.get('promptTokenCount', 0),
        'completion_tokens': usage.get('candidatesTokenCount', 0),
    }


def run_agent_test(
    provider: str,
    model_name: str,
    system_prompt: str,
    input_prompt: str,
    user_api_key: str = '',
    custom_provider_type: str = '',
    custom_api_base: str = '',
) -> dict:
    """
    Runs a single test call against the given provider/model.

    If `user_api_key` is supplied, it's used for this call instead of the
    server's configured key (BYOK) — this lets a person test OpenAI/Gemini/
    Claude/custom models without the server needing those keys configured.
    The key is used only for this one request and is never persisted
    anywhere.

    When `provider` is 'custom', `custom_provider_type` picks which request
    shape to use ('openai_compatible', 'claude', or 'gemini') and, for
    'openai_compatible', `custom_api_base` is the full chat/completions URL
    to call (e.g. an OpenRouter, Together, or self-hosted vLLM endpoint).

    Returns a dict: {text, prompt_tokens, completion_tokens, total_tokens,
    latency_ms, estimated_cost_usd}. Raises AgentTestError on any failure
    (missing key, network error, bad response shape) with a message safe
    to show the person.
    """
    api_key = user_api_key.strip() if user_api_key else _api_key_for(provider)
    if not api_key:
        raise AgentTestError(
            f'No {provider.capitalize()} API key available. Enter your own key above, '
            f'or ask the site admin to configure one.'
        )

    model = model_name.strip() if model_name else DEFAULT_MODELS.get(provider, '')

    start = time.monotonic()
    try:
        if provider in ('groq', 'openai'):
            result = _call_openai_compatible(PROVIDER_URLS[provider], api_key, model, system_prompt, input_prompt)
        elif provider == 'claude':
            result = _call_claude(api_key, model, system_prompt, input_prompt)
        elif provider == 'gemini':
            result = _call_gemini(api_key, model, system_prompt, input_prompt)
        elif provider == 'custom':
            if custom_provider_type == 'claude':
                result = _call_claude(api_key, model, system_prompt, input_prompt)
            elif custom_provider_type == 'gemini':
                result = _call_gemini(api_key, model, system_prompt, input_prompt)
            else:
                if not custom_api_base:
                    raise AgentTestError('A custom OpenAI-compatible model needs an endpoint URL.')
                result = _call_openai_compatible(custom_api_base, api_key, model, system_prompt, input_prompt)
        else:
            raise AgentTestError(f'Unknown provider: {provider}')
    except requests.HTTPError as exc:
        logger.warning('Agent test HTTP error (%s/%s): %s', provider, model, exc)
        detail = ''
        try:
            detail = exc.response.json().get('error', {}).get('message', '')
        except Exception:
            pass
        raise AgentTestError(detail or f'{provider.capitalize()} request failed ({exc.response.status_code}).')
    except requests.RequestException as exc:
        logger.warning('Agent test network error (%s/%s): %s', provider, model, exc)
        raise AgentTestError('Network error while calling the provider. Please try again.')
    except (KeyError, IndexError, ValueError) as exc:
        logger.warning('Agent test unexpected response shape (%s/%s): %s', provider, model, exc)
        raise AgentTestError('Received an unexpected response shape from the provider.')

    latency_ms = int((time.monotonic() - start) * 1000)
    prompt_tokens = result['prompt_tokens']
    completion_tokens = result['completion_tokens']

    return {
        'text': result['text'],
        'model': model,
        'prompt_tokens': prompt_tokens,
        'completion_tokens': completion_tokens,
        'total_tokens': prompt_tokens + completion_tokens,
        'latency_ms': latency_ms,
        'estimated_cost_usd': estimate_cost_usd(provider, model, prompt_tokens, completion_tokens),
    }
