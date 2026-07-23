"""
Sends test prompts to the user's own AI endpoint and pulls the reply text
out of whatever JSON shape it returns. Two things matter most here:

1. Never let this become an open SSRF proxy - `validate_target_url` blocks
   loopback / private / link-local / reserved addresses before a request
   is ever made, since this is a hosted SaaS and the target URL is
   arbitrary user input.
2. Never raise out of `send_prompt` - a flaky or unreachable target should
   show up as a failed/error test result, not crash the whole scan.
"""
import ipaddress
import json
import re
import socket
import time
import uuid
from urllib.parse import urlparse

import requests

BLOCKED_HOSTNAMES = {'localhost', '0.0.0.0'}

REQUEST_TIMEOUT_SECONDS = 20
MAX_RESPONSE_BYTES = 200_000

# URL path fragments that strongly suggest an OpenAI-compatible chat
# completion endpoint, even before we look at the response body.
OPENAI_COMPATIBLE_PATH_HINTS = ('/chat/completions', '/v1/completions', '/v1/responses')


class TargetClientError(Exception):
    """Raised when a target URL fails validation before any request is sent."""


class NotAnAIEndpointError(TargetClientError):
    """
    Raised when the pre-flight probe determines the target doesn't behave
    like an AI model / chat interface at all - e.g. it's a plain website,
    a non-chat REST API, or nothing meaningful answers at that path.
    Carries a user-facing explanation as its message.
    """


def build_headers(auth_header: str = '', api_key: str = '', bearer_token: str = '',
                   custom_headers: dict | None = None) -> dict:
    """
    Merges every supported credential/header source into one headers dict
    for an outgoing test request. Precedence (later wins on conflicting
    keys): auth_header (legacy single field) -> bearer_token -> api_key ->
    custom_headers (most specific, always wins).
    Never logs any of these values - callers must not either.
    """
    headers = {'Content-Type': 'application/json'}
    if auth_header:
        headers['Authorization'] = auth_header
    if bearer_token:
        headers['Authorization'] = bearer_token if bearer_token.lower().startswith('bearer ') else f'Bearer {bearer_token}'
    if api_key:
        # Most AI providers accept the key as a bearer token OR a
        # dedicated header; send both so the scan works either way.
        headers.setdefault('Authorization', f'Bearer {api_key}')
        headers['X-API-Key'] = api_key
    if custom_headers:
        for key, value in custom_headers.items():
            if key and value is not None:
                headers[str(key)] = str(value)
    return headers


def build_payload(request_field: str, prompt: str, request_body_template: str = '',
                   model_name: str = '') -> dict | str:
    """
    Builds the outgoing JSON body for a single test prompt. If a custom
    request_body_template is configured, {{prompt}} and {{model}} are
    substituted into it (as JSON-escaped values, so special characters in
    attack prompts can't break the template's JSON structure) and the
    result is parsed back to a dict. Falls back to the simple
    {request_field: prompt} shape used by the MVP otherwise.
    """
    if request_body_template and request_body_template.strip():
        prompt_json = json.dumps(prompt)[1:-1]  # escaped, without the surrounding quotes
        model_json = json.dumps(model_name or '')[1:-1]
        rendered = request_body_template.replace('{{prompt}}', prompt_json).replace('{{model}}', model_json)
        try:
            return json.loads(rendered)
        except ValueError:
            # Template didn't render to valid JSON - fall back rather than crash the scan.
            pass
    payload = {request_field or 'message': prompt}
    if model_name:
        payload.setdefault('model', model_name)
    return payload


class DNSResolutionError(TargetClientError):
    """Raised when the hostname could not be resolved at all (typo, dead domain,
    or a transient network blip) - distinct from a host that resolved fine but
    points at a blocked private/internal address."""


def _resolve_or_none(hostname: str, attempts: int = 2, delay_seconds: float = 0.4):
    """Tries DNS resolution up to `attempts` times to smooth over transient
    blips, returning the getaddrinfo result list, or None if every attempt
    failed to resolve at all."""
    last_error = None
    for i in range(attempts):
        try:
            return socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            last_error = exc
            if i < attempts - 1:
                time.sleep(delay_seconds)
    return None


def _is_private_or_blocked(hostname: str) -> bool:
    infos = _resolve_or_none(hostname)
    if infos is None:
        raise DNSResolutionError(
            f"Could not resolve '{hostname}'. Double-check the URL is correct and reachable."
        )
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return True
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return True
    return False


def validate_target_url(url: str) -> None:
    """Raises TargetClientError if the URL is malformed or points at an internal/private address."""
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise TargetClientError('The target URL must start with http:// or https://')

    hostname = (parsed.hostname or '').lower()
    if not hostname or hostname in BLOCKED_HOSTNAMES:
        raise TargetClientError('That host cannot be scanned.')

    if _is_private_or_blocked(hostname):
        raise TargetClientError('Scanning private, internal, or reserved network addresses is not allowed.')


def probe_target(target_url: str, request_field: str, response_path: str, auth_header: str = '',
                  api_key: str = '', bearer_token: str = '', custom_headers: dict | None = None,
                  request_body_template: str = '', model_name: str = '') -> dict:
    """
    Pre-flight check run once before the attack suite: sends a single
    harmless, clearly-labelled probe message and inspects how the target
    replies to answer 5 questions -
        1. Is this an AI endpoint at all?
        2. Is it a REST/JSON API?
        3. Is it just a website (HTML)?
        4. Is it an OpenAI-compatible chat-completions endpoint?
        5. Is it some other chat-completion-shaped JSON endpoint?

    Returns a dict:
        {'is_ai_endpoint': bool, 'target_format': str, 'reason': str}
    Raises NotAnAIEndpointError (with a ready-to-show message) if the
    target clearly isn't an AI/chat interface. Network-level failures are
    raised as TargetClientError so the caller can tell "not reachable"
    apart from "reachable but not an AI".
    """
    nonce = f'PROBE-{uuid.uuid4().hex[:10]}'
    probe_prompt = (
        'This is an automated pre-flight connectivity check, not a real user message. '
        f'Reply with only this exact token and nothing else: {nonce}'
    )
    headers = build_headers(auth_header, api_key, bearer_token, custom_headers)
    payload = build_payload(request_field, probe_prompt, request_body_template, model_name)

    parsed_path = urlparse(target_url).path.lower()
    url_looks_openai_shaped = any(hint in parsed_path for hint in OPENAI_COMPATIBLE_PATH_HINTS)

    try:
        resp = requests.post(target_url, json=payload, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
    except requests.exceptions.RequestException as exc:
        raise TargetClientError(f'Could not reach the target URL: {str(exc)[:200]}') from exc

    content_type = resp.headers.get('Content-Type', '').lower()
    raw_text = resp.text[:MAX_RESPONSE_BYTES]

    # 1) Plain website - HTML back, no JSON to speak of.
    if 'text/html' in content_type or re.match(r'^\s*<!doctype html|^\s*<html', raw_text, re.IGNORECASE):
        raise NotAnAIEndpointError(
            'This URL does not appear to expose an AI model or chat interface. '
            'AI security tests cannot be performed. '
            '(The target returned an HTML web page, not a JSON chat/completion response.)'
        )

    # 2) Try to parse as JSON - a REST API that isn't JSON at all is not scannable either.
    try:
        data = json.loads(raw_text)
    except ValueError:
        if nonce in raw_text and len(raw_text.strip()) < 2000:
            # Plain-text chat endpoint (no JSON envelope) that echoed our token back.
            return {'is_ai_endpoint': True, 'target_format': 'plain_text_chat',
                     'reason': 'Target replied in plain text and echoed the probe token back.'}
        raise NotAnAIEndpointError(
            'This URL does not appear to expose an AI model or chat interface. '
            'AI security tests cannot be performed. '
            "(The response wasn't valid JSON, and didn't read like a chat reply either.)"
        )

    # 4) OpenAI-compatible chat completion shape: {"choices": [{"message": {"content": "..."}}]}
    if isinstance(data, dict) and isinstance(data.get('choices'), list) and data['choices']:
        first = data['choices'][0]
        content = None
        if isinstance(first, dict):
            content = (first.get('message') or {}).get('content') if isinstance(first.get('message'), dict) else None
            if content is None:
                content = first.get('text')
        if content:
            return {'is_ai_endpoint': True, 'target_format': 'openai_compatible',
                     'reason': 'Detected an OpenAI-compatible chat-completions response (choices[].message.content).'}

    # 5) Some other chat-shaped JSON endpoint - resolve via the configured response path.
    text = _extract_path(data, response_path or 'response')
    if text and text.strip():
        return {'is_ai_endpoint': True, 'target_format': 'custom_json_chat',
                 'reason': f"Target returned text at the configured response path ('{response_path or 'response'}')."}

    # 3) It's JSON, so it's a REST API of some kind - just not a chat one we could extract a reply from.
    hint = ''
    if url_looks_openai_shaped:
        hint = (
            " The URL looks like an OpenAI-style chat-completions path, but the response didn't "
            "match that shape (no 'choices[].message.content')."
        )
    raise NotAnAIEndpointError(
        'This URL does not appear to expose an AI model or chat interface. '
        'AI security tests cannot be performed. '
        f"(It looks like a JSON REST API, but no reply text was found at the response path '{response_path or 'response'}'.{hint} "
        "Check the 'response path' field, or this endpoint may not be a chat/completion API.)"
    )


def _extract_path(data, path: str):
    """Walks a dotted path like 'data.reply' through nested dicts/lists."""
    current = data
    for part in path.split('.'):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            idx = int(part)
            current = current[idx] if idx < len(current) else None
        else:
            return None
    if isinstance(current, (dict, list)):
        return None
    return current if current is None else str(current)


def _extract_openai_compatible(data):
    """Pulls reply text out of an OpenAI-style {"choices": [...]} response, or None."""
    if not isinstance(data, dict) or not isinstance(data.get('choices'), list) or not data['choices']:
        return None
    first = data['choices'][0]
    if not isinstance(first, dict):
        return None
    message = first.get('message')
    if isinstance(message, dict) and message.get('content'):
        return str(message['content'])
    if first.get('text'):
        return str(first['text'])
    delta = first.get('delta')
    if isinstance(delta, dict) and delta.get('content'):
        return str(delta['content'])
    return None


def _extract_reply_text(data, response_path: str):
    """
    Tries the configured response_path first (works for custom/plain JSON
    chat endpoints), then falls back to the OpenAI-compatible
    choices[].message.content shape - this fallback matters because
    probe_target can detect an OpenAI-compatible target while
    response_path is still left at its 'response' default.
    """
    text = _extract_path(data, response_path or 'response')
    if text and text.strip():
        return text
    return _extract_openai_compatible(data)


def send_prompt(target_url: str, request_field: str, response_path: str, prompt: str,
                 auth_header: str = '', timeout: int = REQUEST_TIMEOUT_SECONDS,
                 api_key: str = '', bearer_token: str = '', custom_headers: dict | None = None,
                 request_body_template: str = '', model_name: str = '') -> dict:
    """
    POSTs a single test prompt to the target AI endpoint as JSON and
    extracts its reply text. Always returns a dict - never raises - so a
    single unreachable/broken target never aborts the rest of the scan.
    """
    headers = build_headers(auth_header, api_key, bearer_token, custom_headers)
    payload = build_payload(request_field, prompt, request_body_template, model_name)
    started = time.monotonic()

    try:
        resp = requests.post(
            target_url, json=payload, headers=headers,
            timeout=timeout, stream=True,
        )
        raw = resp.raw.read(MAX_RESPONSE_BYTES, decode_content=True)
        elapsed_ms = int((time.monotonic() - started) * 1000)

        if resp.status_code >= 400:
            return {'ok': False, 'text': '', 'elapsed_ms': elapsed_ms,
                    'error': f'Target responded with HTTP {resp.status_code}'}

        try:
            import json
            data = json.loads(raw.decode('utf-8', errors='ignore'))
        except ValueError:
            text = raw.decode('utf-8', errors='ignore')[:2000]
            return {'ok': True, 'text': text, 'elapsed_ms': elapsed_ms, 'error': ''}

        text = _extract_reply_text(data, response_path)
        if text is None:
            text = str(data)[:2000]
        return {'ok': True, 'text': text, 'elapsed_ms': elapsed_ms, 'error': ''}

    except requests.exceptions.Timeout:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {'ok': False, 'text': '', 'elapsed_ms': elapsed_ms, 'error': 'Request timed out'}
    except requests.exceptions.RequestException as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {'ok': False, 'text': '', 'elapsed_ms': elapsed_ms, 'error': str(exc)[:300]}