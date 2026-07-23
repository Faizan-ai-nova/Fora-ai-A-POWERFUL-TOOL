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
import socket
import time
from urllib.parse import urlparse

import requests

BLOCKED_HOSTNAMES = {'localhost', '0.0.0.0'}

REQUEST_TIMEOUT_SECONDS = 20
MAX_RESPONSE_BYTES = 200_000


class TargetClientError(Exception):
    """Raised when a target URL fails validation before any request is sent."""


def _is_private_or_blocked(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return True
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


def send_prompt(target_url: str, request_field: str, response_path: str, prompt: str,
                 auth_header: str = '', timeout: int = REQUEST_TIMEOUT_SECONDS) -> dict:
    """
    POSTs a single test prompt to the target AI endpoint as JSON and
    extracts its reply text. Always returns a dict - never raises - so a
    single unreachable/broken target never aborts the rest of the scan.
    """
    headers = {'Content-Type': 'application/json'}
    if auth_header:
        headers['Authorization'] = auth_header

    payload = {request_field or 'message': prompt}
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

        text = _extract_path(data, response_path or 'response')
        if text is None:
            text = str(data)[:2000]
        return {'ok': True, 'text': text, 'elapsed_ms': elapsed_ms, 'error': ''}

    except requests.exceptions.Timeout:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {'ok': False, 'text': '', 'elapsed_ms': elapsed_ms, 'error': 'Request timed out'}
    except requests.exceptions.RequestException as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {'ok': False, 'text': '', 'elapsed_ms': elapsed_ms, 'error': str(exc)[:300]}
