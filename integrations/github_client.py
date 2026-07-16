"""Thin wrapper around the GitHub REST API for the repo-connect flow.

Kept deliberately dependency-light (uses `requests`, already a project
dependency for the payments providers) rather than pulling in PyGithub.
"""
import logging

import requests

logger = logging.getLogger(__name__)

API_ROOT = 'https://api.github.com'
TIMEOUT = 10


class GithubAPIError(Exception):
    """Raised for any non-2xx response from the GitHub API, with a human message."""
    pass


def _headers(token: str) -> dict:
    return {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }


def get_repo_info(token: str, full_name: str) -> dict:
    """Fetch repo metadata. Raises GithubAPIError on failure."""
    resp = requests.get(f'{API_ROOT}/repos/{full_name}', headers=_headers(token), timeout=TIMEOUT)
    if resp.status_code == 404:
        raise GithubAPIError('Repo not found — check the owner/repo name and that the token has access to it.')
    if resp.status_code == 401:
        raise GithubAPIError('That token was rejected by GitHub — check it is valid and not expired.')
    if not resp.ok:
        raise GithubAPIError(f'GitHub API error ({resp.status_code}) while reading repo info.')
    return resp.json()


def create_webhook(token: str, full_name: str, callback_url: str, secret: str) -> str:
    """Creates a push webhook on the repo. Returns the webhook id as a string."""
    payload = {
        'name': 'web',
        'active': True,
        'events': ['push'],
        'config': {
            'url': callback_url,
            'content_type': 'json',
            'secret': secret,
        },
    }
    resp = requests.post(
        f'{API_ROOT}/repos/{full_name}/hooks', headers=_headers(token), json=payload, timeout=TIMEOUT
    )
    if resp.status_code == 403:
        raise GithubAPIError('Token does not have permission to add a webhook (needs "admin:repo_hook" scope, or you need admin rights on the repo).')
    if not resp.ok:
        raise GithubAPIError(f'Could not create the webhook (GitHub said {resp.status_code}: {resp.text[:200]}).')
    return str(resp.json()['id'])


def delete_webhook(token: str, full_name: str, webhook_id: str) -> None:
    """Best-effort webhook removal — failures are logged, not raised, so disconnect always succeeds locally."""
    try:
        requests.delete(
            f'{API_ROOT}/repos/{full_name}/hooks/{webhook_id}', headers=_headers(token), timeout=TIMEOUT
        )
    except requests.RequestException:
        logger.warning('Could not delete GitHub webhook %s for %s (repo may be gone already).', webhook_id, full_name)


def fetch_zipball(token: str, full_name: str, branch: str) -> bytes:
    """Downloads the repo snapshot for a branch as a ZIP and returns the raw bytes."""
    resp = requests.get(
        f'{API_ROOT}/repos/{full_name}/zipball/{branch}', headers=_headers(token), timeout=30
    )
    if not resp.ok:
        raise GithubAPIError(f'Could not download repo archive (GitHub said {resp.status_code}).')
    return resp.content
