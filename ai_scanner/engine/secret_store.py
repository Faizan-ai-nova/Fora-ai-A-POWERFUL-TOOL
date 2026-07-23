"""
Encrypts credentials the user supplies for scanning authenticated AI APIs
(API keys, bearer tokens, custom headers) before they ever touch the
database, and decrypts them only in-memory for the duration of a single
scan run.

Rules this module exists to enforce:
- Nothing here is ever written to logs (see `redact` used at call sites).
- Nothing here is ever included in a report, JSON export, or admin list
  display - only engine/target_client.py reads the decrypted value, and
  only to build the outgoing request headers for that one scan.
- If ENCRYPTION_KEY/SECRET_KEY is rotated, old encrypted values simply
  fail to decrypt - callers treat that as "no credential" rather than
  crashing the scan.
"""
import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings

logger = logging.getLogger(__name__)


def _fernet() -> Fernet:
    # Derive a stable 32-byte key from Django's SECRET_KEY so no extra
    # infra/config is required for the MVP. If a dedicated
    # AI_SCANNER_ENCRYPTION_KEY is set, prefer that instead.
    material = getattr(settings, 'AI_SCANNER_ENCRYPTION_KEY', '') or settings.SECRET_KEY
    digest = hashlib.sha256(material.encode('utf-8')).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt(plaintext: str) -> str:
    """Returns '' for falsy input, otherwise a base64 token safe for a TextField."""
    if not plaintext:
        return ''
    try:
        return _fernet().encrypt(plaintext.encode('utf-8')).decode('ascii')
    except Exception:  # noqa: BLE001 - never let a bad key crash the save path
        logger.exception('Failed to encrypt a scan credential')
        return ''


def decrypt(token: str) -> str:
    """Returns '' for falsy input or if decryption fails (key rotated, corrupt data, etc)."""
    if not token:
        return ''
    try:
        return _fernet().decrypt(token.encode('ascii')).decode('utf-8')
    except (InvalidToken, ValueError):
        return ''
    except Exception:  # noqa: BLE001
        logger.exception('Failed to decrypt a scan credential')
        return ''


def redact(value: str) -> str:
    """Short masked preview for admin/debug display - never the real value."""
    if not value:
        return ''
    return f'{value[:3]}***REDACTED***'
