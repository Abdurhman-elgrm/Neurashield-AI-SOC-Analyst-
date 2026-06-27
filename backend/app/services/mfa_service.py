"""TOTP-based MFA service.

Secrets are stored Fernet-encrypted at rest using a key derived from JWT_SECRET.
Backup codes are stored as SHA-256 hashes; raw codes are shown to the user once.
"""

from __future__ import annotations

import hashlib
import secrets
import string
from datetime import UTC, datetime

import pyotp
import structlog
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings
from app.models.user import User

log = structlog.get_logger(__name__)

_B32_ALPHABET = string.ascii_uppercase + "234567"
_BACKUP_CODE_CHARS = string.ascii_uppercase + string.digits
_BACKUP_CODE_LEN = 10
_NUM_BACKUP_CODES = 8


def _fernet() -> Fernet:
    """Derive a stable 32-byte Fernet key from JWT_SECRET via SHA-256."""
    key_bytes = hashlib.sha256(settings.JWT_SECRET.encode("utf-8")).digest()
    import base64

    return Fernet(base64.urlsafe_b64encode(key_bytes))


def _encrypt_secret(raw_secret: str) -> str:
    return _fernet().encrypt(raw_secret.encode("utf-8")).decode("utf-8")


def _decrypt_secret(encrypted: str) -> str | None:
    try:
        return _fernet().decrypt(encrypted.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        log.warning("totp_decrypt_failed")
        return None


def _hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.upper().encode("utf-8")).hexdigest()


class MFAService:
    @staticmethod
    def generate_totp_setup(user: User) -> dict:
        """
        Generate a new TOTP secret and provisioning URI for QR-code display.
        Does NOT activate MFA — the user must call verify_and_activate_mfa() first.
        Returns: raw_secret (show once), encrypted_secret (store), provisioning_uri.
        """
        raw_secret = pyotp.random_base32()
        encrypted_secret = _encrypt_secret(raw_secret)
        totp = pyotp.TOTP(raw_secret)
        uri = totp.provisioning_uri(
            name=user.email,
            issuer_name="NEURASHIELD SOC",
        )
        return {
            "raw_secret": raw_secret,
            "encrypted_secret": encrypted_secret,
            "provisioning_uri": uri,
        }

    @staticmethod
    def verify_and_activate_mfa(user: User, encrypted_secret: str, code: str) -> list[str]:
        """
        Verify a TOTP code against a pending encrypted_secret and activate MFA on the user.
        Returns the list of raw backup codes (shown to user once).
        Raises ValueError on bad code.
        """
        raw_secret = _decrypt_secret(encrypted_secret)
        if raw_secret is None:
            raise ValueError("Invalid or expired setup token")

        totp = pyotp.TOTP(raw_secret)
        if not totp.verify(code, valid_window=1):
            raise ValueError("Invalid TOTP code")

        raw_codes = [
            "".join(secrets.choice(_BACKUP_CODE_CHARS) for _ in range(_BACKUP_CODE_LEN))
            for _ in range(_NUM_BACKUP_CODES)
        ]
        hashed_codes = [_hash_backup_code(c) for c in raw_codes]

        user.totp_secret = encrypted_secret
        user.totp_enabled = True
        user.totp_enabled_at = datetime.now(tz=UTC)
        user.mfa_backup_codes = hashed_codes

        return raw_codes

    @staticmethod
    def verify_totp(user: User, code: str) -> bool:
        """Verify a TOTP code during login. Returns True on valid code."""
        if not user.totp_enabled or not user.totp_secret:
            return False
        raw_secret = _decrypt_secret(user.totp_secret)
        if raw_secret is None:
            return False
        return pyotp.TOTP(raw_secret).verify(code, valid_window=1)

    @staticmethod
    def verify_backup_code(user: User, code: str) -> bool:
        """
        Verify and consume a backup code.
        Returns True and removes the code if valid; False otherwise.
        """
        if not user.mfa_backup_codes:
            return False
        code_hash = _hash_backup_code(code)
        codes: list[str] = list(user.mfa_backup_codes)
        if code_hash in codes:
            codes.remove(code_hash)
            user.mfa_backup_codes = codes
            return True
        return False

    @staticmethod
    def disable_mfa(user: User) -> None:
        user.totp_secret = None
        user.totp_enabled = False
        user.totp_enabled_at = None
        user.mfa_backup_codes = None
