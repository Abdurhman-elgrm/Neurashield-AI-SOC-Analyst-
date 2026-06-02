"""
Secure credential storage using Windows DPAPI (Data Protection API).

On Windows, credentials are encrypted with CryptProtectData() bound to the
machine key (CRYPTPROTECT_LOCAL_MACHINE = True) so that any process running
as SYSTEM or an Administrator on this machine can decrypt them — but no
other machine can.

On non-Windows platforms (Linux, macOS, CI), a Fernet-based fallback is
used with a machine-unique key derived from the machine-id.  This is not
as strong as DPAPI but preserves cross-platform testability.

The credential file is written to the 'credentials' subdirectory which
bootstrap.ps1 ACLs to SYSTEM + Administrators only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import stat
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from soc_agent.enrollment import RuntimeCredentials


_DESCRIPTION = b"SOCAnalystAgent v2 Runtime Credentials"


# ─── Platform detection ───────────────────────────────────────────────────────

def _is_windows() -> bool:
    return platform.system() == "Windows"


# ─── Windows DPAPI ────────────────────────────────────────────────────────────

def _dpapi_encrypt(plaintext: bytes) -> bytes:
    import win32crypt  # type: ignore[import]
    # CRYPTPROTECT_LOCAL_MACHINE (flag=4) → decryptable by any admin on this host
    encrypted = win32crypt.CryptProtectData(
        plaintext,
        _DESCRIPTION.decode(),
        None,   # optional entropy
        None,   # reserved
        None,   # prompt info
        4,      # CRYPTPROTECT_LOCAL_MACHINE
    )
    return encrypted


def _dpapi_decrypt(ciphertext: bytes) -> bytes:
    import win32crypt  # type: ignore[import]
    _desc, plaintext = win32crypt.CryptUnprotectData(
        ciphertext,
        None,  # optional entropy
        None,  # reserved
        None,  # prompt info
        0,     # flags
    )
    return plaintext


# ─── Non-Windows fallback (CI / development) ─────────────────────────────────

def _get_machine_secret() -> bytes:
    """Derive a machine-unique key from the OS machine-id."""
    raw = ""
    try:
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            if os.path.exists(path):
                raw = open(path).read().strip()
                if raw:
                    break
    except Exception:
        pass
    if not raw:
        # Stable fallback: hostname + a fixed pepper
        import socket
        raw = socket.gethostname() + "-soc-analyst-v2"
    return hashlib.sha256(raw.encode()).digest()


def _fernet_encrypt(plaintext: bytes) -> bytes:
    from cryptography.fernet import Fernet  # type: ignore[import]
    key = base64.urlsafe_b64encode(_get_machine_secret())
    return Fernet(key).encrypt(plaintext)


def _fernet_decrypt(ciphertext: bytes) -> bytes:
    from cryptography.fernet import Fernet  # type: ignore[import]
    key = base64.urlsafe_b64encode(_get_machine_secret())
    return Fernet(key).decrypt(ciphertext)


# ─── Restricted file permissions ─────────────────────────────────────────────

def _restrict_permissions(path: Path) -> None:
    if _is_windows():
        return  # ACLs set at directory level by bootstrap.ps1
    # POSIX: owner-only read/write (600)
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


# ─── Public API ───────────────────────────────────────────────────────────────

def store_credentials(creds: "RuntimeCredentials", path: Path) -> None:
    """
    Serialize and encrypt credentials to *path*.
    The file is written atomically (tmp → rename) to prevent partial writes.
    """
    from soc_agent.enrollment import RuntimeCredentials  # noqa: PLC0415
    payload = json.dumps({
        "agent_id":           str(creds.agent_id),
        "enrollment_token":   creds.enrollment_token,
        "tenant_id":          str(creds.tenant_id),
        "installer_token_id": str(creds.installer_token_id),
        "api_url":            creds.api_url,
    }).encode("utf-8")

    if _is_windows():
        encrypted = _dpapi_encrypt(payload)
    else:
        encrypted = _fernet_encrypt(payload)

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(encrypted)
    _restrict_permissions(tmp)
    tmp.replace(path)  # atomic on both Windows and POSIX
    _restrict_permissions(path)


def load_credentials(path: Path) -> "RuntimeCredentials":
    """
    Decrypt and deserialize credentials from *path*.
    Raises FileNotFoundError if the credentials file does not exist.
    Raises CredentialError if the file is corrupt or cannot be decrypted.
    """
    from soc_agent.enrollment import RuntimeCredentials  # noqa: PLC0415
    import uuid

    if not path.exists():
        raise FileNotFoundError(f"Credentials not found at: {path}")

    ciphertext = path.read_bytes()
    try:
        if _is_windows():
            plaintext = _dpapi_decrypt(ciphertext)
        else:
            plaintext = _fernet_decrypt(ciphertext)
    except Exception as exc:
        raise CredentialError(f"Failed to decrypt credentials: {exc}") from exc

    try:
        data = json.loads(plaintext.decode("utf-8"))
        return RuntimeCredentials(
            agent_id=uuid.UUID(data["agent_id"]),
            enrollment_token=data["enrollment_token"],
            tenant_id=uuid.UUID(data["tenant_id"]),
            installer_token_id=uuid.UUID(data["installer_token_id"]),
            api_url=data["api_url"],
        )
    except (KeyError, ValueError) as exc:
        raise CredentialError(f"Corrupt credential file: {exc}") from exc


def credentials_exist(path: Path) -> bool:
    return path.exists() and path.stat().st_size > 0


class CredentialError(Exception):
    pass
