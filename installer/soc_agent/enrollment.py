"""
Bootstrap enrollment: exchanges the one-time installer token for permanent
agent runtime credentials (agent_id + enrollment_token).

The installer token is invalidated by the server on first successful call.
Subsequent calls with the same token → 404 / 409 (token already consumed).
"""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from typing import Any

import requests
from requests.exceptions import RequestException


_ENROLL_PATH = "/api/v1/installer/bootstrap-enroll"
_TIMEOUT_SECS = 30


@dataclass
class RuntimeCredentials:
    """Permanent agent credentials returned after enrollment.
    Must be stored via DPAPI — never written to plaintext files.
    """
    agent_id:            uuid.UUID
    enrollment_token:    str          # Argon2id-hashed on server; keep secret
    tenant_id:           uuid.UUID
    installer_token_id:  uuid.UUID
    api_url:             str


class EnrollmentError(Exception):
    """Raised when the backend refuses enrollment or the network call fails."""
    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def bootstrap_enroll(
    api_url: str,
    tenant_id: str,
    installer_token: str,
    machine_info: dict[str, Any],
) -> RuntimeCredentials:
    """
    Exchange a one-time installer token for permanent agent credentials.

    Security properties:
    - TLS required (requests validates server certificate by default)
    - Token is sent in the JSON body, not in a URL or header
    - Single-use: server atomically marks token INSTALLING → ACTIVE

    Raises EnrollmentError on any failure so the caller can exit cleanly
    without storing partial state.
    """
    if not api_url.startswith("https://") and not os.environ.get("SOC_ALLOW_HTTP"):
        scheme = api_url.split("://")[0] if "://" in api_url else "unknown"
        raise EnrollmentError(
            f"API URL must use HTTPS for security. Got scheme: {scheme}://... "
            "Set SOC_ALLOW_HTTP=1 to override for local development only."
        )

    url = api_url.rstrip("/") + _ENROLL_PATH
    body = {
        "token":        installer_token,
        "tenant_id":    str(tenant_id),
        "machine_info": machine_info,
    }

    try:
        resp = requests.post(
            url,
            json=body,
            timeout=_TIMEOUT_SECS,
            headers={"Content-Type": "application/json"},
        )
    except RequestException as exc:
        raise EnrollmentError(f"Network error during enrollment: {exc}") from exc

    if resp.status_code == 404:
        raise EnrollmentError(
            "Installer token not found or already used — generate a new token in the SOC Platform dashboard.",
            status_code=404,
        )
    if resp.status_code == 409:
        raise EnrollmentError(
            "Installer token is already in use — another installation is in progress.",
            status_code=409,
        )
    if resp.status_code == 422:
        raise EnrollmentError(
            f"Installer token has expired or is invalid: {_extract_error(resp)}",
            status_code=422,
        )
    if resp.status_code == 429:
        raise EnrollmentError(
            "Enrollment rate limit exceeded — wait before retrying.",
            status_code=429,
        )
    if not resp.ok:
        raise EnrollmentError(
            f"Enrollment failed (HTTP {resp.status_code}): {_extract_error(resp)}",
            status_code=resp.status_code,
        )

    try:
        data = resp.json()["data"]
    except (ValueError, KeyError) as exc:
        raise EnrollmentError(f"Invalid response from server: {exc}") from exc

    try:
        return RuntimeCredentials(
            agent_id=uuid.UUID(data["agent_id"]),
            enrollment_token=data["enrollment_token"],
            tenant_id=uuid.UUID(data["tenant_id"]),
            installer_token_id=uuid.UUID(data["installer_token_id"]),
            api_url=api_url.rstrip("/"),
        )
    except (KeyError, ValueError) as exc:
        raise EnrollmentError(f"Incomplete enrollment response: {exc}") from exc


def _extract_error(resp: requests.Response) -> str:
    try:
        body = resp.json()
        return (
            body.get("error", {}).get("message")
            or body.get("detail")
            or resp.text[:200]
        )
    except Exception:
        return resp.text[:200]
