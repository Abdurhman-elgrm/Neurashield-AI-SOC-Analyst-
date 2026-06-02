"""
Shared fixtures for the installer test suite.

Key design choices:
- win32crypt is mocked globally via sys.modules injection so tests run on Linux/CI.
- requests is NOT patched globally; each test file uses the `responses` library or
  pytest-mock to intercept HTTP at the boundary it cares about.
- tmpdir_install_dir yields a realistic directory tree under pytest's tmp_path.
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest


# ─── win32crypt stub ──────────────────────────────────────────────────────────
# Inject a fake win32crypt module before any soc_agent import so the DPAPI
# code-path can be exercised without a Windows environment.

class _FakeWin32Crypt:
    """Minimal stand-in for win32crypt: encrypt/decrypt are identity operations."""

    @staticmethod
    def CryptProtectData(data: bytes, *args, **kwargs) -> bytes:
        # Prefix with a sentinel to distinguish from plaintext
        return b"DPAPI:" + data

    @staticmethod
    def CryptUnprotectData(data: bytes, *args, **kwargs):
        if data.startswith(b"DPAPI:"):
            return ("SOCAnalystAgent v2 Runtime Credentials", data[6:])
        raise ValueError("Invalid DPAPI blob")


# Inject unconditionally so tests are platform-agnostic
if "win32crypt" not in sys.modules:
    sys.modules["win32crypt"] = _FakeWin32Crypt()  # type: ignore[assignment]

# Also stub the pywin32 service modules so service.py is importable everywhere
for _mod in ("win32event", "win32service", "win32serviceutil", "servicemanager", "win32evtlog"):
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()


# ─── Shared credential factory ────────────────────────────────────────────────

@pytest.fixture()
def sample_creds():
    from soc_agent.enrollment import RuntimeCredentials
    return RuntimeCredentials(
        agent_id=uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001"),
        enrollment_token="tok_live_abcdefghijklmnopqrstuvwx",
        tenant_id=uuid.UUID("bbbbbbbb-0000-0000-0000-000000000002"),
        installer_token_id=uuid.UUID("cccccccc-0000-0000-0000-000000000003"),
        api_url="https://soc.example.com",
    )


# ─── Temp install directory ───────────────────────────────────────────────────

@pytest.fixture()
def install_dir(tmp_path: Path) -> Path:
    """A temp directory pre-seeded with the standard SOCAnalyst subdirectory tree."""
    root = tmp_path / "SOCAnalyst"
    for sub in ("bin", "config", "credentials", "logs", "state", "tmp"):
        (root / sub).mkdir(parents=True)
    return root


# ─── Enrollment HTTP response helpers ─────────────────────────────────────────

def enroll_ok_body(
    agent_id: str = "aaaaaaaa-0000-0000-0000-000000000001",
    enrollment_token: str = "tok_live_abcdefghijklmnopqrstuvwx",
    tenant_id: str = "bbbbbbbb-0000-0000-0000-000000000002",
    installer_token_id: str = "cccccccc-0000-0000-0000-000000000003",
) -> dict:
    return {
        "data": {
            "agent_id": agent_id,
            "enrollment_token": enrollment_token,
            "tenant_id": tenant_id,
            "installer_token_id": installer_token_id,
        }
    }
