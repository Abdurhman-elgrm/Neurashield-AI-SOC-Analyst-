"""
Tests for soc_agent.credential_store

Coverage:
- store / load roundtrip (non-Windows Fernet path)
- store / load roundtrip (mocked DPAPI path)
- missing file raises FileNotFoundError
- corrupt ciphertext raises CredentialError
- truncated file raises CredentialError
- atomic write: tmp file renamed, no partial state on disk
- POSIX permissions set to 0o600 after write
"""
from __future__ import annotations

import stat
import sys
import platform
import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_creds(**overrides):
    from soc_agent.enrollment import RuntimeCredentials
    defaults = dict(
        agent_id=uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001"),
        enrollment_token="tok_live_xxxx",
        tenant_id=uuid.UUID("bbbbbbbb-0000-0000-0000-000000000002"),
        installer_token_id=uuid.UUID("cccccccc-0000-0000-0000-000000000003"),
        api_url="https://soc.example.com",
    )
    return RuntimeCredentials(**{**defaults, **overrides})


# ─── Non-Windows (Fernet) path ────────────────────────────────────────────────

class TestFernetRoundtrip:
    def test_store_and_load(self, tmp_path):
        from soc_agent.credential_store import store_credentials, load_credentials

        cred_file = tmp_path / "runtime.dat"
        creds = _make_creds()

        with patch("soc_agent.credential_store._is_windows", return_value=False):
            store_credentials(creds, cred_file)
            loaded = load_credentials(cred_file)

        assert loaded.agent_id == creds.agent_id
        assert loaded.enrollment_token == creds.enrollment_token
        assert loaded.tenant_id == creds.tenant_id
        assert loaded.installer_token_id == creds.installer_token_id
        assert loaded.api_url == creds.api_url

    def test_file_is_not_plaintext(self, tmp_path):
        from soc_agent.credential_store import store_credentials

        cred_file = tmp_path / "runtime.dat"
        creds = _make_creds()

        with patch("soc_agent.credential_store._is_windows", return_value=False):
            store_credentials(creds, cred_file)

        raw = cred_file.read_bytes()
        assert b"tok_live" not in raw, "Enrollment token must not appear in plaintext"
        assert b"enrollment_token" not in raw, "JSON keys must not appear in plaintext"

    @pytest.mark.skipif(
        __import__("platform").system() == "Windows",
        reason="POSIX chmod semantics are not enforced on Windows"
    )
    def test_posix_permissions(self, tmp_path):
        from soc_agent.credential_store import store_credentials

        cred_file = tmp_path / "runtime.dat"
        creds = _make_creds()

        with patch("soc_agent.credential_store._is_windows", return_value=False):
            store_credentials(creds, cred_file)

        mode = cred_file.stat().st_mode & 0o777
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    def test_creates_parent_directory(self, tmp_path):
        from soc_agent.credential_store import store_credentials

        cred_file = tmp_path / "creds" / "sub" / "runtime.dat"
        creds = _make_creds()

        with patch("soc_agent.credential_store._is_windows", return_value=False):
            store_credentials(creds, cred_file)

        assert cred_file.exists()


# ─── DPAPI (mocked win32crypt) path ───────────────────────────────────────────

class TestDPAPIRoundtrip:
    def test_store_and_load(self, tmp_path):
        from soc_agent.credential_store import store_credentials, load_credentials

        cred_file = tmp_path / "runtime.dat"
        creds = _make_creds()

        with patch("soc_agent.credential_store._is_windows", return_value=True):
            store_credentials(creds, cred_file)
            loaded = load_credentials(cred_file)

        assert loaded.agent_id == creds.agent_id
        assert loaded.enrollment_token == creds.enrollment_token

    def test_dpapi_sentinel_in_file(self, tmp_path):
        from soc_agent.credential_store import store_credentials

        cred_file = tmp_path / "runtime.dat"
        creds = _make_creds()

        with patch("soc_agent.credential_store._is_windows", return_value=True):
            store_credentials(creds, cred_file)

        # Our fake win32crypt prepends "DPAPI:" — real DPAPI would have a blob header
        assert cred_file.read_bytes().startswith(b"DPAPI:")


# ─── Error cases ──────────────────────────────────────────────────────────────

class TestErrorCases:
    def test_missing_file_raises(self, tmp_path):
        from soc_agent.credential_store import load_credentials

        with pytest.raises(FileNotFoundError):
            load_credentials(tmp_path / "does_not_exist.dat")

    def test_corrupt_fernet_raises_credential_error(self, tmp_path):
        from soc_agent.credential_store import load_credentials, CredentialError

        cred_file = tmp_path / "runtime.dat"
        cred_file.write_bytes(b"this is not a valid Fernet token")

        with patch("soc_agent.credential_store._is_windows", return_value=False):
            with pytest.raises(CredentialError, match="Failed to decrypt"):
                load_credentials(cred_file)

    def test_corrupt_dpapi_raises_credential_error(self, tmp_path):
        from soc_agent.credential_store import load_credentials, CredentialError

        cred_file = tmp_path / "runtime.dat"
        # Fake DPAPI blob without the DPAPI: prefix — will fail our stub
        cred_file.write_bytes(b"garbage bytes that are not a valid DPAPI blob")

        with patch("soc_agent.credential_store._is_windows", return_value=True):
            with pytest.raises(CredentialError, match="Failed to decrypt"):
                load_credentials(cred_file)

    def test_truncated_file_raises_credential_error(self, tmp_path):
        from soc_agent.credential_store import load_credentials, CredentialError

        cred_file = tmp_path / "runtime.dat"
        cred_file.write_bytes(b"")

        with patch("soc_agent.credential_store._is_windows", return_value=False):
            with pytest.raises(CredentialError):
                load_credentials(cred_file)

    def test_valid_ciphertext_but_missing_json_keys(self, tmp_path):
        """Decryption succeeds but JSON is missing expected keys → CredentialError."""
        from soc_agent.credential_store import load_credentials, CredentialError
        from cryptography.fernet import Fernet
        import base64, hashlib, json

        cred_file = tmp_path / "runtime.dat"

        # Encrypt valid JSON that's missing required fields
        raw = ""
        try:
            for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
                if Path(path).exists():
                    raw = open(path).read().strip()
                    break
        except Exception:
            pass
        if not raw:
            import socket as _s
            raw = _s.gethostname() + "-soc-analyst-v2"
        key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())
        partial = json.dumps({"agent_id": "not-a-uuid"}).encode()
        cred_file.write_bytes(Fernet(key).encrypt(partial))

        with patch("soc_agent.credential_store._is_windows", return_value=False):
            with pytest.raises(CredentialError, match="Corrupt"):
                load_credentials(cred_file)


# ─── Atomic write ─────────────────────────────────────────────────────────────

class TestAtomicWrite:
    def test_no_tmp_file_left_after_success(self, tmp_path):
        from soc_agent.credential_store import store_credentials

        cred_file = tmp_path / "runtime.dat"
        creds = _make_creds()

        with patch("soc_agent.credential_store._is_windows", return_value=False):
            store_credentials(creds, cred_file)

        tmp_file = cred_file.with_suffix(".tmp")
        assert not tmp_file.exists(), ".tmp file should be renamed away after atomic write"
        assert cred_file.exists()

    def test_credentials_exist_utility(self, tmp_path):
        from soc_agent.credential_store import store_credentials, credentials_exist

        cred_file = tmp_path / "runtime.dat"
        assert not credentials_exist(cred_file)

        creds = _make_creds()
        with patch("soc_agent.credential_store._is_windows", return_value=False):
            store_credentials(creds, cred_file)

        assert credentials_exist(cred_file)
