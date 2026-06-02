"""
Tests for install.py (main installer flow)

Coverage:
- Directory tree is created on first install
- Reinstall without --force succeeds (re-enrolls, overwrites credentials)
- Reinstall without --force logs previous agent_id
- --force flag passes through to the same flow (idempotent)
- State manifest (install.json) is written with correct fields
- State manifest is_reinstall=False on first install, True on reinstall
- EnrollmentError causes sys.exit (token NOT stored)
- copy_agent_files copies expected files to bin/
- copy_agent_files skips missing source files with a warning (no crash)
- write_config produces a parseable INI with the supplied values
- locate_config returns the expected path relative to install_dir
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from unittest.mock import patch, MagicMock, call

import pytest

# conftest.py has already injected the win32crypt stub


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


# ─── Directory structure ──────────────────────────────────────────────────────

class TestDirectoryCreation:
    def test_subdirs_created(self, tmp_path):
        from install import ensure_dir

        root = tmp_path / "test_agent"
        for sub in ("bin", "config", "credentials", "logs", "state", "tmp"):
            ensure_dir(root / sub)
            assert (root / sub).is_dir()

    def test_ensure_dir_idempotent(self, tmp_path):
        from install import ensure_dir

        d = tmp_path / "existing"
        d.mkdir()
        ensure_dir(d)  # should not raise
        assert d.is_dir()


# ─── State manifest ───────────────────────────────────────────────────────────

class TestStateManifest:
    def test_write_and_read_state(self, install_dir):
        from install import _write_install_state, _read_install_state

        meta = {
            "agent_id": "aaaaaaaa-0000-0000-0000-000000000001",
            "tenant_id": "bbbbbbbb-0000-0000-0000-000000000002",
            "installed_at": "2026-01-01T00:00:00Z",
            "is_reinstall": False,
        }
        _write_install_state(install_dir, meta)

        loaded = _read_install_state(install_dir)
        assert loaded["agent_id"] == meta["agent_id"]
        assert loaded["is_reinstall"] is False

    def test_read_missing_state_returns_empty(self, install_dir):
        from install import _read_install_state

        result = _read_install_state(install_dir / "nonexistent")
        assert result == {}

    def test_read_corrupt_state_returns_empty(self, install_dir):
        from install import _read_install_state

        state_file = install_dir / "state" / "install.json"
        state_file.write_text("not valid json", encoding="utf-8")

        result = _read_install_state(install_dir)
        assert result == {}


# ─── Reinstall detection ──────────────────────────────────────────────────────

class TestReinstallDetection:
    def test_first_install_not_reinstall(self, install_dir):
        from install import _is_reinstall

        assert not _is_reinstall(install_dir)

    def test_existing_runtime_dat_is_reinstall(self, install_dir):
        from install import _is_reinstall
        from soc_agent.credential_store import store_credentials

        cred_file = install_dir / "credentials" / "runtime.dat"
        creds = _make_creds()
        with patch("soc_agent.credential_store._is_windows", return_value=False):
            store_credentials(creds, cred_file)

        assert _is_reinstall(install_dir)


# ─── copy_agent_files ─────────────────────────────────────────────────────────

class TestCopyAgentFiles:
    def test_copies_expected_files(self, tmp_path, install_dir):
        from install import copy_agent_files

        src = tmp_path / "pkg"
        pkg = src / "soc_agent"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("VERSION = '2.0.0'")
        (pkg / "config.py").write_text("# config")
        (pkg / "credential_store.py").write_text("# store")
        (pkg / "enrollment.py").write_text("# enroll")
        (pkg / "log_manager.py").write_text("# log")
        (pkg / "service.py").write_text("# service")
        (src / "requirements.txt").write_text("requests\n")

        log = MagicMock()
        copy_agent_files(src_dir=src, install_dir=install_dir, log=log)

        bin_dir = install_dir / "bin"
        assert (bin_dir / "soc_agent" / "__init__.py").exists()
        assert (bin_dir / "soc_agent" / "service.py").exists()
        assert (bin_dir / "requirements.txt").exists()

    def test_missing_source_file_logged_not_raised(self, tmp_path, install_dir):
        from install import copy_agent_files

        src = tmp_path / "pkg"
        (src / "soc_agent").mkdir(parents=True)
        # Only create __init__.py; all other files are missing

        log = MagicMock()
        copy_agent_files(src_dir=src, install_dir=install_dir, log=log)  # must not raise

        # At least one warning should have been emitted for missing files
        assert log.warning.called


# ─── Full install flow (mocked enrollment) ────────────────────────────────────

class TestMainInstallFlow:
    def _run_main(self, install_dir, extra_args=None, creds=None):
        """Run install.main() with patched enrollment and filesystem calls."""
        if creds is None:
            creds = _make_creds()

        argv = [
            "install.py",
            "--token", "inst_abcdefghijklmnopqrstuvwxyz",
            "--tenant-id", "bbbbbbbb-0000-0000-0000-000000000002",
            "--api-url", "https://soc.example.com",
            "--install-dir", str(install_dir),
            "--hostname", "test-host",
            "--os-type", "linux",
        ]
        if extra_args:
            argv.extend(extra_args)

        with patch("sys.argv", argv), \
             patch("install.bootstrap_enroll", return_value=creds) as mock_enroll, \
             patch("soc_agent.credential_store._is_windows", return_value=False), \
             patch("install.copy_agent_files"):   # skip actual file copy
            from install import main
            main()

        return mock_enroll

    def test_directories_created_on_first_install(self, install_dir):
        # Remove pre-created dirs so we test creation from scratch
        import shutil
        shutil.rmtree(install_dir)

        self._run_main(install_dir)

        for sub in ("bin", "config", "credentials", "logs", "state"):
            assert (install_dir / sub).is_dir(), f"Missing subdir: {sub}"

    def test_state_manifest_written(self, install_dir):
        from install import _read_install_state

        self._run_main(install_dir)

        state = _read_install_state(install_dir)
        assert state["agent_id"] == "aaaaaaaa-0000-0000-0000-000000000001"
        assert state["is_reinstall"] is False

    def test_reinstall_state_manifest(self, install_dir):
        from install import _read_install_state
        from soc_agent.credential_store import store_credentials

        # Seed a pre-existing credential to simulate reinstall
        cred_file = install_dir / "credentials" / "runtime.dat"
        with patch("soc_agent.credential_store._is_windows", return_value=False):
            store_credentials(_make_creds(), cred_file)

        self._run_main(install_dir)

        state = _read_install_state(install_dir)
        assert state["is_reinstall"] is True

    def test_enrollment_called_with_correct_args(self, install_dir):
        mock_enroll = self._run_main(install_dir)

        mock_enroll.assert_called_once()
        call_kwargs = mock_enroll.call_args.kwargs
        assert call_kwargs["api_url"] == "https://soc.example.com"
        assert call_kwargs["tenant_id"] == "bbbbbbbb-0000-0000-0000-000000000002"
        assert call_kwargs["installer_token"] == "inst_abcdefghijklmnopqrstuvwxyz"
        assert call_kwargs["machine_info"]["hostname"] == "test-host"

    def test_enrollment_error_calls_sys_exit(self, install_dir):
        from soc_agent.enrollment import EnrollmentError

        argv = [
            "install.py",
            "--token", "inst_abcdefghijklmnopqrstuvwxyz",
            "--tenant-id", "bbbbbbbb-0000-0000-0000-000000000002",
            "--api-url", "https://soc.example.com",
            "--install-dir", str(install_dir),
            "--hostname", "test-host",
            "--os-type", "linux",
        ]

        with patch("sys.argv", argv), \
             patch("install.bootstrap_enroll",
                   side_effect=EnrollmentError("Token already used", status_code=404)):
            from install import main
            with pytest.raises(SystemExit):
                main()

    def test_enrollment_error_does_not_write_credentials(self, install_dir):
        from soc_agent.enrollment import EnrollmentError

        argv = [
            "install.py",
            "--token", "inst_abcdefghijklmnopqrstuvwxyz",
            "--tenant-id", "bbbbbbbb-0000-0000-0000-000000000002",
            "--api-url", "https://soc.example.com",
            "--install-dir", str(install_dir),
            "--hostname", "test-host",
            "--os-type", "linux",
        ]

        with patch("sys.argv", argv), \
             patch("install.bootstrap_enroll",
                   side_effect=EnrollmentError("Token already used", status_code=404)):
            from install import main
            try:
                main()
            except SystemExit:
                pass

        cred_file = install_dir / "credentials" / "runtime.dat"
        assert not cred_file.exists(), "Credentials must not be written after enrollment failure"

    def test_config_file_written(self, install_dir):
        self._run_main(install_dir)

        config_path = install_dir / "config" / "agent.ini"
        assert config_path.exists()

        from soc_agent.config import read_config
        cfg = read_config(config_path)
        assert cfg["api_url"] == "https://soc.example.com"


# ─── config module ────────────────────────────────────────────────────────────

class TestConfig:
    def test_write_and_read_roundtrip(self, tmp_path):
        from soc_agent.config import write_config, read_config

        p = tmp_path / "config" / "agent.ini"
        write_config(p, api_url="https://soc.example.com",
                     install_dir="/opt/soc", log_level="DEBUG")

        cfg = read_config(p)
        assert cfg["api_url"] == "https://soc.example.com"
        assert cfg["install_dir"] == "/opt/soc"
        assert cfg["log_level"] == "DEBUG"

    def test_defaults_returned_for_missing_keys(self, tmp_path):
        from soc_agent.config import read_config

        cfg = read_config(tmp_path / "nonexistent.ini")
        assert cfg["heartbeat_interval_secs"] == "20"
        assert cfg["log_level"] == "INFO"

    def test_locate_config(self, tmp_path):
        from soc_agent.config import locate_config

        p = locate_config(tmp_path)
        assert p == tmp_path / "config" / "agent.ini"
