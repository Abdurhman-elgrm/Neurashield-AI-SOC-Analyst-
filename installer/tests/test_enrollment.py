"""
Tests for soc_agent.enrollment (bootstrap_enroll)

Coverage:
- Successful enrollment returns correct RuntimeCredentials
- Token replay (404) raises EnrollmentError with helpful message
- Token in-use (409) raises EnrollmentError
- Expired/invalid token (422) raises EnrollmentError
- Rate limit (429) raises EnrollmentError
- Generic server error (500) raises EnrollmentError with status code
- Network error (connection refused) raises EnrollmentError
- Malformed JSON response raises EnrollmentError
- Response missing expected fields raises EnrollmentError
- Token is sent in body, never in URL or header
- api_url trailing slash is stripped
"""
from __future__ import annotations

import uuid
from unittest.mock import patch, MagicMock

import pytest
import responses as resp_lib
from responses import matchers

from soc_agent.enrollment import bootstrap_enroll, EnrollmentError, RuntimeCredentials

_API_URL = "https://soc.example.com"
_ENROLL_URL = f"{_API_URL}/api/v1/installer/bootstrap-enroll"
_TENANT_ID = "bbbbbbbb-0000-0000-0000-000000000002"
_TOKEN = "inst_abcdefghijklmnopqrstuvwxyz"

_MACHINE_INFO = {
    "hostname": "test-host",
    "os_type": "windows",
    "ip_address": "10.0.0.5",
    "agent_version": "2.0.0",
}

_OK_RESPONSE = {
    "data": {
        "agent_id": "aaaaaaaa-0000-0000-0000-000000000001",
        "enrollment_token": "tok_live_xxxx",
        "tenant_id": _TENANT_ID,
        "installer_token_id": "cccccccc-0000-0000-0000-000000000003",
    }
}


def _enroll(**kwargs):
    params = dict(
        api_url=_API_URL,
        tenant_id=_TENANT_ID,
        installer_token=_TOKEN,
        machine_info=_MACHINE_INFO,
    )
    params.update(kwargs)
    return bootstrap_enroll(**params)


# ─── Success path ─────────────────────────────────────────────────────────────

class TestSuccessfulEnrollment:
    @resp_lib.activate
    def test_returns_runtime_credentials(self):
        resp_lib.add(resp_lib.POST, _ENROLL_URL, json=_OK_RESPONSE, status=200)

        creds = _enroll()

        assert isinstance(creds, RuntimeCredentials)
        assert creds.agent_id == uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
        assert creds.enrollment_token == "tok_live_xxxx"
        assert creds.tenant_id == uuid.UUID(_TENANT_ID)
        assert creds.api_url == _API_URL

    @resp_lib.activate
    def test_api_url_trailing_slash_stripped(self):
        resp_lib.add(resp_lib.POST, _ENROLL_URL, json=_OK_RESPONSE, status=200)

        creds = bootstrap_enroll(
            api_url=_API_URL + "/",
            tenant_id=_TENANT_ID,
            installer_token=_TOKEN,
            machine_info=_MACHINE_INFO,
        )

        assert creds.api_url == _API_URL  # no trailing slash

    @resp_lib.activate
    def test_token_sent_in_body_not_url(self):
        """Token must never appear in the URL path or query string."""
        captured_requests = []

        def capture(req):
            captured_requests.append(req)
            return (200, {}, str(_OK_RESPONSE).replace("'", '"'))

        resp_lib.add_callback(resp_lib.POST, _ENROLL_URL, callback=capture,
                              content_type="application/json")

        # Use responses library properly
        resp_lib.reset()
        resp_lib.add(resp_lib.POST, _ENROLL_URL, json=_OK_RESPONSE, status=200)

        _enroll()

        req = resp_lib.calls[0].request
        assert _TOKEN not in req.url, "Raw token must not appear in the URL"

    @resp_lib.activate
    def test_token_sent_in_json_body(self):
        import json as _json
        resp_lib.add(resp_lib.POST, _ENROLL_URL, json=_OK_RESPONSE, status=200)

        _enroll()

        body = _json.loads(resp_lib.calls[0].request.body)
        assert body["token"] == _TOKEN
        assert body["tenant_id"] == _TENANT_ID
        assert "machine_info" in body


# ─── Token replay / error cases ───────────────────────────────────────────────

class TestErrorCases:
    @resp_lib.activate
    def test_404_token_not_found_or_used(self):
        resp_lib.add(resp_lib.POST, _ENROLL_URL, json={"error": "not found"}, status=404)

        with pytest.raises(EnrollmentError) as exc_info:
            _enroll()

        assert exc_info.value.status_code == 404
        assert "already used" in str(exc_info.value).lower() or \
               "not found" in str(exc_info.value).lower()

    @resp_lib.activate
    def test_409_token_already_in_use(self):
        resp_lib.add(resp_lib.POST, _ENROLL_URL, json={"error": "conflict"}, status=409)

        with pytest.raises(EnrollmentError) as exc_info:
            _enroll()

        assert exc_info.value.status_code == 409
        assert "in use" in str(exc_info.value).lower()

    @resp_lib.activate
    def test_422_token_expired_or_invalid(self):
        resp_lib.add(
            resp_lib.POST, _ENROLL_URL,
            json={"error": {"message": "Token has expired"}},
            status=422,
        )

        with pytest.raises(EnrollmentError) as exc_info:
            _enroll()

        assert exc_info.value.status_code == 422
        assert "expired" in str(exc_info.value).lower() or \
               "invalid" in str(exc_info.value).lower()

    @resp_lib.activate
    def test_429_rate_limit(self):
        resp_lib.add(resp_lib.POST, _ENROLL_URL, json={}, status=429)

        with pytest.raises(EnrollmentError) as exc_info:
            _enroll()

        assert exc_info.value.status_code == 429
        assert "rate limit" in str(exc_info.value).lower()

    @resp_lib.activate
    def test_500_server_error(self):
        resp_lib.add(resp_lib.POST, _ENROLL_URL,
                     json={"error": "internal"}, status=500)

        with pytest.raises(EnrollmentError) as exc_info:
            _enroll()

        assert exc_info.value.status_code == 500

    def test_network_error_raises_enrollment_error(self):
        from requests.exceptions import ConnectionError

        with patch("requests.post", side_effect=ConnectionError("connection refused")):
            with pytest.raises(EnrollmentError, match="Network error"):
                _enroll()


# ─── Malformed responses ──────────────────────────────────────────────────────

class TestMalformedResponses:
    @resp_lib.activate
    def test_non_json_response(self):
        resp_lib.add(resp_lib.POST, _ENROLL_URL,
                     body="<html>Gateway Timeout</html>",
                     content_type="text/html",
                     status=200)

        with pytest.raises(EnrollmentError, match="Invalid response"):
            _enroll()

    @resp_lib.activate
    def test_missing_data_key(self):
        resp_lib.add(resp_lib.POST, _ENROLL_URL,
                     json={"result": "ok"},  # no "data" key
                     status=200)

        with pytest.raises(EnrollmentError, match="Invalid response"):
            _enroll()

    @resp_lib.activate
    def test_incomplete_data_fields(self):
        """Response has "data" but is missing required fields."""
        resp_lib.add(resp_lib.POST, _ENROLL_URL,
                     json={"data": {"agent_id": "aaaaaaaa-0000-0000-0000-000000000001"}},
                     status=200)

        with pytest.raises(EnrollmentError, match="Incomplete"):
            _enroll()

    @resp_lib.activate
    def test_invalid_uuid_in_response(self):
        resp_lib.add(resp_lib.POST, _ENROLL_URL,
                     json={"data": {
                         "agent_id": "not-a-uuid",
                         "enrollment_token": "tok",
                         "tenant_id": _TENANT_ID,
                         "installer_token_id": "cccccccc-0000-0000-0000-000000000003",
                     }},
                     status=200)

        with pytest.raises(EnrollmentError, match="Incomplete"):
            _enroll()


# ─── Token is not stored on failure ───────────────────────────────────────────

class TestTokenNotStoredOnFailure:
    @resp_lib.activate
    def test_enrollment_error_does_not_return_partial_credentials(self):
        """Caller must receive an exception, never a partially-initialized object."""
        resp_lib.add(resp_lib.POST, _ENROLL_URL, json={}, status=404)

        result = None
        try:
            result = _enroll()
        except EnrollmentError:
            pass

        assert result is None, "bootstrap_enroll must not return on error"
