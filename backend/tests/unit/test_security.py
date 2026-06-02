from __future__ import annotations

import pytest

from app.core.exceptions import UnauthorizedError
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_access_token,
    decode_refresh_token,
    hash_password,
    needs_rehash,
    verify_password,
)


class TestPasswordHashing:
    def test_hash_is_not_plaintext(self) -> None:
        hashed = hash_password("mypassword")
        assert hashed != "mypassword"
        assert len(hashed) > 20

    def test_verify_correct_password(self) -> None:
        hashed = hash_password("correct_password")
        assert verify_password("correct_password", hashed) is True

    def test_reject_wrong_password(self) -> None:
        hashed = hash_password("correct_password")
        assert verify_password("wrong_password", hashed) is False

    def test_unique_hashes_for_same_password(self) -> None:
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2  # Different salts

    def test_needs_rehash_returns_bool(self) -> None:
        hashed = hash_password("password")
        assert isinstance(needs_rehash(hashed), bool)


class TestAccessTokens:
    def test_create_and_decode_access_token(self) -> None:
        subject = "user-uuid-1234"
        token = create_access_token(subject)
        payload = decode_access_token(token)
        assert payload.sub == subject
        assert payload.token_type == "access"

    def test_reject_wrong_token_type(self) -> None:
        _, _ = create_refresh_token("user-1")
        # Refresh token cannot be used as access token
        refresh_token, _ = create_refresh_token("user-1")
        with pytest.raises(UnauthorizedError):
            decode_access_token(refresh_token)

    def test_reject_invalid_token(self) -> None:
        with pytest.raises(UnauthorizedError):
            decode_access_token("not.a.valid.jwt")

    def test_reject_tampered_token(self) -> None:
        token = create_access_token("user-1")
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(UnauthorizedError):
            decode_access_token(tampered)


class TestRefreshTokens:
    def test_create_and_decode_refresh_token(self) -> None:
        subject = "user-uuid-5678"
        token, jti = create_refresh_token(subject)
        payload = decode_refresh_token(token)
        assert payload.sub == subject
        assert payload.jti == jti
        assert payload.token_type == "refresh"

    def test_jti_is_unique_per_token(self) -> None:
        _, jti1 = create_refresh_token("user-1")
        _, jti2 = create_refresh_token("user-1")
        assert jti1 != jti2

    def test_reject_access_token_as_refresh(self) -> None:
        access = create_access_token("user-1")
        with pytest.raises(UnauthorizedError):
            decode_refresh_token(access)


class TestRBAC:
    def test_owner_has_all_permissions(self) -> None:
        from app.rbac.permissions import Permission
        from app.rbac.roles import Role, get_role_permissions
        owner_perms = get_role_permissions(Role.OWNER)
        for perm in Permission:
            assert perm in owner_perms

    def test_viewer_cannot_manage(self) -> None:
        from app.rbac.permissions import Permission
        from app.rbac.roles import Role, has_permission
        assert has_permission(Role.VIEWER, Permission.ALERTS_UPDATE) is False
        assert has_permission(Role.VIEWER, Permission.AGENTS_MANAGE) is False
        assert has_permission(Role.VIEWER, Permission.TENANT_DELETE) is False

    def test_viewer_can_read(self) -> None:
        from app.rbac.permissions import Permission
        from app.rbac.roles import Role, has_permission
        assert has_permission(Role.VIEWER, Permission.ALERTS_READ) is True
        assert has_permission(Role.VIEWER, Permission.EVENTS_READ) is True

    def test_analyst_can_acknowledge(self) -> None:
        from app.rbac.permissions import Permission
        from app.rbac.roles import Role, has_permission
        assert has_permission(Role.ANALYST, Permission.ALERTS_UPDATE) is True

    def test_role_hierarchy(self) -> None:
        from app.rbac.roles import Role, has_minimum_role
        assert has_minimum_role(Role.OWNER, Role.ADMIN) is True
        assert has_minimum_role(Role.ADMIN, Role.ANALYST) is True
        assert has_minimum_role(Role.VIEWER, Role.ANALYST) is False
        assert has_minimum_role(Role.ANALYST, Role.ADMIN) is False
