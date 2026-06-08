"""Tests for JWT and password security."""

import pytest

from app.core.security import create_access_token, verify_token, hash_password, verify_password


class TestJWT:
    def test_create_and_verify_token(self):
        token = create_access_token({"sub": "user-123", "role": "analyst"}, secret="test-secret")
        payload = verify_token(token, secret="test-secret")
        assert payload["sub"] == "user-123"
        assert payload["role"] == "analyst"
        assert "exp" in payload

    def test_invalid_token(self):
        result = verify_token("invalid.token.here", secret="test-secret")
        assert result is None

    def test_wrong_secret(self):
        token = create_access_token({"sub": "user-123"}, secret="secret-a")
        result = verify_token(token, secret="secret-b")
        assert result is None

    def test_token_contains_exp(self):
        token = create_access_token({"sub": "user-123"}, secret="test-secret", expires_minutes=30)
        payload = verify_token(token, secret="test-secret")
        assert payload is not None
        assert "exp" in payload


class TestPassword:
    def test_hash_and_verify(self):
        hashed = hash_password("mypassword")
        assert verify_password("mypassword", hashed) is True

    def test_wrong_password(self):
        hashed = hash_password("mypassword")
        assert verify_password("wrongpassword", hashed) is False

    def test_different_hashes(self):
        h1 = hash_password("samepassword")
        h2 = hash_password("samepassword")
        assert h1 != h2  # bcrypt salts differ
