"""Tests for WebSocket auth helpers."""

from types import SimpleNamespace

import pytest

from app.api.chat import authenticate_ws


@pytest.mark.anyio
async def test_authenticate_ws_uses_configured_algorithm(monkeypatch):
    captured: dict[str, str] = {}

    def fake_verify_token(token: str, secret: str, algorithm: str = "HS256"):
        captured["token"] = token
        captured["secret"] = secret
        captured["algorithm"] = algorithm
        return {"sub": "user-123", "role": "analyst", "tenant_id": "tenant-x"}

    monkeypatch.setattr("app.api.chat.verify_token", fake_verify_token)
    monkeypatch.setattr(
        "app.api.chat.get_settings",
        lambda: SimpleNamespace(jwt_secret="ws-secret", jwt_algorithm="HS512"),
    )

    user = await authenticate_ws("token-abc")

    assert captured == {
        "token": "token-abc",
        "secret": "ws-secret",
        "algorithm": "HS512",
    }
    assert user["sub"] == "user-123"
    assert user["user_id"] == "user-123"
    assert user["tenant_id"] == "tenant-x"
