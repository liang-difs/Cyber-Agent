"""Tests for auth endpoints."""

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.anyio
async def test_login_success(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin123"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user_id"] == "00000000-0000-0000-0000-000000000001"
    assert data["role"] == "admin"
    assert data["tenant_id"] == "tenant-1"


@pytest.mark.anyio
async def test_login_wrong_password(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "wrong"},
    )
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_login_unknown_user(client):
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": "nobody", "password": "test"},
    )
    assert resp.status_code == 401
