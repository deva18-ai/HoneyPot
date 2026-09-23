import pytest
from httpx import AsyncClient


class TestAuth:
    @pytest.mark.asyncio
    async def test_login_success(self, client: AsyncClient, admin_user):
        response = await client.post(
            "/api/v1/auth/login",
            data={"username": "admin", "password": "admin123"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, client: AsyncClient):
        response = await client.post(
            "/api/v1/auth/login",
            data={"username": "admin", "password": "wrong"},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_login_inactive_user(self, client: AsyncClient, db_session):
        from backend.core.security import hash_password
        from backend.models import User

        user = User(
            username="inactive",
            email="inactive@test.com",
            password_hash=hash_password("password123"),
            role="viewer",
            is_active=False,
        )
        db_session.add(user)
        await db_session.commit()

        response = await client.post(
            "/api/v1/auth/login",
            data={"username": "inactive", "password": "password123"},
        )
        assert response.status_code == 400
        assert response.json()["detail"] == "Inactive user"

    @pytest.mark.asyncio
    async def test_refresh_token(self, client: AsyncClient, admin_user):
        login_response = await client.post(
            "/api/v1/auth/login",
            data={"username": "admin", "password": "admin123"},
        )
        refresh_token = login_response.json()["refresh_token"]

        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data

    @pytest.mark.asyncio
    async def test_refresh_invalid_token(self, client: AsyncClient):
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid_token"},
        )
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_get_me(self, client: AsyncClient, auth_headers):
        response = await client.get("/api/v1/auth/me", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "admin"
        assert data["role"] == "admin"

    @pytest.mark.asyncio
    async def test_rate_limit_login(self, client: AsyncClient):
        for _ in range(6):
            response = await client.post(
                "/api/v1/auth/login",
                data={"username": "admin", "password": "wrong"},
            )
        assert response.status_code == 429
