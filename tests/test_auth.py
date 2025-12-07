import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_register_user_success(client: AsyncClient):
    payload = {
        "name": "Test User",
        "username": "testuser",
        "email": "test@example.com",
        "password": "Password123!",
        "confirmPassword": "Password123!"
    }
    response = await client.post("/api/users/signup", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert "detail" in data

@pytest.mark.asyncio
async def test_login_user_success(client: AsyncClient, db):
    # Register first
    register_payload = {
        "name": "Login User",
        "username": "loginuser",
        "email": "login@example.com",
        "password": "Password123!",
        "confirmPassword": "Password123!"
    }
    await client.post("/api/users/signup", json=register_payload)

    # Manually verify user in DB to allow login
    await db["users"].update_one(
        {"username": "loginuser"}, 
        {"$set": {"isEmailVerified": True}}
    )

    # Login
    login_data = {
        "username": "loginuser",
        "password": "Password123!"
    }
    response = await client.post("/api/auth/signin", data=login_data)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

@pytest.mark.asyncio
async def test_login_invalid_credentials(client: AsyncClient):
    login_data = {
        "username": "nonexistent",
        "password": "WrongPassword123!"
    }
    response = await client.post("/api/auth/signin", data=login_data)
    # Depending on implementation, it might be 401 or 400. 
    # OAuth2PasswordRequestForm failure is usually 400 or 401.
    # src/auth/service.py authenticate_user raises IncorrectCredentialsError -> 401 likely.
    assert response.status_code in [400, 401] 
