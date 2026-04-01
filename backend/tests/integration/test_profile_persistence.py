import pytest
import os
import sqlite3
from fastapi.testclient import TestClient
from main import app
from src.security.auth_manager import TokenManager, UserRole
from src.services.user_db_service import UserDatabase, user_db

# Use a temporary test database
TEST_DB_PATH = "database/test_users.db"

@pytest.fixture(scope="module", autouse=True)
def setup_test_db():
    # Ensure directory exists
    os.makedirs("database", exist_ok=True)
    
    # Initialize test database
    test_db = UserDatabase(TEST_DB_PATH)
    
    # Override global user_db instance
    # Note: Because of how imports work, some modules might still use the old instance
    # unless we patch it where it's used.
    # In auth_routes.py, it's imported inside the route or from auth_manager.
    # We'll patch it in user_db_service.
    import src.services.user_db_service
    src.services.user_db_service.user_db = test_db
    
    yield test_db
    
    # Cleanup
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture(scope="module")
def test_user(setup_test_db):
    username = "test_profile_user"
    email = "profile@test.com"
    password = "SecurePassword@123"
    
    user_id = setup_test_db.create_user(username, email, password, UserRole.DEVELOPER)
    return {
        "user_id": user_id,
        "username": username,
        "email": email
    }

@pytest.fixture(scope="module")
def auth_header(test_user):
    token = TokenManager.create_access_token(
        user_id=test_user["user_id"],
        username=test_user["username"],
        email=test_user["email"],
        role=UserRole.DEVELOPER
    )
    return {"Authorization": f"Bearer {token}"}

def test_get_profile(client, auth_header, test_user):
    response = client.get("/api/auth/profile", headers=auth_header)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == test_user["username"]
    assert data["email"] == test_user["email"]

def test_update_profile_persistence(client, auth_header, test_user, setup_test_db):
    new_username = "updated_user_name"
    new_email = "updated@test.com"
    
    # Update profile via API
    response = client.put("/api/auth/profile", headers=auth_header, json={
        "username": new_username,
        "email": new_email
    })
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["user"]["username"] == new_username
    assert data["user"]["email"] == new_email
    
    # Verify persistence in database
    db_user = setup_test_db.get_user_by_id(test_user["user_id"])
    assert db_user is not None
    assert db_user.username == new_username
    assert db_user.email == new_email
    
    # Verify subsequent GET returns updated data
    # (Note: Token still has old data in its payload, but /profile endpoint 
    # might be using the token payload or fetching from DB)
    # Looking at auth_routes.py:
    # @router.get("/auth/profile")
    # async def get_profile(current_user: dict = Depends(get_current_user)):
    #     return current_user ...
    # Wait! get_current_user returns the token payload!
    # So /profile might return OLD data until token is refreshed if it just returns payload.
    # Let's check get_profile implementation in auth_routes.py.
    
    # If the endpoint returns the data from the token, we need a new token.
    # But the DB expectation is what matters for persistence.
    
    # Let's check /profile again with same header
    response = client.get("/api/auth/profile", headers=auth_header)
    # If it returns token data, it will be old.
    # If it fetches from DB using user_id from token, it will be new.
