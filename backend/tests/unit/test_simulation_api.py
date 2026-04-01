import pytest
from fastapi.testclient import TestClient
from main import app
from src.security.auth_manager import TokenManager, UserRole

client = TestClient(app)

@pytest.fixture
def auth_header():
    # Create a mock token for a test user
    token = TokenManager.create_access_token(
        user_id="test_user_123",
        username="test_admin",
        email="admin@example.com",
        role=UserRole.ADMIN
    )
    return {"Authorization": f"Bearer {token}"}

def test_simulate_generic(auth_header):
    response = client.get("/api/simulate", headers=auth_header)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "fraud_event" in data
    assert data["fraud_event"]["scenario_id"] == "generic"

def test_simulate_supply_chain(auth_header):
    response = client.get("/api/simulate?scenario=supply-chain", headers=auth_header)
    assert response.status_code == 200
    data = response.json()
    assert data["fraud_event"]["scenario_id"] == "supply-chain"
    assert "supply chain compromise" in data["fraud_event"]["message"].lower()
    assert data["fraud_event"]["risk_score"] >= 0.8

def test_simulate_secret_leak(auth_header):
    response = client.get("/api/simulate?scenario=secret-leak", headers=auth_header)
    assert response.status_code == 200
    data = response.json()
    assert data["fraud_event"]["scenario_id"] == "secret-leak"
    assert "sensitive PAT string" in data["fraud_event"]["message"]

def test_simulate_invalid_scenario(auth_header):
    response = client.get("/api/simulate?scenario=non-existent", headers=auth_header)
    assert response.status_code == 404

def test_simulate_unauthorized():
    response = client.get("/api/simulate")
    # FastAPI HTTPBearer returns 403 if missing header by default
    assert response.status_code in [401, 403]
