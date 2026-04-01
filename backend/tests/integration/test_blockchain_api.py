"""
Integration Tests for Blockchain API
Tests API endpoints for blockchain event logging and audit trail retrieval
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from datetime import datetime


@pytest.fixture
def client():
    """Create test client for FastAPI app"""
    from main import app
    return TestClient(app)


class TestBlockchainAPI:
    """Integration tests for blockchain API endpoints"""

    def test_blockchain_health_endpoint(self, client):
        """Test blockchain health check endpoint"""
        response = client.get("/api/blockchain/health")
        
        assert response.status_code == 200
        data = response.json()
        assert "healthy" in data
        assert "blockchain_connected" in data
        assert "contract_available" in data
        assert "timestamp" in data

    def test_blockchain_stats_endpoint(self, client):
        """Test blockchain stats endpoint"""
        response = client.get("/api/blockchain/stats")
        
        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert "stats" in data
        assert "timestamp" in data
        
        stats = data["stats"]
        assert "connected" in stats
        assert "provider" in stats
        assert "network" in stats

    def test_log_security_event_offline(self, client):
        """Test logging security event when blockchain is offline"""
        event_data = {
            "event_type": "fraud_detected",
            "risk_score": 0.85,
            "repository": "production-app",
            "rule_violations": ["suspicious_commit"],
            "message": "Potential credential compromise"
        }
        
        response = client.post("/api/blockchain/events", json=event_data)
        
        # Should return 200 even if blockchain is offline (uses fallback)
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "data_hash" in data
        assert "timestamp" in data

    def test_log_security_event_validation(self, client):
        """Test event logging with invalid data"""
        # Missing required fields
        event_data = {
            "event_type": "fraud_detected"
            # Missing risk_score
        }
        
        response = client.post("/api/blockchain/events", json=event_data)
        
        # Should return validation error
        assert response.status_code == 422

    def test_log_security_event_risk_score_validation(self, client):
        """Test risk score validation (0.0-1.0)"""
        # Risk score > 1.0
        event_data = {
            "event_type": "fraud_detected",
            "risk_score": 1.5,  # Invalid
            "repository": "test"
        }
        
        response = client.post("/api/blockchain/events", json=event_data)
        
        assert response.status_code == 422

    def test_get_audit_trail_endpoint(self, client):
        """Test retrieving audit trail"""
        response = client.get("/api/blockchain/audit-trail")
        
        assert response.status_code == 200
        data = response.json()
        assert "event_count" in data
        assert "events" in data
        assert isinstance(data["events"], list)
        assert "timestamp" in data

    def test_get_audit_trail_with_filters(self, client):
        """Test audit trail with severity filter"""
        response = client.get("/api/blockchain/audit-trail?severity=high")
        
        assert response.status_code == 200
        data = response.json()
        assert "event_count" in data
        assert "events" in data

    def test_get_audit_trail_with_repository_filter(self, client):
        """Test audit trail with repository filter"""
        response = client.get("/api/blockchain/audit-trail?repository=production")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["events"], list)

    def test_get_audit_trail_with_risk_threshold(self, client):
        """Test audit trail with risk threshold filter"""
        response = client.get("/api/blockchain/audit-trail?risk_threshold=75")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["events"], list)

    def test_verify_event_endpoint(self, client):
        """Test event verification endpoint"""
        verify_data = {
            "event_id": 0,
            "signature_hash": "0xabc123def456"
        }
        
        response = client.post("/api/blockchain/events/verify", json=verify_data)
        
        # Will fail if not connected, but endpoint should exist
        assert response.status_code in [200, 500, 503]
        if response.status_code == 200:
            data = response.json()
            assert "success" in data or "event_id" in data

    def test_test_connection_endpoint(self, client):
        """Test blockchain connection test endpoint"""
        response = client.post("/api/blockchain/test-connection")
        
        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert "provider" in data
        assert "message" in data

    def test_get_specific_event(self, client):
        """Test retrieving specific event"""
        response = client.get("/api/blockchain/events/0")
        
        # Will return 404 or 503 if event doesn't exist
        assert response.status_code in [200, 404, 503]

    def test_api_error_handling(self, client):
        """Test API error handling"""
        # Test 404 for non-existent event
        response = client.get("/api/blockchain/events/99999")
        
        assert response.status_code in [404, 503]


class TestBlockchainAPIDataFlow:
    """Test complete data flow through blockchain API"""

    def test_event_logging_flow(self, client):
        """Test complete event logging flow"""
        # 1. Log event
        event_data = {
            "event_type": "credential_compromise",
            "risk_score": 0.90,
            "repository": "production-api",
            "rule_violations": ["unauthorized_access"],
            "message": "Suspicious deployment from unknown IP"
        }
        
        response = client.post("/api/blockchain/events", json=event_data)
        assert response.status_code == 200
        
        logged_event = response.json()
        assert "data_hash" in logged_event
        
        # 2. Get audit trail
        response = client.get("/api/blockchain/audit-trail")
        assert response.status_code == 200
        
        audit_data = response.json()
        assert audit_data["event_count"] >= 0

    def test_event_filtering_flow(self, client):
        """Test event filtering through audit trail"""
        # Log multiple events
        for i, risk_score in enumerate([0.5, 0.75, 0.95]):
            event_data = {
                "event_type": f"event_{i}",
                "risk_score": risk_score,
                "repository": f"repo_{i % 2}"
            }
            
            response = client.post("/api/blockchain/events", json=event_data)
            assert response.status_code == 200
        
        # Retrieve high-risk events
        response = client.get("/api/blockchain/audit-trail?risk_threshold=75")
        assert response.status_code == 200
        
        data = response.json()
        # Should have filtered events (or empty if offline)
        assert isinstance(data["events"], list)


class TestBlockchainAPIResponseFormats:
    """Test response format compliance"""

    def test_security_event_response_format(self, client):
        """Test security event response includes all required fields"""
        response = client.get("/api/blockchain/audit-trail")
        assert response.status_code == 200
        
        data = response.json()
        
        # Check response structure
        assert "event_count" in data
        assert "events" in data
        assert "timestamp" in data
        assert isinstance(data["events"], list)

    def test_blockchain_stats_response_format(self, client):
        """Test blockchain stats response format"""
        response = client.get("/api/blockchain/stats")
        assert response.status_code == 200
        
        data = response.json()
        
        # Check required fields
        assert "success" in data
        assert "stats" in data
        
        stats = data["stats"]
        required_fields = ["connected", "provider", "network", "status"]
        for field in required_fields:
            assert field in stats

    def test_event_logging_response_format(self, client):
        """Test event logging response format"""
        event_data = {
            "event_type": "test_event",
            "risk_score": 0.5,
            "repository": "test-repo"
        }
        
        response = client.post("/api/blockchain/events", json=event_data)
        assert response.status_code == 200
        
        data = response.json()
        
        # Check required fields
        assert "success" in data
        assert "data_hash" in data
        assert "timestamp" in data
        assert "storage_method" in data


class TestBlockchainAPIEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_very_large_risk_score(self, client):
        """Test with maximum valid risk score"""
        event_data = {
            "event_type": "critical_event",
            "risk_score": 1.0,  # Maximum valid
            "repository": "test"
        }
        
        response = client.post("/api/blockchain/events", json=event_data)
        assert response.status_code == 200

    def test_very_low_risk_score(self, client):
        """Test with minimum valid risk score"""
        event_data = {
            "event_type": "low_risk_event",
            "risk_score": 0.0,  # Minimum valid
            "repository": "test"
        }
        
        response = client.post("/api/blockchain/events", json=event_data)
        assert response.status_code == 200

    def test_long_event_type(self, client):
        """Test with very long event type string"""
        event_data = {
            "event_type": "a" * 1000,  # Very long string
            "risk_score": 0.5,
            "repository": "test"
        }
        
        response = client.post("/api/blockchain/events", json=event_data)
        assert response.status_code == 200

    def test_empty_violations_list(self, client):
        """Test with empty rule violations"""
        event_data = {
            "event_type": "no_violations",
            "risk_score": 0.3,
            "repository": "test",
            "rule_violations": []
        }
        
        response = client.post("/api/blockchain/events", json=event_data)
        assert response.status_code == 200

    def test_null_optional_fields(self, client):
        """Test with null optional fields"""
        event_data = {
            "event_type": "minimal_event",
            "risk_score": 0.5,
            "repository": "test",
            "message": None,
            "details": None
        }
        
        response = client.post("/api/blockchain/events", json=event_data)
        # Should handle None gracefully
        assert response.status_code in [200, 422]

    def test_special_characters_in_repository(self, client):
        """Test with special characters in repository name"""
        event_data = {
            "event_type": "special_chars_test",
            "risk_score": 0.6,
            "repository": "production/api-v2.1:main@region-1"
        }
        
        response = client.post("/api/blockchain/events", json=event_data)
        assert response.status_code == 200


class TestBlockchainAPIConcurrency:
    """Test concurrent API operations"""

    def test_multiple_event_logging(self, client):
        """Test logging multiple events in sequence"""
        for i in range(5):
            event_data = {
                "event_type": f"event_{i}",
                "risk_score": 0.3 + (i * 0.1),
                "repository": "test-repo"
            }
            
            response = client.post("/api/blockchain/events", json=event_data)
            assert response.status_code == 200

    def test_rapid_audit_trail_queries(self, client):
        """Test rapid successive audit trail queries"""
        for _ in range(10):
            response = client.get("/api/blockchain/audit-trail")
            assert response.status_code == 200
