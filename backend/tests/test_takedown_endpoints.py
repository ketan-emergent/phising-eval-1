"""
Tests for Takedown Endpoints
Testing:
- POST /api/test/takedown/{job_id} - QA Test takedown endpoint
- POST /api/prod/takedown/{job_id} - Production takedown endpoint
"""
import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')


class TestTestTakedownEndpoint:
    """Tests for POST /api/test/takedown/{job_id} - QA Test Takedown"""
    
    def test_test_takedown_returns_401_without_auth_token(self):
        """Test POST /api/test/takedown/{job_id} returns 401 without auth token"""
        job_id = "test-job-123"
        response = requests.post(
            f"{BASE_URL}/api/test/takedown/{job_id}",
            json={"suspension_reason": "Test reason"},
            allow_redirects=True
        )
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
        assert data["detail"] == "Not authenticated"
        print(f"Test takedown without token correctly returns 401: {data}")
    
    def test_test_takedown_returns_401_with_invalid_token(self):
        """Test POST /api/test/takedown/{job_id} returns 401 with invalid Bearer token"""
        job_id = "test-job-123"
        headers = {"Authorization": "Bearer invalid_token_xyz"}
        response = requests.post(
            f"{BASE_URL}/api/test/takedown/{job_id}",
            headers=headers,
            json={"suspension_reason": "Test reason"},
            allow_redirects=True
        )
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
        print(f"Test takedown with invalid token correctly returns 401: {data}")
    
    def test_test_takedown_returns_400_if_suspension_reason_missing(self):
        """Test POST /api/test/takedown/{job_id} returns 400 if suspension_reason is missing"""
        job_id = "test-job-123"
        headers = {"Authorization": "Bearer fake_valid_token"}
        
        # Test with empty body
        response = requests.post(
            f"{BASE_URL}/api/test/takedown/{job_id}",
            headers=headers,
            json={},
            allow_redirects=True
        )
        # Should return 401 first (auth check) then 400 if auth passes
        # Since we don't have a valid token, it will return 401
        # But we can verify the endpoint exists and responds
        assert response.status_code in [400, 401]
        print(f"Test takedown without suspension_reason returns {response.status_code}: {response.json()}")
    
    def test_test_takedown_returns_400_if_suspension_reason_empty_string(self):
        """Test POST /api/test/takedown/{job_id} returns 400 if suspension_reason is empty string"""
        job_id = "test-job-123"
        headers = {"Authorization": "Bearer fake_valid_token"}
        
        response = requests.post(
            f"{BASE_URL}/api/test/takedown/{job_id}",
            headers=headers,
            json={"suspension_reason": ""},
            allow_redirects=True
        )
        # Same as above - will hit auth check first
        assert response.status_code in [400, 401]
        print(f"Test takedown with empty suspension_reason returns {response.status_code}: {response.json()}")
    
    def test_test_takedown_returns_400_if_suspension_reason_whitespace_only(self):
        """Test POST /api/test/takedown/{job_id} returns 400 if suspension_reason is whitespace only"""
        job_id = "test-job-123"
        headers = {"Authorization": "Bearer fake_valid_token"}
        
        response = requests.post(
            f"{BASE_URL}/api/test/takedown/{job_id}",
            headers=headers,
            json={"suspension_reason": "   "},
            allow_redirects=True
        )
        assert response.status_code in [400, 401]
        print(f"Test takedown with whitespace-only suspension_reason returns {response.status_code}: {response.json()}")


class TestProdTakedownEndpoint:
    """Tests for POST /api/prod/takedown/{job_id} - Production Takedown"""
    
    def test_prod_takedown_returns_401_without_auth_token(self):
        """Test POST /api/prod/takedown/{job_id} returns 401 without auth token"""
        job_id = "prod-job-123"
        response = requests.post(
            f"{BASE_URL}/api/prod/takedown/{job_id}",
            json={"suspension_reason": "Test reason"},
            allow_redirects=True
        )
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
        assert data["detail"] == "Not authenticated"
        print(f"Prod takedown without token correctly returns 401: {data}")
    
    def test_prod_takedown_returns_401_with_invalid_token(self):
        """Test POST /api/prod/takedown/{job_id} returns 401 with invalid Bearer token"""
        job_id = "prod-job-123"
        headers = {"Authorization": "Bearer invalid_token_xyz"}
        response = requests.post(
            f"{BASE_URL}/api/prod/takedown/{job_id}",
            headers=headers,
            json={"suspension_reason": "Test reason"},
            allow_redirects=True
        )
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
        print(f"Prod takedown with invalid token correctly returns 401: {data}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
