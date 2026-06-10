"""
Tests for Supabase Auth Migration
Testing: Backend auth endpoints with Bearer token authentication
"""
import pytest
import requests
import os

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')

class TestHealthEndpoint:
    """Health check endpoint tests"""
    
    def test_health_check_returns_ok(self):
        """Test /api/health returns OK status"""
        response = requests.get(f"{BASE_URL}/api/health", allow_redirects=True)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "mongo" in data
        assert "bigquery" in data
        print(f"Health check passed: {data}")


class TestAuthEndpoint:
    """Authentication endpoint tests - Supabase Bearer token auth"""
    
    def test_auth_me_returns_401_without_token(self):
        """Test /api/auth/me returns 401 when no token provided"""
        response = requests.get(f"{BASE_URL}/api/auth/me", allow_redirects=True)
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
        assert data["detail"] == "Not authenticated"
        print(f"Auth without token correctly returns 401: {data}")
    
    def test_auth_me_returns_401_with_invalid_token(self):
        """Test /api/auth/me returns 401 with invalid Bearer token"""
        headers = {"Authorization": "Bearer invalid_token_123"}
        response = requests.get(f"{BASE_URL}/api/auth/me", headers=headers, allow_redirects=True)
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
        # Backend returns "Not authenticated" for invalid tokens
        assert "authenticated" in data["detail"].lower() or "token" in data["detail"].lower()
        print(f"Auth with invalid token correctly returns 401: {data}")
    
    def test_auth_me_returns_401_without_bearer_prefix(self):
        """Test /api/auth/me returns 401 when token doesn't have Bearer prefix"""
        headers = {"Authorization": "some_token_without_bearer"}
        response = requests.get(f"{BASE_URL}/api/auth/me", headers=headers, allow_redirects=True)
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
        print(f"Auth without Bearer prefix correctly returns 401: {data}")


class TestProtectedEndpoints:
    """Test protected endpoints require authentication"""
    
    def test_prod_jobs_returns_401_without_token(self):
        """Test /api/prod/jobs returns 401 when no token provided"""
        response = requests.get(f"{BASE_URL}/api/prod/jobs", allow_redirects=True)
        assert response.status_code == 401
        print("Protected endpoint /api/prod/jobs correctly returns 401 without token")
    
    def test_prod_stats_returns_401_without_token(self):
        """Test /api/prod/stats returns 401 when no token provided"""
        response = requests.get(f"{BASE_URL}/api/prod/stats", allow_redirects=True)
        assert response.status_code == 401
        print("Protected endpoint /api/prod/stats correctly returns 401 without token")
    
    def test_eval_jobs_returns_401_without_token(self):
        """Test /api/eval/jobs returns 401 when no token provided"""
        response = requests.get(f"{BASE_URL}/api/eval/jobs", allow_redirects=True)
        assert response.status_code == 401
        print("Protected endpoint /api/eval/jobs correctly returns 401 without token")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
