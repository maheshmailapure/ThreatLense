def test_health_check(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"

def test_login_success(client):
    response = client.post("/api/auth/login", json={"username": "admin", "password": "Admin@1234"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["username"] == "admin"
    assert data["role"] == "admin"

def test_login_invalid_password(client):
    response = client.post("/api/auth/login", json={"username": "admin", "password": "WrongPassword!"})
    assert response.status_code == 401

def test_get_current_user(client, auth_headers):
    response = client.get("/api/auth/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["username"] == "admin"
