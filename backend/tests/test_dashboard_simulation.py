def test_dashboard_stats(client, auth_headers):
    response = client.get("/api/dashboard/stats", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_records" in data
    assert "normal_records" in data
    assert "attack_records" in data
    assert "anomalies" in data
    assert "models_trained_count" in data

def test_dashboard_charts(client, auth_headers):
    response = client.get("/api/dashboard/charts", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "normal_vs_attack" in data
    assert "attack_categories" in data
    assert "risk_distribution" in data
    assert "protocol_distribution" in data

def test_simulation_status(client, auth_headers):
    response = client.get("/api/simulation/status", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "is_running" in data
