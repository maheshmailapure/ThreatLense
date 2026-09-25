def test_web_auditor_scan_domain(client, auth_headers):
    resp = client.post(
        "/api/web-auditor/scan",
        json={"target": "example.com"},
        headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "target_url" in data
    assert "security_score" in data
    assert "security_grade" in data
    assert "ssl_tls" in data
    assert "missing_headers" in data

def test_web_auditor_scan_ip(client, auth_headers):
    resp = client.post(
        "/api/web-auditor/scan",
        json={"target": "1.1.1.1"},
        headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ip_address"] == "1.1.1.1"
    assert "posture_level" in data
