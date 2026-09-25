def test_get_system_telemetry(client, auth_headers):
    response = client.get("/api/live-monitor/telemetry", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "cpu_usage_pct" in data
    assert "memory_usage_pct" in data
    assert "interfaces" in data

def test_scan_host_network(client, auth_headers):
    response = client.get("/api/live-monitor/scan?max_connections=20", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_open_sockets" in data
    assert "flows" in data
    assert len(data["flows"]) >= 0

def test_test_attack_scenario(client, auth_headers):
    test_syn_flood = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "private",
        "flag": "S0",
        "src_bytes": 0,
        "dst_bytes": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 0,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 350,
        "srv_count": 350,
        "serror_rate": 1.0,
        "srv_serror_rate": 1.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 255,
        "dst_host_srv_count": 10,
        "dst_host_same_srv_rate": 0.04,
        "dst_host_diff_srv_rate": 0.06,
        "dst_host_same_src_port_rate": 0.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 1.0,
        "dst_host_srv_serror_rate": 1.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0
    }

    response = client.post(
        "/api/live-monitor/test-attack",
        json={"model_name": "Random Forest", "packet_features": test_syn_flood},
        headers=auth_headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["prediction"] == "ATTACK"
    assert data["risk_level"] in ["HIGH", "CRITICAL"]
    assert "explanation" in data
