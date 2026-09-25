def test_kill_chain_endpoint(client, auth_headers):
    resp = client.get("/api/advanced-soc/kill-chain", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "stages" in data
    assert "campaigns" in data
    assert len(data["stages"]) == 7
    assert len(data["campaigns"]) >= 1

def test_ueba_endpoint(client, auth_headers):
    resp = client.get("/api/advanced-soc/ueba", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "metrics" in data
    assert "entities" in data
    assert data["metrics"]["total_entities_monitored"] > 0

def test_encrypted_traffic_endpoint(client, auth_headers):
    resp = client.get("/api/advanced-soc/encrypted-traffic", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 2
    assert "entropy_score" in data[0]
    assert "tls_version" in data[0]

def test_playbooks_endpoint_and_execution(client, auth_headers):
    # List playbooks
    resp = client.get("/api/advanced-soc/playbooks", headers=auth_headers)
    assert resp.status_code == 200
    playbooks = resp.json()
    assert len(playbooks) >= 3

    # Execute playbook
    exec_resp = client.post(
        "/api/advanced-soc/playbooks/execute",
        json={"playbook_id": "playbook_firewall_drop", "parameters": {"source_ip": "203.0.113.99"}},
        headers=auth_headers
    )
    assert exec_resp.status_code == 200
    exec_data = exec_resp.json()
    assert exec_data["status"] == "SUCCESSFULLY EXECUTED"
    assert "203.0.113.99" in exec_data["command_executed"]
