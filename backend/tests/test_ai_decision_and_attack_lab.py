def test_ollama_config_and_test(client, auth_headers):
    # Test getting config
    resp = client.get("/api/ai-decision/config", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "ollama_base_url" in data
    assert "ollama_model" in data

    # Test updating config
    up_resp = client.post(
        "/api/ai-decision/config",
        json={"ollama_base_url": "http://localhost:11434", "ollama_model": "llama3"},
        headers=auth_headers
    )
    assert up_resp.status_code == 200
    assert up_resp.json()["ollama_model"] == "llama3"

    # Test connection test endpoint (returns structured status even if ollama is offline)
    ping_resp = client.post(
        "/api/ai-decision/test-ollama",
        json={"ollama_base_url": "http://localhost:11434", "ollama_model": "llama3"},
        headers=auth_headers
    )
    assert ping_resp.status_code == 200
    assert "status" in ping_resp.json()

def test_attack_lab_scenarios(client, auth_headers):
    resp = client.get("/api/attack-lab/scenarios", headers=auth_headers)
    assert resp.status_code == 200
    scenarios = resp.json()
    assert len(scenarios) >= 5
    ids = [s["id"] for s in scenarios]
    assert "web_sqli" in ids
    assert "dos_syn_flood" in ids

def test_simulate_web_sqli_attack(client, auth_headers):
    resp = client.post(
        "/api/attack-lab/simulate",
        json={"scenario_id": "web_sqli", "model_name": "Random Forest"},
        headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["prediction"] in ["ATTACK", "NORMAL"]
    assert "ai_decision" in data
    assert "threat_summary" in data["ai_decision"]
    assert "firewall_rule" in data["ai_decision"]
