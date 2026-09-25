def test_run_detection(client, auth_headers):
    datasets = client.get("/api/datasets", headers=auth_headers).json()
    dataset_id = datasets[0]["id"]

    response = client.post(
        "/api/detection/run",
        json={"dataset_id": dataset_id, "model_name": "Random Forest", "limit": 100},
        headers=auth_headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["total_processed"] == 100
    assert data["normal_count"] + data["attack_count"] == 100
    assert data["alerts_generated"] >= 0

def test_get_detection_results(client, auth_headers):
    response = client.get("/api/detection/results?page=1&page_size=10", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert len(data["items"]) > 0

def test_alerts_lifecycle(client, auth_headers):
    # Fetch alerts
    response = client.get("/api/alerts?page=1&page_size=10", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    if len(data["items"]) > 0:
        alert_id = data["items"][0]["id"]
        # Update status to INVESTIGATING
        update_resp = client.put(
            f"/api/alerts/{alert_id}/status",
            json={"status": "INVESTIGATING"},
            headers=auth_headers
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["status"] == "INVESTIGATING"

        # Update status to RESOLVED
        res_resp = client.put(
            f"/api/alerts/{alert_id}/status",
            json={"status": "RESOLVED"},
            headers=auth_headers
        )
        assert res_resp.status_code == 200
        assert res_resp.json()["status"] == "RESOLVED"
