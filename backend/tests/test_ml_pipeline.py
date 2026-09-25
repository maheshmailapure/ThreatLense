def test_list_models(client, auth_headers):
    response = client.get("/api/models", headers=auth_headers)
    assert response.status_code == 200
    models = response.json()
    assert len(models) >= 3
    model_names = [m["name"] for m in models]
    assert "Random Forest" in model_names
    assert "SVM" in model_names
    assert "K-Means" in model_names

def test_model_evaluation_compare(client, auth_headers):
    response = client.get("/api/evaluation/compare", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "models" in data
    assert len(data["models"]) >= 3
    
    rf_model = next(m for m in data["models"] if m["name"] == "Random Forest")
    assert rf_model["accuracy"] is not None
    assert rf_model["f1_score"] is not None
    assert "confusion_matrix" in rf_model["metrics_json"]

def test_specific_model_evaluation(client, auth_headers):
    response = client.get("/api/evaluation/Random Forest", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "Random Forest"
    assert data["accuracy"] > 0
