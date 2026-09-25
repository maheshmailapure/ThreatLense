def test_list_datasets(client, auth_headers):
    response = client.get("/api/datasets", headers=auth_headers)
    assert response.status_code == 200
    datasets = response.json()
    assert len(datasets) > 0
    assert datasets[0]["filename"] == "NSL_KDD_Sample.csv"

def test_preview_dataset(client, auth_headers):
    # First get dataset id
    datasets = client.get("/api/datasets", headers=auth_headers).json()
    dataset_id = datasets[0]["id"]
    
    response = client.get(f"/api/datasets/{dataset_id}/preview", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert "sample_records" in data
    assert len(data["sample_records"]) > 0
    assert "columns" in data
