def test_get_download_watcher_status(client, auth_headers):
    resp = client.get("/api/file-scanner/watcher-status", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "downloads_folder_path" in data
    assert "watcher_enabled" in data

def test_scan_real_system_downloads(client, auth_headers):
    resp = client.post("/api/file-scanner/scan-downloads", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "downloads_folder" in data
    assert "total_files_scanned" in data
    assert "files" in data

def test_policy_decision_execution(client, auth_headers):
    # Test Block
    resp_block = client.post(
        "/api/file-scanner/policy-decision",
        json={"filename": "test_threat.exe", "action": "block"},
        headers=auth_headers
    )
    assert resp_block.status_code == 200
    assert resp_block.json()["policy_decision"] == "BLOCK"

    # Test Allow
    resp_allow = client.post(
        "/api/file-scanner/policy-decision",
        json={"filename": "safe_override.pdf", "action": "allow", "md5_hash": "abc123md5"},
        headers=auth_headers
    )
    assert resp_allow.status_code == 200
    assert resp_allow.json()["policy_decision"] == "ALLOW"

def test_scan_custom_webshell_text(client, auth_headers):
    resp = client.post(
        "/api/file-scanner/scan-text",
        json={
            "filename": "shell.php",
            "content": "<?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk7')); ?>"
        },
        headers=auth_headers
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_malicious"] is True
    assert data["trigger_alarm"] is True
