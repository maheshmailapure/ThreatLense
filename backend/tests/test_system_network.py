def test_get_system_hardware_overview(client, auth_headers):
    resp = client.get("/api/system-network/overview", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "os_name" in data
    assert "cpu" in data
    assert "memory" in data
    assert "disks" in data
    assert data["cpu"]["logical_cores"] > 0

def test_get_open_listening_ports(client, auth_headers):
    resp = client.get("/api/system-network/open-ports", headers=auth_headers)
    assert resp.status_code == 200
    ports = resp.json()
    assert isinstance(ports, list)
    if len(ports) > 0:
        assert "port" in ports[0]
        assert "bind_address" in ports[0]
        assert "risk_level" in ports[0]

def test_get_live_traffic_flows(client, auth_headers):
    resp = client.get("/api/system-network/traffic-flows?max_flows=25", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "total_active_flows" in data
    assert "flows" in data
    assert "bytes_received_mb" in data
    assert "bytes_sent_mb" in data

def test_get_network_interfaces(client, auth_headers):
    resp = client.get("/api/system-network/interfaces", headers=auth_headers)
    assert resp.status_code == 200
    ifaces = resp.json()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0
    assert "name" in ifaces[0]
