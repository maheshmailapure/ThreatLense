from fastapi import APIRouter, Depends, Query
from typing import Dict, Any, List
from app.database.models import User
from app.api.auth import get_current_user
from app.services.network_topology_service import NetworkTopologyService

router = APIRouter(prefix="/api/system-network", tags=["System & Network Deep Analysis"])

@router.get("/overview")
def get_system_hardware_overview(
    current_user: User = Depends(get_current_user)
):
    """Retrieve full system hardware specs, CPU cores, RAM breakdown, disk partitions, uptime, and OS info."""
    return NetworkTopologyService.get_full_system_overview()

@router.get("/open-ports")
def get_open_listening_ports(
    current_user: User = Depends(get_current_user)
):
    """List all open listening TCP/UDP ports, bound addresses, process names, PIDs, and exposure security risk levels."""
    return NetworkTopologyService.get_open_listening_ports()

@router.get("/traffic-flows")
def get_live_traffic_flows(
    max_flows: int = Query(60, ge=10, le=200),
    current_user: User = Depends(get_current_user)
):
    """Retrieve real-time inbound and outbound communicating traffic flows with Source -> Destination endpoints and byte throughput."""
    return NetworkTopologyService.get_active_traffic_flows(max_flows=max_flows)

@router.get("/interfaces")
def get_network_interfaces(
    current_user: User = Depends(get_current_user)
):
    """List all network adapters, MAC addresses, IPv4/IPv6 assignments, link speed, and TX/RX packet statistics."""
    return NetworkTopologyService.get_network_interfaces()
