import os
import sys
import time
import socket
import platform
import psutil
from typing import Dict, Any, List, Set
from datetime import datetime, timedelta

# Port security risk assessment mapping
PORT_SECURITY_RISK = {
    21: {"service": "FTP (Unencrypted File Transfer)", "risk": "HIGH", "recommendation": "Migrate to SFTP/SSH on port 22."},
    22: {"service": "SSH (Secure Shell)", "risk": "LOW", "recommendation": "Enforce key-based authentication and disable root login."},
    23: {"service": "Telnet (Unencrypted Remote Terminal)", "risk": "CRITICAL", "recommendation": "Telnet sends passwords in cleartext. Disable immediately."},
    25: {"service": "SMTP (Mail Transfer)", "risk": "MEDIUM", "recommendation": "Require TLS encryption (STARTTLS) and SMTP authentication."},
    53: {"service": "DNS (Domain Name System)", "risk": "LOW", "recommendation": "Enable DNSSEC and rate limit recursive queries."},
    80: {"service": "HTTP (Web Server)", "risk": "LOW", "recommendation": "Redirect all plaintext traffic to HTTPS (port 443)."},
    110: {"service": "POP3 (Mail Retrieval)", "risk": "MEDIUM", "recommendation": "Use POP3S (port 995) with SSL/TLS."},
    135: {"service": "RPC (Remote Procedure Call)", "risk": "HIGH", "recommendation": "Block RPC exposure to public internet to prevent lateral movement."},
    139: {"service": "NetBIOS Session Service", "risk": "HIGH", "recommendation": "Restrict NetBIOS to local private LAN only."},
    143: {"service": "IMAP (Mail Retrieval)", "risk": "MEDIUM", "recommendation": "Use IMAPS (port 993) with SSL/TLS."},
    443: {"service": "HTTPS (Secure Web Server)", "risk": "LOW", "recommendation": "Enforce TLS 1.3 and strong cipher suites."},
    445: {"service": "SMB (Server Message Block)", "risk": "CRITICAL", "recommendation": "Never expose SMB publicly (vulnerable to EternalBlue/WannaCry)."},
    1433: {"service": "Microsoft SQL Server", "risk": "HIGH", "recommendation": "Bind to localhost/private network and enforce strong passwords."},
    3306: {"service": "MySQL / MariaDB Database", "risk": "HIGH", "recommendation": "Bind to 127.0.0.1 only and disable remote root access."},
    3389: {"service": "RDP (Remote Desktop Protocol)", "risk": "HIGH", "recommendation": "Place RDP behind VPN and enforce Network Level Authentication (NLA)."},
    5432: {"service": "PostgreSQL Database", "risk": "MEDIUM", "recommendation": "Restrict pg_hba.conf to authorized client subnets."},
    8000: {"service": "AI-IDS Backend API", "risk": "LOW", "recommendation": "Secured FastAPI REST Gateway."},
    5173: {"service": "AI-IDS Frontend SOC Console", "risk": "LOW", "recommendation": "Vite React Dashboard."},
    8080: {"service": "HTTP Alternate / Proxy", "risk": "LOW", "recommendation": "Ensure authentication is enabled."},
}

def classify_ip(ip_str: str) -> Dict[str, str]:
    """Classify IP address into locality and zone."""
    if not ip_str or ip_str in ["0.0.0.0", "::", "N/A"]:
        return {"type": "ALL_INTERFACES", "label": "Listen on All Interfaces (0.0.0.0)"}
    if ip_str.startswith("127.") or ip_str == "::1":
        return {"type": "LOOPBACK", "label": "Local Loopback (127.0.0.1)"}
    if ip_str.startswith("10.") or ip_str.startswith("192.168.") or (ip_str.startswith("172.") and 16 <= int(ip_str.split(".")[1] if len(ip_str.split(".")) > 1 else 0) <= 31):
        return {"type": "PRIVATE_LAN", "label": "Internal Private Subnet"}
    return {"type": "PUBLIC_WAN", "label": "External Public Internet"}

class NetworkTopologyService:
    @staticmethod
    def get_full_system_overview() -> Dict[str, Any]:
        """Collect deep host hardware, operating system, and system performance metrics."""
        uname = platform.uname()
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime_seconds = int(time.time() - psutil.boot_time())
        uptime_str = str(timedelta(seconds=uptime_seconds))

        # CPU details (non-blocking instantaneous sample)
        cpu_pct = psutil.cpu_percent(interval=None)
        per_cpu = psutil.cpu_percent(percpu=True, interval=None)
        cpu_count_logical = psutil.cpu_count(logical=True) or 4
        cpu_count_physical = psutil.cpu_count(logical=False) or 2
        cpu_freq = psutil.cpu_freq()

        # Memory details
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        # Disk partitions & usage
        disks = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "used_gb": round(usage.used / (1024 ** 3), 2),
                    "free_gb": round(usage.free / (1024 ** 3), 2),
                    "percent_used": usage.percent
                })
            except Exception:
                continue

        # Network I/O details
        net_io = psutil.net_io_counters()
        net_stats = {
            "bytes_recv_mb": round(net_io.bytes_recv / (1024 ** 2), 2),
            "bytes_sent_mb": round(net_io.bytes_sent / (1024 ** 2), 2),
            "packets_recv": net_io.packets_recv,
            "packets_sent": net_io.packets_sent,
            "errin": net_io.errin,
            "errout": net_io.errout,
            "dropin": net_io.dropin,
            "dropout": net_io.dropout
        }

        # Process counts
        total_pids = len(psutil.pids())

        return {
            "os_name": f"{uname.system} {uname.release}",
            "os_version": uname.version,
            "architecture": uname.machine,
            "hostname": uname.node,
            "boot_time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
            "uptime": uptime_str,
            "uptime_seconds": uptime_seconds,
            "active_processes_count": total_pids,
            "cpu_usage_pct": cpu_pct,
            "cpu_cores_logical": cpu_count_logical,
            "cpu": {
                "usage_percent": cpu_pct,
                "per_core_percent": per_cpu,
                "logical_cores": cpu_count_logical,
                "physical_cores": cpu_count_physical,
                "current_freq_mhz": round(cpu_freq.current, 1) if cpu_freq else 0,
                "max_freq_mhz": round(cpu_freq.max, 1) if cpu_freq else 0
            },
            "memory": {
                "total_gb": round(mem.total / (1024 ** 3), 2),
                "used_gb": round(mem.used / (1024 ** 3), 2),
                "available_gb": round(mem.available / (1024 ** 3), 2),
                "percent_used": mem.percent,
                "swap_total_gb": round(swap.total / (1024 ** 3), 2),
                "swap_used_gb": round(swap.used / (1024 ** 3), 2),
                "swap_percent_used": swap.percent
            },
            "network": net_stats,
            "disks": disks
        }

    @staticmethod
    def get_open_listening_ports() -> List[Dict[str, Any]]:
        """Inspect all active listening sockets on the host and evaluate exposure risk."""
        connections = psutil.net_connections(kind='inet')
        listening_sockets = [c for c in connections if c.status == 'LISTEN']

        open_ports = []
        seen_keys = set()

        for c in listening_sockets:
            l_ip = c.laddr.ip if c.laddr else "0.0.0.0"
            l_port = c.laddr.port if c.laddr else 0
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"

            key = (l_ip, l_port, proto)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            # Process info
            proc_name = "System Process"
            proc_exe = "N/A"
            if c.pid:
                try:
                    proc = psutil.Process(c.pid)
                    proc_name = proc.name()
                except Exception:
                    proc_name = f"PID:{c.pid}"

            # Risk assessment
            ip_class = classify_ip(l_ip)
            risk_meta = PORT_SECURITY_RISK.get(l_port, {
                "service": f"Custom Service (Port {l_port})",
                "risk": "MEDIUM" if ip_class["type"] == "ALL_INTERFACES" else "LOW",
                "recommendation": "Ensure service requires authentication if bound to public interface."
            })

            # Elevate risk if high-risk port is exposed on 0.0.0.0
            adjusted_risk = risk_meta["risk"]
            if ip_class["type"] == "ALL_INTERFACES" and l_port in [21, 23, 135, 139, 445, 1433, 3306]:
                adjusted_risk = "CRITICAL"

            open_ports.append({
                "port": l_port,
                "protocol": proto,
                "bind_address": l_ip,
                "bind_scope": ip_class["label"],
                "bind_type": ip_class["type"],
                "service_name": risk_meta["service"],
                "risk_level": adjusted_risk,
                "recommendation": risk_meta["recommendation"],
                "pid": c.pid,
                "process_name": proc_name,
                "process_exe": proc_exe
            })

        # Sort ports numerically
        open_ports.sort(key=lambda x: x["port"])
        return open_ports

    @staticmethod
    def get_active_traffic_flows(max_flows: int = 80) -> Dict[str, Any]:
        """
        Inspect live established and communicating socket connections.
        Classifies traffic direction (Inbound vs Outbound), remote endpoint, and byte volume.
        """
        connections = psutil.net_connections(kind='inet')
        active = [c for c in connections if c.status not in ['LISTEN', 'NONE']][:max_flows]

        flows = []
        inbound_count = 0
        outbound_count = 0
        state_distribution: Dict[str, int] = {}
        process_flows_count: Dict[str, int] = {}

        # Host local IPs for direction inference
        local_ips = set()
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family == socket.AF_INET:
                    local_ips.add(a.address)

        for c in active:
            l_ip = c.laddr.ip if c.laddr else "127.0.0.1"
            l_port = c.laddr.port if c.laddr else 0
            r_ip = c.raddr.ip if c.raddr else "0.0.0.0"
            r_port = c.raddr.port if c.raddr else 0
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            status = c.status or "ESTABLISHED"

            state_distribution[status] = state_distribution.get(status, 0) + 1

            # Direction inference
            if l_port in [8000, 5173, 80, 443, 22, 21, 3000, 8080]:
                direction = "INBOUND"
                inbound_count += 1
            else:
                direction = "OUTBOUND"
                outbound_count += 1

            r_class = classify_ip(r_ip)

            # Process info
            proc_name = "System"
            try:
                if c.pid:
                    proc = psutil.Process(c.pid)
                    proc_name = proc.name()
            except Exception:
                proc_name = f"PID:{c.pid}" if c.pid else "System"

            process_flows_count[proc_name] = process_flows_count.get(proc_name, 0) + 1

            flows.append({
                "local_endpoint": f"{l_ip}:{l_port}",
                "local_ip": l_ip,
                "local_port": l_port,
                "remote_endpoint": f"{r_ip}:{r_port}",
                "remote_ip": r_ip,
                "remote_port": r_port,
                "remote_zone": r_class["label"],
                "remote_type": r_class["type"],
                "protocol": proto,
                "state": status,
                "direction": direction,
                "pid": c.pid,
                "process_name": proc_name
            })

        # Overall I/O
        net_io = psutil.net_io_counters()

        # Top processes by socket count
        top_processes = [
            {"process": k, "active_sockets": v}
            for k, v in sorted(process_flows_count.items(), key=lambda x: x[1], reverse=True)[:8]
        ]

        return {
            "total_active_flows": len(flows),
            "inbound_flows": inbound_count,
            "outbound_flows": outbound_count,
            "bytes_received_mb": round(net_io.bytes_recv / (1024 ** 2), 2),
            "bytes_sent_mb": round(net_io.bytes_sent / (1024 ** 2), 2),
            "packets_received": net_io.packets_recv,
            "packets_sent": net_io.packets_sent,
            "errors_in": net_io.errin,
            "errors_out": net_io.errout,
            "drops_in": net_io.dropin,
            "drops_out": net_io.dropout,
            "state_distribution": state_distribution,
            "top_processes": top_processes,
            "flows": flows
        }

    @staticmethod
    def get_network_interfaces() -> List[Dict[str, Any]]:
        """Retrieve all physical, virtual, and loopback network adapters with live statistics."""
        interfaces = []
        stats = psutil.net_if_stats()
        io_counters = psutil.net_io_counters(pernic=True)

        for iface_name, addrs in psutil.net_if_addrs().items():
            ipv4_list = []
            ipv6_list = []
            mac_addr = "N/A"

            for a in addrs:
                if a.family == socket.AF_INET:
                    ipv4_list.append(a.address)
                elif hasattr(socket, 'AF_INET6') and a.family == socket.AF_INET6:
                    ipv6_list.append(a.address)
                elif hasattr(psutil, 'AF_LINK') and a.family == psutil.AF_LINK:
                    mac_addr = a.address

            st = stats.get(iface_name)
            io = io_counters.get(iface_name)

            interfaces.append({
                "name": iface_name,
                "is_up": st.isup if st else True,
                "speed_mbps": st.speed if st else 0,
                "mtu": st.mtu if st else 1500,
                "duplex": str(st.duplex).split(".")[-1] if st and hasattr(st, "duplex") else "FULL",
                "mac_address": mac_addr,
                "ipv4_addresses": ipv4_list,
                "ipv6_addresses": ipv6_list[:1],
                "bytes_recv_mb": round(io.bytes_recv / (1024 ** 2), 2) if io else 0.0,
                "bytes_sent_mb": round(io.bytes_sent / (1024 ** 2), 2) if io else 0.0,
                "packets_recv": io.packets_recv if io else 0,
                "packets_sent": io.packets_sent if io else 0,
                "errin": io.errin if io else 0,
                "errout": io.errout if io else 0,
                "dropin": io.dropin if io else 0,
                "dropout": io.dropout if io else 0
            })

        return interfaces
