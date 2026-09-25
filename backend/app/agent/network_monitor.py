import time
import socket
import ipaddress
import psutil
from datetime import datetime
from typing import Dict, Any, List, Set, Tuple

# Common standard service ports map
PORT_SERVICE_MAP = {
    80: "http", 443: "https", 53: "domain", 22: "ssh", 21: "ftp",
    25: "smtp", 110: "pop3", 143: "imap", 3306: "mysql", 5432: "postgresql",
    8080: "http_proxy", 8443: "https_alt", 8000: "http_backend", 5173: "http_frontend",
    11434: "ollama_ai", 3389: "rdp", 445: "smb", 135: "msrpc", 139: "netbios"
}

def classify_ip_address(ip_str: str) -> Dict[str, str]:
    """Classify an IP string as LOCAL, PRIVATE, EXTERNAL, LINK_LOCAL, or MULTICAST."""
    if not ip_str or ip_str in ["0.0.0.0", "::", "127.0.0.1", "::1"]:
        return {"type": "LOCAL", "label": "Loopback / Host Local"}
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback:
            return {"type": "LOCAL", "label": "Loopback Local"}
        elif ip_obj.is_private:
            return {"type": "PRIVATE", "label": "Private LAN Subnet"}
        elif ip_obj.is_link_local:
            return {"type": "LINK_LOCAL", "label": "Link-Local Auto IP"}
        elif ip_obj.is_multicast:
            return {"type": "MULTICAST", "label": "Multicast Group"}
        else:
            return {"type": "EXTERNAL", "label": "External Public Internet"}
    except Exception:
        return {"type": "EXTERNAL", "label": "External Remote"}

class NetworkMonitor:
    """
    Monitors live network sockets, active traffic flows, interface throughput,
    and classifies incoming vs outgoing connections in real-time.
    """
    def __init__(self):
        self._last_net_io = psutil.net_io_counters()
        self._last_time = time.time()

    def collect(self, max_connections: int = 60) -> Dict[str, Any]:
        """Inspect all real network sockets and traffic throughput."""
        now = time.time()
        time_delta = max(now - self._last_time, 0.1)

        current_io = psutil.net_io_counters()
        bytes_sent_sec = round((current_io.bytes_sent - self._last_net_io.bytes_sent) / time_delta, 1)
        bytes_recv_sec = round((current_io.bytes_recv - self._last_net_io.bytes_recv) / time_delta, 1)

        self._last_net_io = current_io
        self._last_time = now

        # Inspect network sockets
        raw_conns = psutil.net_connections(kind='inet')
        total_sockets = len(raw_conns)
        listening_count = 0
        established_count = 0
        external_count = 0

        active_flows: List[Dict[str, Any]] = []

        for c in raw_conns:
            if c.status == 'LISTEN':
                listening_count += 1
            elif c.status == 'ESTABLISHED':
                established_count += 1

            l_ip = c.laddr.ip if c.laddr else "0.0.0.0"
            l_port = c.laddr.port if c.laddr else 0
            r_ip = c.raddr.ip if c.raddr else ""
            r_port = c.raddr.port if c.raddr else 0
            proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"

            remote_class = classify_ip_address(r_ip) if r_ip else {"type": "NONE", "label": "None"}
            if remote_class["type"] == "EXTERNAL":
                external_count += 1

            # Process Name
            proc_name = "System"
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except Exception:
                    proc_name = f"PID:{c.pid}"

            # Determine direction
            if c.status == 'LISTEN':
                direction = "LISTENING"
            elif r_ip in ["127.0.0.1", "::1", "0.0.0.0", ""]:
                direction = "LOOPBACK"
            elif remote_class["type"] == "PRIVATE":
                direction = "LAN"
            else:
                direction = "OUTBOUND" if l_port > 1024 else "INBOUND"

            service = PORT_SERVICE_MAP.get(l_port, PORT_SERVICE_MAP.get(r_port, "other"))

            active_flows.append({
                "local_address": l_ip,
                "local_port": l_port,
                "remote_address": r_ip or "0.0.0.0",
                "remote_port": r_port,
                "protocol": proto,
                "status": c.status,
                "process_name": proc_name,
                "pid": c.pid,
                "direction": direction,
                "service": service,
                "remote_type": remote_class["type"],
                "remote_label": remote_class["label"]
            })

        # Collect network interfaces
        interfaces: List[Dict[str, Any]] = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for name, addr_list in addrs.items():
            st = stats.get(name)
            is_up = st.isup if st else False
            speed_mbps = st.speed if st else 0

            ipv4 = "N/A"
            mac = "N/A"
            for a in addr_list:
                if a.family == socket.AF_INET:
                    ipv4 = a.address
                elif getattr(a, 'family', None) == getattr(psutil, 'AF_LINK', -1) or 'MAC' in str(a.family):
                    mac = a.address

            interfaces.append({
                "name": name,
                "is_up": is_up,
                "speed_mbps": speed_mbps,
                "ipv4": ipv4,
                "mac": mac
            })

        return {
            "status": "ACTIVE",
            "timestamp": datetime.utcnow().isoformat(),
            "throughput": {
                "bytes_recv_sec": bytes_recv_sec,
                "bytes_sent_sec": bytes_sent_sec,
                "kb_recv_sec": round(bytes_recv_sec / 1024, 2),
                "kb_sent_sec": round(bytes_sent_sec / 1024, 2)
            },
            "total_sockets": total_sockets,
            "listening_sockets_count": listening_count,
            "established_sockets_count": established_count,
            "external_sockets_count": external_count,
            "interfaces": interfaces,
            "flows": active_flows[:max_connections]
        }
