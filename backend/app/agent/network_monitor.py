import time
import socket
import ipaddress
import psutil
from datetime import datetime
from typing import Dict, Any, List, Set, Tuple, Optional

# Common standard service ports map
PORT_SERVICE_MAP = {
    80: "http", 443: "https", 53: "domain", 22: "ssh", 21: "ftp",
    25: "smtp", 110: "pop3", 143: "imap", 3306: "mysql", 5432: "postgresql",
    8080: "http_proxy", 8443: "https_alt", 8000: "http_backend", 5173: "http_frontend",
    11434: "ollama_ai", 3389: "rdp", 445: "smb", 135: "msrpc", 139: "netbios"
}

_IP_CLASS_CACHE: Dict[str, Dict[str, str]] = {}
_PID_NAME_CACHE: Dict[int, str] = {}
_PID_CACHE_TIME = 0.0

def classify_ip_address(ip_str: str) -> Dict[str, str]:
    """Classify an IP string with in-memory memoization."""
    if not ip_str or ip_str in ["0.0.0.0", "::", "127.0.0.1", "::1"]:
        return {"type": "LOCAL", "label": "Loopback / Host Local"}
    if ip_str in _IP_CLASS_CACHE:
        return _IP_CLASS_CACHE[ip_str]
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback:
            res = {"type": "LOCAL", "label": "Loopback Local"}
        elif ip_obj.is_private:
            res = {"type": "PRIVATE", "label": "Private LAN Subnet"}
        elif ip_obj.is_link_local:
            res = {"type": "LINK_LOCAL", "label": "Link-Local Auto IP"}
        elif ip_obj.is_multicast:
            res = {"type": "MULTICAST", "label": "Multicast Group"}
        else:
            res = {"type": "EXTERNAL", "label": "External Public Internet"}
    except Exception:
        res = {"type": "EXTERNAL", "label": "External Remote"}
    if len(_IP_CLASS_CACHE) < 500:
        _IP_CLASS_CACHE[ip_str] = res
    return res

def get_process_name_fast(pid: Optional[int]) -> str:
    """Resolve process name using an in-memory PID cache to avoid expensive OS syscalls."""
    global _PID_NAME_CACHE, _PID_CACHE_TIME
    if not pid:
        return "System"
    now = time.time()
    if now - _PID_CACHE_TIME > 5.0:
        _PID_NAME_CACHE.clear()
        _PID_CACHE_TIME = now
    if pid in _PID_NAME_CACHE:
        return _PID_NAME_CACHE[pid]
    try:
        name = psutil.Process(pid).name()
        _PID_NAME_CACHE[pid] = name
        return name
    except Exception:
        name = f"PID:{pid}"
        _PID_NAME_CACHE[pid] = name
        return name

class NetworkMonitor:
    """
    Monitors live network sockets, active traffic flows, interface throughput,
    and classifies incoming vs outgoing connections in real-time (<15ms).
    """
    def __init__(self):
        self._last_net_io = psutil.net_io_counters()
        self._last_time = time.time()
        self._cached_interfaces: List[Dict[str, Any]] = []
        self._last_iface_time = 0.0

    def collect(self, max_connections: int = 60) -> Dict[str, Any]:
        """Inspect all real network sockets and traffic throughput in <15ms."""
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

            if len(active_flows) < max_connections:
                proc_name = get_process_name_fast(c.pid)

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

        # Cache interfaces for 10 seconds
        if not self._cached_interfaces or (now - self._last_iface_time > 10.0):
            interfaces: List[Dict[str, Any]] = []
            try:
                addrs = psutil.net_if_addrs()
                stats = psutil.net_if_stats()
                for iface_name, addr_list in addrs.items():
                    ipv4 = "N/A"
                    mac = "N/A"
                    for addr in addr_list:
                        if addr.family == socket.AF_INET:
                            ipv4 = addr.address
                        elif addr.family == psutil.AF_LINK if hasattr(psutil, 'AF_LINK') else -1:
                            mac = addr.address

                    iface_stat = stats.get(iface_name)
                    is_up = iface_stat.isup if iface_stat else False
                    speed_mbps = iface_stat.speed if iface_stat else 0

                    interfaces.append({
                        "interface": iface_name,
                        "ipv4": ipv4,
                        "mac": mac,
                        "is_up": is_up,
                        "speed_mbps": speed_mbps
                    })
            except Exception:
                pass
            self._cached_interfaces = interfaces
            self._last_iface_time = now

        return {
            "status": "ACTIVE",
            "timestamp": datetime.utcnow().isoformat(),
            "total_sockets": total_sockets,
            "listening_count": listening_count,
            "established_count": established_count,
            "external_count": external_count,
            "bytes_sent_per_sec": bytes_sent_sec,
            "bytes_recv_per_sec": bytes_recv_sec,
            "interfaces": self._cached_interfaces,
            "flows": active_flows
        }
