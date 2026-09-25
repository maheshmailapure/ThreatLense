import time
import platform
import psutil
from datetime import datetime, timedelta
from typing import Dict, Any, List

class SystemMonitor:
    """
    Collects real-time hardware, operating system, and system performance metrics
    directly from Windows kernel APIs using psutil.
    """
    def __init__(self):
        self.uname = platform.uname()
        self.boot_time = datetime.fromtimestamp(psutil.boot_time())
        # Initial non-blocking CPU sample
        psutil.cpu_percent(interval=None)

    def collect(self) -> Dict[str, Any]:
        """Collect instantaneous genuine system metrics."""
        now = time.time()
        uptime_seconds = int(now - psutil.boot_time())
        uptime_str = str(timedelta(seconds=uptime_seconds))

        # CPU details
        cpu_pct = psutil.cpu_percent(interval=None)
        per_cpu = psutil.cpu_percent(percpu=True, interval=None)
        cpu_count_logical = psutil.cpu_count(logical=True) or 4
        cpu_count_physical = psutil.cpu_count(logical=False) or 2
        
        try:
            cpu_freq_obj = psutil.cpu_freq()
            current_freq = round(cpu_freq_obj.current, 1) if cpu_freq_obj else 0.0
            max_freq = round(cpu_freq_obj.max, 1) if cpu_freq_obj else 0.0
        except Exception:
            current_freq, max_freq = 0.0, 0.0

        # Memory details
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()

        # Disk details
        disks: List[Dict[str, Any]] = []
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

        # Network I/O byte counters
        net_io = psutil.net_io_counters()
        net_stats = {
            "bytes_recv_mb": round(net_io.bytes_recv / (1024 ** 2), 2),
            "bytes_sent_mb": round(net_io.bytes_sent / (1024 ** 2), 2),
            "packets_recv": net_io.packets_recv,
            "packets_sent": net_io.packets_sent
        }

        # Process counts
        total_pids = len(psutil.pids())

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "status": "ACTIVE",
            "os_name": f"{self.uname.system} {self.uname.release}",
            "os_version": self.uname.version,
            "architecture": self.uname.machine,
            "hostname": self.uname.node,
            "boot_time": self.boot_time.strftime("%Y-%m-%d %H:%M:%S"),
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
                "current_freq_mhz": current_freq,
                "max_freq_mhz": max_freq
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
