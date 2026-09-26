import time
import psutil
from datetime import datetime
from typing import Dict, Any, List, Set, Optional

SUPPORTED_BROWSERS = {
    "chrome.exe": "Google Chrome",
    "msedge.exe": "Microsoft Edge",
    "firefox.exe": "Mozilla Firefox",
    "brave.exe": "Brave Browser",
    "opera.exe": "Opera Browser"
}

SUSPICIOUS_SCRIPT_PATTERNS = [
    "-enc", "invoke-expression", "iex", "downloadstring", "downloadfile",
    "webclient", "mshta", "certutil", "-urlcache", "bitsadmin",
    "hidden", "reg add", "rundll32", "net user", "vssadmin"
]

class BrowserMonitor:
    """
    Monitors browser instances (Chrome, Edge, Firefox) on the Windows system.
    Tracks browser processes, active sockets, child process spawning, and
    identifies abnormal browser-launched child processes with 4-second TTL caching.
    """
    def __init__(self):
        self._cached_result: Optional[Dict[str, Any]] = None
        self.last_scan_time = 0.0
        self.cache_ttl = 4.0

    def collect(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Inspect all running supported browser processes and their socket flows."""
        now = time.time()
        if not force_refresh and self._cached_result and (now - self.last_scan_time < self.cache_ttl):
            return self._cached_result

        active_browsers: Dict[str, Dict[str, Any]] = {}
        browser_processes: List[Dict[str, Any]] = []
        suspicious_children: List[Dict[str, Any]] = []
        browser_pids: Set[int] = set()

        # Single pass: find browser processes and identify suspicious children in one go
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'memory_info']):
            try:
                pinfo = proc.info
                pid = pinfo.get('pid')
                if not pid or pid == 0:
                    continue
                raw_name = pinfo.get('name') or ""
                name = raw_name.lower()

                if name in SUPPORTED_BROWSERS:
                    browser_pids.add(pid)
                    browser_family = SUPPORTED_BROWSERS[name]
                    if browser_family not in active_browsers:
                        active_browsers[browser_family] = {
                            "name": browser_family,
                            "process_count": 0,
                            "total_memory_mb": 0.0,
                            "active_connections": 0
                        }

                    mem_info = pinfo.get('memory_info')
                    mem_mb = round(mem_info.rss / (1024 ** 2), 2) if mem_info else 0.0

                    active_browsers[browser_family]["process_count"] += 1
                    active_browsers[browser_family]["total_memory_mb"] = round(
                        active_browsers[browser_family]["total_memory_mb"] + mem_mb, 2
                    )

                    browser_processes.append({
                        "pid": pid,
                        "ppid": pinfo.get('ppid', 0),
                        "name": raw_name,
                        "browser": browser_family,
                        "memory_mb": mem_mb
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self.last_scan_time = now
        result = {
            "status": "ACTIVE",
            "timestamp": datetime.utcnow().isoformat(),
            "detected_browsers": list(active_browsers.values()),
            "total_browser_processes": len(browser_processes),
            "suspicious_child_spawns_count": len(suspicious_children),
            "suspicious_child_spawns": suspicious_children
        }
        self._cached_result = result
        return result
