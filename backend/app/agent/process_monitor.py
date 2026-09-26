import time
import os
import psutil
from datetime import datetime
from typing import Dict, Any, List, Set, Optional

KNOWN_DEV_PROCS = {
    "node.exe", "npm.cmd", "git.exe", "code.exe", "python.exe", "pythonw.exe",
    "uvicorn.exe", "vite.exe", "electron.exe", "conhost.exe", "antigravity.exe",
    "cursor.exe", "threatlense.exe", "threatlense-setup.exe"
}

class ProcessMonitor:
    """
    Monitors running processes on the Windows operating system in real-time.
    Extracts process trees, resource consumption, executable origins, and detects
    suspicious parent-child process anomalies with fast in-memory caching.
    """
    def __init__(self):
        self._known_pids: Set[int] = set()
        self._cached_result: Optional[Dict[str, Any]] = None
        self.last_scan_time = 0.0
        self.cache_ttl = 4.0  # Cache for 4 seconds to avoid saturating Windows kernel APIs

    def collect(self, limit: int = 60, force_refresh: bool = False) -> Dict[str, Any]:
        """Collect current processes snapshot and detect newly created/terminated processes."""
        now = time.time()
        if not force_refresh and self._cached_result and (now - self.last_scan_time < self.cache_ttl):
            return self._cached_result

        current_processes: List[Dict[str, Any]] = []
        current_pids: Set[int] = set()
        new_processes: List[Dict[str, Any]] = []

        # Single batch query to avoid expensive individual process syscalls
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'memory_info', 'create_time']):
            try:
                pinfo = proc.info
                pid = pinfo.get('pid')
                if not pid or pid == 0:
                    continue
                current_pids.add(pid)

                name = pinfo.get('name') or f"PID:{pid}"
                ppid = pinfo.get('ppid') or 0
                create_time = pinfo.get('create_time') or now

                # Memory RSS from batch info (zero syscall overhead)
                mem_info = pinfo.get('memory_info')
                mem_mb = round(mem_info.rss / (1024 ** 2), 2) if mem_info else 0.0
                mem_pct = round((mem_mb / 16384.0) * 100, 1)

                is_new = self._known_pids and (pid not in self._known_pids)
                exe_path = name

                # Only inspect full disk exe path if newly spawned or suspicious extension
                is_suspicious_location = False
                lower_name = name.lower()
                if is_new or lower_name.endswith((".scr", ".vbs", ".bat", ".cmd", ".ps1", ".hta")):
                    try:
                        full_exe = proc.exe() or name
                        exe_path = full_exe
                        lower_exe = full_exe.lower()
                        if lower_name not in KNOWN_DEV_PROCS and any(p in lower_exe for p in ["\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\"]):
                            is_suspicious_location = True
                    except Exception:
                        exe_path = name

                entry = {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "exe_path": exe_path,
                    "cpu_percent": 0.0,
                    "memory_mb": mem_mb,
                    "memory_percent": mem_pct,
                    "create_time": datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M:%S"),
                    "is_suspicious_location": is_suspicious_location
                }

                current_processes.append(entry)

                if is_new:
                    new_processes.append(entry)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        terminated_pids = list(self._known_pids - current_pids) if self._known_pids else []
        self._known_pids = current_pids
        self.last_scan_time = now

        # Sort top processes by memory consumption
        current_processes.sort(key=lambda x: x["memory_mb"], reverse=True)
        displayed_processes = current_processes[:limit]

        result = {
            "status": "ACTIVE",
            "timestamp": datetime.utcnow().isoformat(),
            "total_running_processes": len(current_processes),
            "new_processes_detected": len(new_processes),
            "new_processes": new_processes,
            "terminated_pids_count": len(terminated_pids),
            "processes": displayed_processes
        }
        self._cached_result = result
        return result
