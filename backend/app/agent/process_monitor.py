import time
import os
import psutil
from datetime import datetime
from typing import Dict, Any, List, Set

class ProcessMonitor:
    """
    Monitors running processes on the Windows operating system in real-time.
    Extracts process trees, resource consumption, executable origins, and detects
    suspicious parent-child process anomalies.
    """
    def __init__(self):
        self._known_pids: Set[int] = set()
        self._process_cache: Dict[int, Dict[str, Any]] = {}
        self.last_scan_time = 0.0

    def collect(self, limit: int = 60) -> Dict[str, Any]:
        """Collect current processes snapshot and detect newly created/terminated processes."""
        current_processes: List[Dict[str, Any]] = []
        current_pids: Set[int] = set()
        new_processes: List[Dict[str, Any]] = []

        now = time.time()
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'create_time']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                if pid == 0:
                    continue
                current_pids.add(pid)

                # Fetch basic process metrics safely
                name = pinfo.get('name') or f"PID:{pid}"
                ppid = pinfo.get('ppid') or 0
                create_time = pinfo.get('create_time') or now

                # Memory and CPU (fast sampling)
                try:
                    mem_info = proc.memory_info()
                    mem_mb = round(mem_info.rss / (1024 ** 2), 2)
                    mem_pct = round(proc.memory_percent(), 1)
                except Exception:
                    mem_mb, mem_pct = 0.0, 0.0

                try:
                    cpu_pct = proc.cpu_percent(interval=None)
                except Exception:
                    cpu_pct = 0.0

                # Check executable path if accessible
                exe_path = "System"
                try:
                    exe_path = proc.exe() or name
                except Exception:
                    exe_path = name

                # Identify if process was created from a suspicious location
                is_suspicious_location = False
                lower_exe = exe_path.lower()
                lower_name = name.lower()
                KNOWN_DEV_PROCS = {"node.exe", "npm.cmd", "git.exe", "code.exe", "python.exe", "uvicorn.exe", "vite.exe", "electron.exe", "conhost.exe", "antigravity.exe", "cursor.exe"}
                if lower_name not in KNOWN_DEV_PROCS and any(p in lower_exe for p in ["\\temp\\", "\\downloads\\", "\\appdata\\local\\temp\\"]):
                    if lower_exe.endswith((".exe", ".scr", ".vbs", ".bat", ".cmd", ".ps1")):
                        is_suspicious_location = True

                entry = {
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "exe_path": exe_path,
                    "cpu_percent": cpu_pct,
                    "memory_mb": mem_mb,
                    "memory_percent": mem_pct,
                    "create_time": datetime.fromtimestamp(create_time).strftime("%Y-%m-%d %H:%M:%S"),
                    "is_suspicious_location": is_suspicious_location
                }

                current_processes.append(entry)

                # Check if this PID is newly spawned since last check
                if self._known_pids and pid not in self._known_pids:
                    new_processes.append(entry)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Update known PID state
        terminated_pids = list(self._known_pids - current_pids) if self._known_pids else []
        self._known_pids = current_pids
        self.last_scan_time = now

        # Sort top processes by memory consumption
        current_processes.sort(key=lambda x: x["memory_mb"], reverse=True)
        displayed_processes = current_processes[:limit]

        return {
            "status": "ACTIVE",
            "timestamp": datetime.utcnow().isoformat(),
            "total_running_processes": len(current_processes),
            "new_processes_detected": len(new_processes),
            "new_processes": new_processes,
            "terminated_pids_count": len(terminated_pids),
            "processes": displayed_processes
        }
