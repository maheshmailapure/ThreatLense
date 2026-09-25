import time
import psutil
from datetime import datetime
from typing import Dict, Any, List, Set

SUPPORTED_BROWSERS = {
    "chrome.exe": "Google Chrome",
    "msedge.exe": "Microsoft Edge",
    "firefox.exe": "Mozilla Firefox",
    "brave.exe": "Brave Browser",
    "opera.exe": "Opera Browser"
}

class BrowserMonitor:
    """
    Monitors browser instances (Chrome, Edge, Firefox) on the Windows system.
    Tracks browser processes, active sockets, child process spawning, and
    identifies abnormal browser-launched child processes (e.g. cmd.exe, powershell.exe).
    """
    def __init__(self):
        pass

    def collect(self) -> Dict[str, Any]:
        """Inspect all running supported browser processes and their socket flows."""
        active_browsers: Dict[str, Dict[str, Any]] = {}
        browser_processes: List[Dict[str, Any]] = []
        suspicious_children: List[Dict[str, Any]] = []
        browser_pids: Set[int] = set()

        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'create_time']):
            try:
                pinfo = proc.info
                pid = pinfo['pid']
                name = (pinfo.get('name') or "").lower()

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

                    # Memory
                    try:
                        mem_info = proc.memory_info()
                        mem_mb = round(mem_info.rss / (1024 ** 2), 2)
                    except Exception:
                        mem_mb = 0.0

                    active_browsers[browser_family]["process_count"] += 1
                    active_browsers[browser_family]["total_memory_mb"] = round(
                        active_browsers[browser_family]["total_memory_mb"] + mem_mb, 2
                    )

                    browser_processes.append({
                        "pid": pid,
                        "ppid": pinfo.get('ppid', 0),
                        "name": pinfo.get('name'),
                        "browser": browser_family,
                        "memory_mb": mem_mb
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Look for suspicious child processes spawned by browsers (e.g. cmd, powershell, certutil, mshta)
        # Verify cmdline arguments and network connections to eliminate false positives on dev tools/native helpers
        SUSPICIOUS_SCRIPT_PATTERNS = [
            "-enc", "invoke-expression", "iex", "downloadstring", "downloadfile",
            "webclient", "mshta", "certutil", "-urlcache", "bitsadmin",
            "hidden", "reg add", "rundll32", "net user", "vssadmin"
        ]

        if browser_pids:
            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline']):
                try:
                    pinfo = proc.info
                    ppid = pinfo.get('ppid')
                    if ppid in browser_pids:
                        cname = (pinfo.get('name') or "").lower()
                        if cname in ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe"]:
                            cmdline_list = pinfo.get('cmdline') or []
                            cmdline_str = " ".join(cmdline_list).lower()

                            # Check if command line contains actual exploit/malware indicators
                            has_suspicious_payload = any(pattern in cmdline_str for pattern in SUSPICIOUS_SCRIPT_PATTERNS)
                            
                            # Check if child process has active socket connections
                            has_active_sockets = False
                            try:
                                conns = proc.net_connections(kind='inet')
                                for c in conns:
                                    if c.raddr and c.raddr.ip not in ["127.0.0.1", "::1", "0.0.0.0"]:
                                        has_active_sockets = True
                                        break
                            except Exception:
                                pass

                            # Only flag if there is evidence of malicious payload or external connection
                            if has_suspicious_payload or has_active_sockets:
                                suspicious_children.append({
                                    "child_pid": pinfo['pid'],
                                    "child_name": pinfo.get('name'),
                                    "cmdline": cmdline_str[:200],
                                    "has_network": has_active_sockets,
                                    "parent_browser_pid": ppid,
                                    "timestamp": datetime.utcnow().isoformat(),
                                    "severity": "CRITICAL"
                                })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        return {
            "status": "ACTIVE",
            "timestamp": datetime.utcnow().isoformat(),
            "detected_browsers": list(active_browsers.values()),
            "total_browser_processes": len(browser_processes),
            "suspicious_child_spawns_count": len(suspicious_children),
            "suspicious_child_spawns": suspicious_children
        }
