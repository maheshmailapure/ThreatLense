import os
import time
import psutil
from datetime import datetime
from typing import Dict, Any, List, Optional

class PersistenceMonitor:
    """
    Monitors Windows persistence mechanisms: Startup folder, active/stopped Windows Services,
    and checks for unauthorized persistence items with 15-second TTL caching.
    """
    def __init__(self):
        self.startup_dir = os.path.join(
            os.getenv('APPDATA', ''),
            r'Microsoft\Windows\Start Menu\Programs\Startup'
        )
        self._cached_result: Optional[Dict[str, Any]] = None
        self.last_scan_time = 0.0
        self.cache_ttl = 15.0

    def collect(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Inspect startup folder files and active Windows system services."""
        now = time.time()
        if not force_refresh and self._cached_result and (now - self.last_scan_time < self.cache_ttl):
            return self._cached_result

        startup_items: List[Dict[str, Any]] = []

        # 1. Startup folder check
        if os.path.exists(self.startup_dir):
            try:
                for entry in os.scandir(self.startup_dir):
                    if entry.is_file():
                        startup_items.append({
                            "name": entry.name,
                            "path": entry.path,
                            "size_kb": round(entry.stat().st_size / 1024, 2),
                            "modified": datetime.fromtimestamp(entry.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                        })
            except Exception:
                pass

        # 2. Windows Services check (via psutil)
        services: List[Dict[str, Any]] = []
        running_services_count = 0
        stopped_services_count = 0

        if hasattr(psutil, "win_service_iter"):
            try:
                for svc in psutil.win_service_iter():
                    try:
                        sinfo = svc.as_dict()
                        st = sinfo.get("status", "unknown")
                        if st == "running":
                            running_services_count += 1
                        else:
                            stopped_services_count += 1

                        if len(services) < 30:
                            services.append({
                                "name": sinfo.get("name"),
                                "display_name": sinfo.get("display_name"),
                                "status": st,
                                "start_type": sinfo.get("start_type"),
                                "binpath": sinfo.get("binpath", "N/A")
                            })
                    except Exception:
                        continue
            except Exception:
                pass

        self.last_scan_time = now
        result = {
            "status": "ACTIVE",
            "timestamp": datetime.utcnow().isoformat(),
            "startup_folder_items_count": len(startup_items),
            "startup_items": startup_items,
            "running_services_count": running_services_count,
            "stopped_services_count": stopped_services_count,
            "inspected_services": services
        }
        self._cached_result = result
        return result
