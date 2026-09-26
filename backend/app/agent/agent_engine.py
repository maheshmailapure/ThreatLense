import time
import threading
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional, Set
import psutil
from fastapi import WebSocket

from app.agent.system_monitor import SystemMonitor
from app.agent.process_monitor import ProcessMonitor
from app.agent.network_monitor import NetworkMonitor
from app.agent.download_monitor import DownloadMonitor
from app.agent.browser_monitor import BrowserMonitor
from app.agent.persistence_monitor import PersistenceMonitor
from app.agent.event_correlator import EventCorrelator
from app.agent.risk_engine import RiskEngine
from app.agent.host_anomaly_detector import host_anomaly_detector
from app.utils.logger import logger, log_event

class IDSAgentEngine:
    """
    Master Real-Time Endpoint ThreatLense Intrusion Detection System Agent.
    Runs continuously as an autonomous background daemon, gathers live telemetry
    across all security surfaces, executes event correlation, evaluates risks,
    and streams updates to connected WebSocket clients with zero UI freeze.
    """
    def __init__(self):
        self.is_running = False
        self.is_paused = False
        self._thread: Optional[threading.Thread] = None

        # Sub-monitors
        self.system_monitor = SystemMonitor()
        self.process_monitor = ProcessMonitor()
        self.network_monitor = NetworkMonitor()
        self.download_monitor = DownloadMonitor()
        self.browser_monitor = BrowserMonitor()
        self.persistence_monitor = PersistenceMonitor()

        # Correlation & Risk Engines
        self.correlator = EventCorrelator()
        self.risk_engine = RiskEngine()

        # Cached state across different scanning frequencies
        self._cached_proc_data: Dict[str, Any] = {"status": "ACTIVE", "total_running_processes": 0, "processes": []}
        self._cached_browser_data: Dict[str, Any] = {"status": "ACTIVE", "detected_browsers": []}
        self._cached_persist_data: Dict[str, Any] = {"status": "ACTIVE", "startup_items": []}
        self._last_proc_scan = 0.0
        self._last_browser_scan = 0.0
        self._last_persist_scan = 0.0

        # Live In-Memory Telemetry Snapshot
        self.latest_telemetry: Dict[str, Any] = {}
        self.active_incidents: List[Dict[str, Any]] = []

    def _collect_all(self):
        """Perform high-frequency collection (<20ms) and scheduled deep scans."""
        try:
            now = time.time()

            # 1. Instantaneous sub-10ms metrics (every 1s)
            sys_data = self.system_monitor.collect()
            net_data = self.network_monitor.collect(max_connections=50)
            dl_data = self.download_monitor.scan()

            # 2. Medium frequency scans (every 5 seconds)
            if now - self._last_proc_scan > 5.0 or not self._cached_proc_data.get("processes"):
                self._cached_proc_data = self.process_monitor.collect(limit=50)
                self._last_proc_scan = now

            if now - self._last_browser_scan > 5.0 or not self._cached_browser_data.get("detected_browsers"):
                self._cached_browser_data = self.browser_monitor.collect()
                self._last_browser_scan = now

            # 3. Low frequency persistence scan (every 15 seconds)
            if now - self._last_persist_scan > 15.0 or not self._cached_persist_data.get("startup_items"):
                self._cached_persist_data = self.persistence_monitor.collect()
                self._last_persist_scan = now

            proc_data = self._cached_proc_data
            browser_data = self._cached_browser_data
            persist_data = self._cached_persist_data

            # Correlate cross-surface telemetry
            raw_incidents = self.correlator.correlate(
                system_data=sys_data,
                process_data=proc_data,
                network_data=net_data,
                download_data=dl_data,
                browser_data=browser_data,
                persistence_data=persist_data
            )

            # Process incidents and prepend to live active list
            if raw_incidents:
                processed_incidents = self.risk_engine.process_incidents(raw_incidents)
                for p_inc in processed_incidents:
                    if not any(i.get("title") == p_inc.get("title") for i in self.active_incidents):
                        self.active_incidents.insert(0, p_inc)

            # Auto-prune terminated process incidents or stale incidents
            live_active_incidents = []
            for inc in self.active_incidents:
                pid = inc.get("pid")
                if pid and isinstance(pid, int):
                    if psutil.pid_exists(pid):
                        live_active_incidents.append(inc)
                else:
                    live_active_incidents.append(inc)
            self.active_incidents = live_active_incidents[:15]

            # Evaluate live mathematical host anomaly deviation
            host_anomaly = host_anomaly_detector.evaluate_live_sample()
            if host_anomaly.get("is_anomaly") and not host_anomaly_detector.is_calibrating and host_anomaly.get("anomaly_score", 0) >= 0.95:
                anomaly_inc = {
                    "incident_type": "HOST_BEHAVIORAL_ANOMALY",
                    "attack_category": "ZERO-DAY BEHAVIORAL DEVIATION",
                    "severity": "LOW",
                    "confidence": round(host_anomaly.get("anomaly_score", 0) * 100, 1),
                    "title": f"Statistical System Metric Deviation (Score: {host_anomaly.get('anomaly_score')})",
                    "process": "Telemetry Engine",
                    "evidence": f"Baseline deviation noticed. Max Z-Score: {host_anomaly.get('z_deviation_max')}.",
                    "timestamp": datetime.utcnow().isoformat(),
                    "recommended_action": "Routine observation."
                }
                if not any(i.get("incident_type") == "HOST_BEHAVIORAL_ANOMALY" for i in self.active_incidents):
                    self.active_incidents.insert(0, anomaly_inc)

            # Assemble live telemetry snapshot
            self.latest_telemetry = {
                "agent_status": "ONLINE" if self.is_running else "READY",
                "timestamp": datetime.utcnow().isoformat(),
                "component_health": {
                    "ids_agent": "ONLINE" if not self.is_paused else "PAUSED",
                    "system_monitor": "ACTIVE",
                    "network_monitor": "ACTIVE",
                    "process_monitor": "ACTIVE",
                    "download_monitor": "ACTIVE",
                    "browser_monitor": "ACTIVE",
                    "persistence_monitor": "ACTIVE",
                    "database": "CONNECTED",
                    "atria_ai": "ONLINE"
                },
                "host_anomaly": host_anomaly,
                "system": sys_data,
                "processes": proc_data,
                "network": net_data,
                "downloads": dl_data,
                "browsers": browser_data,
                "persistence": persist_data,
                "active_incidents": self.active_incidents,
                "active_incidents_count": len(self.active_incidents)
            }
        except Exception as err:
            logger.error(f"Error in IDS Agent collection cycle: {err}")

    def _loop(self):
        """Background continuous monitoring loop running every 1 second."""
        logger.info("Real-Time IDS Background Monitoring Agent daemon started.")
        while self.is_running:
            if not self.is_paused:
                self._collect_all()
            time.sleep(1.0)

    def clear_incidents(self):
        """Reset and clear all in-memory active threat incidents."""
        self.active_incidents = []
        if self.latest_telemetry:
            self.latest_telemetry["active_incidents"] = []
            self.latest_telemetry["active_incidents_count"] = 0

    def start(self):
        """Start the background monitoring agent thread."""
        if not self.is_running:
            self.is_running = True
            self.is_paused = False
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
            log_event("IDS_AGENT_STARTED", {"timestamp": datetime.utcnow().isoformat()})

    def stop(self):
        """Stop the background monitoring agent."""
        self.is_running = False
        log_event("IDS_AGENT_STOPPED", {"timestamp": datetime.utcnow().isoformat()})

    def pause(self):
        """Pause monitoring cycles."""
        self.is_paused = True

    def resume(self):
        """Resume monitoring cycles."""
        self.is_paused = False

    def get_snapshot(self) -> Dict[str, Any]:
        """Return the latest live in-memory telemetry snapshot instantly (0ms)."""
        if not self.latest_telemetry:
            return {
                "agent_status": "ONLINE" if self.is_running else "READY",
                "timestamp": datetime.utcnow().isoformat(),
                "component_health": {
                    "ids_agent": "ONLINE",
                    "system_monitor": "ACTIVE",
                    "network_monitor": "ACTIVE",
                    "process_monitor": "ACTIVE",
                    "download_monitor": "ACTIVE",
                    "browser_monitor": "ACTIVE",
                    "persistence_monitor": "ACTIVE",
                    "database": "CONNECTED",
                    "atria_ai": "ONLINE"
                },
                "system": self.system_monitor.collect(),
                "processes": self._cached_proc_data,
                "network": {"status": "ACTIVE", "total_sockets": 0, "flows": []},
                "downloads": {"status": "ACTIVE", "in_progress_downloads": [], "recent_downloads": []},
                "browsers": {"status": "ACTIVE", "detected_browsers": []},
                "persistence": {"status": "ACTIVE", "startup_items": []},
                "active_incidents": [],
                "active_incidents_count": 0
            }
        return self.latest_telemetry

# Global Singleton Agent Instance
ids_agent = IDSAgentEngine()
