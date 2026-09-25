from typing import List, Dict, Any
from datetime import datetime, timedelta
import random

class UEBAService:
    @staticmethod
    def get_entity_profiles() -> List[Dict[str, Any]]:
        """Return user and device behavioral anomaly profiles with risk scores."""
        return [
            {
                "entity_id": "USR-001",
                "name": "Alex Mercer (Database Admin)",
                "entity_type": "User Account",
                "role": "DBA",
                "risk_score": 88,
                "risk_level": "HIGH",
                "status": "ANOMALOUS ACTIVITY",
                "baseline_deviation_pct": 74.5,
                "anomaly_indicators": [
                    {"type": "After-Hours Login", "detail": "Authenticated at 03:14 AM UTC (Normal: 09:00 - 18:00 UTC)", "severity": "HIGH"},
                    {"type": "Mass Data Query", "detail": "Queried 45,000 sensitive records in 60 seconds (Baseline: 250/min)", "severity": "CRITICAL"},
                    {"type": "Privilege Escalation", "detail": "Attempted SUDO command from unapproved IP 192.168.1.189", "severity": "HIGH"}
                ],
                "last_active": (datetime.utcnow() - timedelta(minutes=14)).isoformat()
            },
            {
                "entity_id": "DEV-042",
                "name": "SRV-PROD-WEB-01",
                "entity_type": "Host Server",
                "role": "Edge Web Server",
                "risk_score": 94,
                "risk_level": "CRITICAL",
                "status": "SUSPECTED COMPROMISE",
                "baseline_deviation_pct": 91.2,
                "anomaly_indicators": [
                    {"type": "Outbound Port Scan", "detail": "Initiated 250 connections to internal subnet 192.168.2.0/24", "severity": "CRITICAL"},
                    {"type": "Unusual Binary Execution", "detail": "Process /tmp/.nc executed with root permissions", "severity": "CRITICAL"},
                    {"type": "DNS Tunneling Spike", "detail": "High frequency of sub-domain TXT record lookups", "severity": "HIGH"}
                ],
                "last_active": (datetime.utcnow() - timedelta(minutes=5)).isoformat()
            },
            {
                "entity_id": "USR-004",
                "name": "Sarah Chen (Security Analyst)",
                "entity_type": "User Account",
                "role": "SOC Analyst",
                "risk_score": 12,
                "risk_level": "LOW",
                "status": "NORMAL BASELINE",
                "baseline_deviation_pct": 4.1,
                "anomaly_indicators": [],
                "last_active": (datetime.utcnow() - timedelta(minutes=2)).isoformat()
            },
            {
                "entity_id": "DEV-019",
                "name": "WORKSTATION-CORP-88",
                "entity_type": "Workstation",
                "role": "Developer Laptop",
                "risk_score": 65,
                "risk_level": "MEDIUM",
                "status": "MONITORING",
                "baseline_deviation_pct": 42.0,
                "anomaly_indicators": [
                    {"type": "Failed Authentication Spike", "detail": "7 failed SSH logins within 2 minutes to internal git host", "severity": "MEDIUM"}
                ],
                "last_active": (datetime.utcnow() - timedelta(minutes=32)).isoformat()
            }
        ]

    @staticmethod
    def get_ueba_metrics() -> Dict[str, Any]:
        """Aggregate behavioral anomaly metrics across enterprise entities."""
        return {
            "total_entities_monitored": 148,
            "high_risk_entities": 3,
            "critical_risk_entities": 1,
            "normal_entities": 144,
            "avg_fleet_risk_score": 18.4,
            "active_insider_threat_alerts": 4,
            "lateral_movement_attempts": 2
        }
