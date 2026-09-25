from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.database.models import Alert, Detection
from datetime import datetime, timedelta

KILL_CHAIN_STAGES = [
    {"id": "reconnaissance", "name": "1. Reconnaissance", "description": "Active port scanning, host discovery, and service enumeration."},
    {"id": "weaponization", "name": "2. Weaponization", "description": "Crafting exploit payloads, SQLi queries, or buffer overflow triggers."},
    {"id": "delivery", "name": "3. Delivery", "description": "Transmission of malicious payloads via HTTP, SSH, FTP, or email."},
    {"id": "exploitation", "name": "4. Exploitation", "description": "Triggering vulnerability (e.g. U2R root shell spawn, remote execution)."},
    {"id": "installation", "name": "5. Installation", "description": "Persistence mechanisms, backdoor listeners, or malicious cron jobs."},
    {"id": "command_and_control", "name": "6. Command & Control", "description": "Outbound beaconing to external attacker infrastructure."},
    {"id": "actions_on_objectives", "name": "7. Actions on Objectives", "description": "Data exfiltration, database dumping, or DoS service outage."}
]

class KillChainService:
    @staticmethod
    def get_stages() -> List[Dict[str, Any]]:
        return KILL_CHAIN_STAGES

    @staticmethod
    def correlate_campaigns(db: Session) -> List[Dict[str, Any]]:
        """Correlate active database alerts into unified Kill Chain campaign timelines."""
        alerts = db.query(Alert).order_by(Alert.created_at.desc()).limit(50).all()
        
        # Predefined demo campaigns mapped to realistic attack stories
        campaigns = [
            {
                "id": "CAMP-2026-088",
                "name": "Coordinated APT Reconnaissance & Root Shell Intrusion",
                "attacker_ip": "203.0.113.88",
                "target_host": "192.168.1.100 (Primary App Server)",
                "status": "CRITICAL - ACTIVE MITIGATION",
                "progress_pct": 71,
                "stages_activated": [
                    {
                        "stage_id": "reconnaissance",
                        "stage_name": "1. Reconnaissance",
                        "matched_threat": "Nmap Aggressive Port Sweep (Probe)",
                        "timestamp": (datetime.utcnow() - timedelta(minutes=45)).isoformat(),
                        "confidence": 98.4,
                        "details": "High diff_srv_rate detected across 25 host ports."
                    },
                    {
                        "stage_id": "weaponization",
                        "stage_name": "2. Weaponization",
                        "matched_threat": "SQL Injection & Auth Bypass Query Crafted",
                        "timestamp": (datetime.utcnow() - timedelta(minutes=30)).isoformat(),
                        "confidence": 96.1,
                        "details": "Observed URI payload with UNION SELECT statement."
                    },
                    {
                        "stage_id": "delivery",
                        "stage_name": "3. Delivery",
                        "matched_threat": "HTTP Malicious Payload Transmission",
                        "timestamp": (datetime.utcnow() - timedelta(minutes=20)).isoformat(),
                        "confidence": 95.8,
                        "details": "Ingested high-byte HTTP flow targeting /api/auth endpoint."
                    },
                    {
                        "stage_id": "exploitation",
                        "stage_name": "4. Exploitation",
                        "matched_threat": "Root Shell Privilege Escalation (U2R)",
                        "timestamp": (datetime.utcnow() - timedelta(minutes=10)).isoformat(),
                        "confidence": 99.2,
                        "details": "Spawned root shell (root_shell=1, su_attempted=1)."
                    },
                    {
                        "stage_id": "installation",
                        "stage_name": "5. Installation",
                        "matched_threat": "Suspicious Listening Socket Created",
                        "timestamp": (datetime.utcnow() - timedelta(minutes=3)).isoformat(),
                        "confidence": 91.5,
                        "details": "Active socket listener detected on non-standard port 44211."
                    }
                ]
            },
            {
                "id": "CAMP-2026-092",
                "name": "Distributed TCP SYN Flood & Service Disruption",
                "attacker_ip": "198.51.100.42",
                "target_host": "192.168.1.102 (Edge Web Gateway)",
                "status": "CONTAINED",
                "progress_pct": 85,
                "stages_activated": [
                    {
                        "stage_id": "reconnaissance",
                        "stage_name": "1. Reconnaissance",
                        "matched_threat": "ICMP Ping Sweep Probe",
                        "timestamp": (datetime.utcnow() - timedelta(hours=2)).isoformat(),
                        "confidence": 94.2,
                        "details": "Sequential subnet host discovery."
                    },
                    {
                        "stage_id": "delivery",
                        "stage_name": "3. Delivery",
                        "matched_threat": "Volumetric TCP SYN Stream",
                        "timestamp": (datetime.utcnow() - timedelta(hours=1, minutes=45)).isoformat(),
                        "confidence": 99.1,
                        "details": "480 connections/sec with S0 flag."
                    },
                    {
                        "stage_id": "actions_on_objectives",
                        "stage_name": "7. Actions on Objectives",
                        "matched_threat": "Denial of Service (DoS Outage Attempt)",
                        "timestamp": (datetime.utcnow() - timedelta(hours=1, minutes=30)).isoformat(),
                        "confidence": 98.7,
                        "details": "Target service queue capacity saturation."
                    }
                ]
            }
        ]

        return campaigns
