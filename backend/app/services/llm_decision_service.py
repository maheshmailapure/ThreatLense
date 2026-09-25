import os
import json
import httpx
from typing import Dict, Any, Optional
from app.utils.logger import log_event, logger

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")

class LLMDecisionService:
    @staticmethod
    def get_config() -> Dict[str, Any]:
        """Return active Ollama gateway settings."""
        return {
            "ollama_base_url": OLLAMA_BASE_URL,
            "ollama_model": OLLAMA_MODEL,
            "timeout_seconds": 15
        }

    @staticmethod
    def update_config(base_url: str, model: str) -> Dict[str, Any]:
        """Update runtime Ollama connection settings."""
        global OLLAMA_BASE_URL, OLLAMA_MODEL
        OLLAMA_BASE_URL = base_url.rstrip("/")
        OLLAMA_MODEL = model
        return LLMDecisionService.get_config()

    @staticmethod
    async def test_connection(base_url: Optional[str] = None) -> Dict[str, Any]:
        """Test reachability of the remote or local Ollama LLM gateway."""
        url = (base_url or OLLAMA_BASE_URL).rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                res = await client.get(f"{url}/api/tags")
                if res.status_code == 200:
                    models_data = res.json().get("models", [])
                    model_names = [m.get("name") for m in models_data]
                    return {
                        "connected": True,
                        "status": "ONLINE",
                        "url": url,
                        "available_models": model_names,
                        "message": f"Successfully connected to Ollama gateway. Found {len(model_names)} models."
                    }
                else:
                    return {
                        "connected": False,
                        "status": "ERROR",
                        "url": url,
                        "message": f"Ollama gateway responded with HTTP status {res.status_code}."
                    }
        except Exception as e:
            return {
                "connected": False,
                "status": "OFFLINE",
                "url": url,
                "message": f"Could not reach Ollama at {url}: {str(e)}"
            }

    @staticmethod
    async def generate_incident_decision(incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send detection and packet threat telemetry to the Ollama LLM model to generate
        intelligent security response decisions, root-cause analysis, and firewall mitigation rules.
        """
        attack_type = incident_data.get("attack_type", "Unknown Threat")
        prediction = incident_data.get("prediction", "ATTACK")
        risk_level = incident_data.get("risk_level", "HIGH")
        anomaly_score = incident_data.get("anomaly_score", 0.0)
        input_features = incident_data.get("input_features", {})
        source_ip = input_features.get("remote_addr", input_features.get("source_ip", "192.168.1.105"))
        target_port = input_features.get("service", input_features.get("target_port", "80/http"))

        prompt = f"""You are a Senior SOC Cybersecurity Incident Responder and Defensive AI Engine.
An intrusion detection event has occurred on the server/network:

INCIDENT DETAILS:
- Verdict: {prediction}
- Attack Classification: {attack_type}
- Assessed Risk Level: {risk_level}
- Behavioral Anomaly Score: {anomaly_score}
- Source Flow / IP: {source_ip}
- Target Service / Port: {target_port}
- Packet Snapshot: {json.dumps(input_features)}

Provide an immediate, actionable incident response decision in JSON format with the following keys:
1. "threat_summary": (A concise 1-2 sentence executive assessment of the threat)
2. "root_cause_analysis": (Technical breakdown of the packet anomaly / exploit mechanism)
3. "immediate_action": (Top priority defensive step to take immediately)
4. "firewall_rule": (Exact copy-paste Linux iptables / Windows netsh command to block this attack)
5. "containment_strategy": (Long-term hardening recommendation for this server)

Respond ONLY with valid JSON.
"""

        # Attempt querying remote Ollama gateway
        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                response = await client.post(
                    f"{OLLAMA_BASE_URL}/api/generate",
                    json={
                        "model": OLLAMA_MODEL,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json"
                    }
                )
                if response.status_code == 200:
                    raw_text = response.json().get("response", "")
                    decision_json = json.loads(raw_text)
                    decision_json["source"] = f"Ollama LLM ({OLLAMA_MODEL})"
                    decision_json["gateway_url"] = OLLAMA_BASE_URL
                    log_event("OLLAMA_DECISION_SUCCESS", {"model": OLLAMA_MODEL, "attack": attack_type})
                    return decision_json
        except Exception as e:
            logger.warning(f"Ollama gateway query failed or offline ({str(e)}). Using Heuristic AI Decision Engine.")

        # Heuristic AI Fallback Decision Engine
        return LLMDecisionService._generate_heuristic_decision(incident_data)

    @staticmethod
    def _generate_heuristic_decision(incident: Dict[str, Any]) -> Dict[str, Any]:
        """Deterministic expert rule-based AI reasoning engine fallback."""
        attack_type = incident.get("attack_type", "Normal")
        risk_level = incident.get("risk_level", "HIGH")
        anomaly_score = incident.get("anomaly_score", 0.0)
        input_features = incident.get("input_features", {})
        source_ip = input_features.get("remote_addr", input_features.get("source_ip", "192.168.1.105")).split(":")[0]
        if not source_ip or source_ip in ["0.0.0.0", "127.0.0.1"]:
            source_ip = "203.0.113.45"

        if attack_type == "DoS":
            return {
                "source": "AI Decision Engine (Heuristic Expert System)",
                "threat_summary": f"High-density Denial of Service (DoS) flood detected originating from {source_ip}.",
                "root_cause_analysis": "Abnormal volume of unacknowledged SYN packets (S0 flag) with 100% serror rate designed to exhaust TCP socket connection tables.",
                "immediate_action": "Apply rate-limiting and immediately drop incoming traffic from the offending source IP.",
                "firewall_rule": f"iptables -I INPUT -s {source_ip} -p tcp --syn -j DROP",
                "containment_strategy": "Enable TCP SYN Cookies (sysctl -w net.ipv4.tcp_syncookies=1) and deploy reverse proxy edge mitigation."
            }
        elif attack_type == "Probe":
            return {
                "source": "AI Decision Engine (Heuristic Expert System)",
                "threat_summary": f"Network surveillance and port scanning probe detected from {source_ip}.",
                "root_cause_analysis": "High differential service access rate (diff_srv_rate > 0.8) indicates automated Nmap/Masscan reconnaissance probing open listening ports.",
                "immediate_action": "Blacklist scanning IP address and mask server banner disclosures.",
                "firewall_rule": f"iptables -A INPUT -s {source_ip} -j REJECT --reject-with icmp-port-unreachable",
                "containment_strategy": "Implement port-knocking, hide unused ports, and restrict administrative access via VPN."
            }
        elif attack_type == "R2L":
            return {
                "source": "AI Decision Engine (Heuristic Expert System)",
                "threat_summary": f"Unauthorized remote authentication attempt / credential brute force from {source_ip}.",
                "root_cause_analysis": "Multiple consecutive failed logins coupled with abnormal command sequences detected on remote access service.",
                "immediate_action": "Enforce immediate account lockout and block source IP for 24 hours.",
                "firewall_rule": f"iptables -I INPUT -s {source_ip} -p tcp --dport 22 -j DROP",
                "containment_strategy": "Disable password-based SSH authentication, enforce SSH key pairs, and activate Fail2Ban."
            }
        elif attack_type == "U2R":
            return {
                "source": "AI Decision Engine (Heuristic Expert System)",
                "threat_summary": f"CRITICAL: User-to-Root privilege escalation attempt detected on host machine.",
                "root_cause_analysis": "Unauthorized buffer overflow triggering root shell spawn (root_shell=1, su_attempted=1) on active socket.",
                "immediate_action": "Isolate the compromised process PID immediately and revoke active host session tokens.",
                "firewall_rule": f"kill -9 $(lsof -t -i:{input_features.get('service', '80')}) && iptables -I INPUT -s {source_ip} -j DROP",
                "containment_strategy": "Audit SUID binaries, update kernel patches, and enforce SELinux / AppArmor confinement."
            }
        else:
            return {
                "source": "AI Decision Engine (Heuristic Expert System)",
                "threat_summary": f"Elevated behavioral anomaly flagged (score: {anomaly_score:.3f}).",
                "root_cause_analysis": "Packet header distribution deviates from learned K-Means centroid baseline by more than 95th percentile.",
                "immediate_action": "Enable enhanced deep packet inspection logging for this flow session.",
                "firewall_rule": f"iptables -A INPUT -s {source_ip} -m limit --limit 5/min -j LOG --log-prefix '[AI-IDS-ANOMALY]: '",
                "containment_strategy": "Retrain anomaly clustering baseline with current traffic profile."
            }
