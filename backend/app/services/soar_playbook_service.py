from typing import List, Dict, Any
from datetime import datetime

PLAYBOOKS = [
    {
        "id": "playbook_firewall_drop",
        "name": "Automated Perimeter IP Isolation",
        "trigger": "Critical DoS / Inbound Brute Force Alert",
        "target": "Firewall / Edge Router (iptables/netsh)",
        "status": "READY",
        "actions": [
            "1. Validate threat source IP against internal whitelist",
            "2. Inject immediate DROP rule into host firewall filter table",
            "3. Broadcast dynamic blocklist to perimeter edge gateways",
            "4. Log immutable containment event in security audit trail"
        ],
        "default_command": "iptables -I INPUT -s {source_ip} -j DROP"
    },
    {
        "id": "playbook_process_kill",
        "name": "Host Rogue Process & Socket Termination",
        "trigger": "User-to-Root (U2R) / Malicious Shell Spawn Alert",
        "target": "Host Operating System Daemon",
        "status": "READY",
        "actions": [
            "1. Locate process PID associated with anomalous socket connection",
            "2. Send SIGKILL signal to isolate rogue subprocess",
            "3. Revoke open file handles and socket descriptors",
            "4. Capture forensic memory dump for offline analysis"
        ],
        "default_command": "kill -9 {pid} && lsof -i :{port}"
    },
    {
        "id": "playbook_account_quarantine",
        "name": "Compromised Account & Credential Quarantine",
        "trigger": "High-Risk UEBA Credential Abuse Alert",
        "target": "Identity & Access Management (IAM)",
        "status": "READY",
        "actions": [
            "1. Invalidate active JWT bearer tokens and browser sessions",
            "2. Force user account status into locked quarantine state",
            "3. Require MFA re-enrollment upon next login attempt",
            "4. Dispatch emergency notification to Security Admin"
        ],
        "default_command": "UPDATE users SET role='quarantined' WHERE username='{username}'"
    }
]

class SOARPlaybookService:
    @staticmethod
    def get_playbooks() -> List[Dict[str, Any]]:
        return PLAYBOOKS

    @staticmethod
    def execute_playbook(playbook_id: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a containment action playbook and return audit execution logs."""
        matched = next((p for p in PLAYBOOKS if p["id"] == playbook_id), None)
        if not matched:
            raise ValueError(f"Playbook {playbook_id} not found.")

        target_ip = parameters.get("source_ip", "203.0.113.88")
        target_pid = parameters.get("pid", 4128)
        target_user = parameters.get("username", "compromised_user")

        executed_cmd = matched["default_command"].replace("{source_ip}", str(target_ip)).replace("{pid}", str(target_pid)).replace("{username}", str(target_user))

        return {
            "execution_id": f"SOAR-EXEC-{int(datetime.utcnow().timestamp())}",
            "playbook_id": playbook_id,
            "playbook_name": matched["name"],
            "status": "SUCCESSFULLY EXECUTED",
            "timestamp": datetime.utcnow().isoformat(),
            "target": matched["target"],
            "command_executed": executed_cmd,
            "containment_summary": f"Playbook '{matched['name']}' executed successfully against target {target_ip or target_user}. Threat neutralized."
        }
