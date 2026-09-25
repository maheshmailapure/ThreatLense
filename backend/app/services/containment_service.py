import os
import shutil
import subprocess
import psutil
from typing import Dict, Any, Optional
from datetime import datetime
from app.utils.logger import logger, log_event

PROTECTED_PROCESSES = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe", 
    "wininit.exe", "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
    "winlogon.exe", "dwm.exe", "taskhostw.exe"
}

class ContainmentService:
    """
    Autonomous and Operator-Initiated Live System Protection Service.
    Executes real-time firewall isolation, port blocking, rogue process termination,
    and suspicious file quarantining on Windows/Linux hosts.
    """

    @staticmethod
    def block_ip(ip: str, rule_name: Optional[str] = None) -> Dict[str, Any]:
        """Add Windows Defender Firewall rule to drop all incoming and outgoing packets for an IP."""
        if not ip or ip in ["127.0.0.1", "::1", "localhost", "0.0.0.0"]:
            return {"success": False, "message": "Cannot block loopback or empty IP address."}

        sanitized_ip = ip.strip()
        name = rule_name or f"AI-IDS-Block-{sanitized_ip.replace(':', '_')}"

        commands = [
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}-IN", "dir=in", "action=block", f"remoteip={sanitized_ip}"],
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}-OUT", "dir=out", "action=block", f"remoteip={sanitized_ip}"]
        ]

        executed = []
        errors = []
        for cmd in commands:
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0 or "Ok." in res.stdout:
                    executed.append(" ".join(cmd))
                else:
                    errors.append(res.stderr.strip() or res.stdout.strip())
            except Exception as ex:
                errors.append(str(ex))

        success = len(executed) > 0
        log_event("CONTAINMENT_IP_BLOCKED", {"ip": sanitized_ip, "success": success, "rules": executed})

        return {
            "success": success,
            "ip": sanitized_ip,
            "rule_name": name,
            "commands_executed": executed,
            "errors": errors if errors else None,
            "timestamp": datetime.utcnow().isoformat(),
            "message": f"Firewall block rules installed for {sanitized_ip}." if success else f"Failed to install firewall rule: {', '.join(errors)}"
        }

    @staticmethod
    def block_port(port: int, protocol: str = "TCP", rule_name: Optional[str] = None) -> Dict[str, Any]:
        """Block an inbound or outbound port to instantly neutralize a reverse shell or backdoor."""
        if not port or port < 1 or port > 65535:
            return {"success": False, "message": f"Invalid port number: {port}"}

        proto = protocol.upper()
        name = rule_name or f"AI-IDS-Block-Port-{port}-{proto}"

        commands = [
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}-IN", f"protocol={proto}", "dir=in", "action=block", f"localport={port}"],
            ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}-OUT", f"protocol={proto}", "dir=out", "action=block", f"remoteport={port}"]
        ]

        executed = []
        errors = []
        for cmd in commands:
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                if res.returncode == 0 or "Ok." in res.stdout:
                    executed.append(" ".join(cmd))
                else:
                    errors.append(res.stderr.strip() or res.stdout.strip())
            except Exception as ex:
                errors.append(str(ex))

        success = len(executed) > 0
        log_event("CONTAINMENT_PORT_BLOCKED", {"port": port, "protocol": proto, "success": success})

        return {
            "success": success,
            "port": port,
            "protocol": proto,
            "rule_name": name,
            "commands_executed": executed,
            "errors": errors if errors else None,
            "timestamp": datetime.utcnow().isoformat(),
            "message": f"Port {port}/{proto} blocked via Windows Defender Firewall." if success else f"Failed to block port: {', '.join(errors)}"
        }

    @staticmethod
    def terminate_process(pid: int, process_name: Optional[str] = None) -> Dict[str, Any]:
        """Terminate a malicious or hijacked process by PID with OS integrity protections."""
        if pid in [0, 4]:
            return {"success": False, "message": "Refusing to terminate Core OS System kernel PID."}

        try:
            proc = psutil.Process(pid)
            name = proc.name().lower()

            if name in PROTECTED_PROCESSES:
                return {
                    "success": False, 
                    "message": f"Refusing to terminate protected critical OS process '{name}' (PID {pid})."
                }

            proc.terminate()
            gone, alive = psutil.wait_procs([proc], timeout=3)
            if alive:
                proc.kill()

            log_event("CONTAINMENT_PROCESS_TERMINATED", {"pid": pid, "process": name})
            return {
                "success": True,
                "pid": pid,
                "process_name": name,
                "message": f"Process '{name}' (PID {pid}) successfully terminated and neutralized.",
                "timestamp": datetime.utcnow().isoformat()
            }
        except psutil.NoSuchProcess:
            return {"success": True, "pid": pid, "message": f"Process PID {pid} is already terminated."}
        except psutil.AccessDenied:
            return {"success": False, "pid": pid, "message": f"Access denied when attempting to terminate PID {pid} (requires Administrator privileges)."}
        except Exception as ex:
            return {"success": False, "pid": pid, "message": f"Failed to terminate process: {str(ex)}"}

    @staticmethod
    def quarantine_file(filepath: str) -> Dict[str, Any]:
        """Safely quarantine a malicious or high-entropy downloaded file to prevent execution."""
        if not filepath or not os.path.exists(filepath):
            return {"success": False, "message": f"File path not found: '{filepath}'"}

        try:
            dirname = os.path.dirname(filepath)
            filename = os.path.basename(filepath)
            quarantine_dir = os.path.join(dirname, ".quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)

            quarantine_path = os.path.join(quarantine_dir, f"{filename}.quarantined_{int(datetime.utcnow().timestamp())}")
            shutil.move(filepath, quarantine_path)

            log_event("CONTAINMENT_FILE_QUARANTINED", {"original_path": filepath, "quarantined_path": quarantine_path})
            return {
                "success": True,
                "original_file": filepath,
                "quarantine_path": quarantine_path,
                "message": f"File '{filename}' successfully quarantined into secure vault.",
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as ex:
            return {"success": False, "filepath": filepath, "message": f"Quarantine failed: {str(ex)}"}
