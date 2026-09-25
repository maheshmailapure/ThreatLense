import time
from datetime import datetime
from typing import Dict, Any, List, Optional

SUSPICIOUS_C2_PORTS = {4444, 1337, 5555, 6667, 8888, 31337, 9001, 9999, 4443}
SHELL_PROCESSES = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "rundll32.exe"}

class EventCorrelator:
    """
    Correlates disparate real-time events across Process, Network, File, Download,
    and Browser surfaces to identify multi-stage attack vectors and discard routine activity.
    """
    def __init__(self):
        self._recent_events: List[Dict[str, Any]] = []

    def correlate(
        self,
        system_data: Dict[str, Any],
        process_data: Dict[str, Any],
        network_data: Dict[str, Any],
        download_data: Dict[str, Any],
        browser_data: Dict[str, Any],
        persistence_data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Correlate telemetry across all active sub-monitors.
        Returns a list of structured security incidents (or empty list if completely benign).
        """
        detected_incidents: List[Dict[str, Any]] = []
        now_iso = datetime.utcnow().isoformat()

        # 1. Check for Browser spawning Command Shells / Script Interpreters (Critical RCE indicator)
        suspicious_children = browser_data.get("suspicious_child_spawns", [])
        for child in suspicious_children:
            detected_incidents.append({
                "incident_type": "BROWSER_RCE_SUSPICION",
                "attack_category": "MALWARE-LIKE BEHAVIOR",
                "severity": "CRITICAL",
                "confidence": 98.5,
                "title": f"Suspicious Child Process Spawned by Browser: {child.get('child_name')}",
                "process": child.get("child_name"),
                "pid": child.get("child_pid"),
                "parent_pid": child.get("parent_browser_pid"),
                "evidence": f"Browser process (PID {child.get('parent_browser_pid')}) spawned execution shell ({child.get('child_name')} PID {child.get('child_pid')}).",
                "timestamp": now_iso,
                "recommended_action": "Terminate child process immediately and inspect browser tab origin."
            })

        # 2. Check for High-Risk File Downloads (Double Extension or High-Entropy Binaries)
        threat_downloads = download_data.get("new_threats", [])
        for d in threat_downloads:
            detected_incidents.append({
                "incident_type": "SUSPICIOUS_DOWNLOAD",
                "attack_category": "DOWNLOAD INSPECTION",
                "severity": "MEDIUM",
                "confidence": 75.0,
                "is_harmful": False,  # Pending Atria AI evaluation
                "ai_status": "ANALYZING",
                "title": f"New Download Intercepted for AI Inspection: {d.get('filename')}",
                "process": "Browser Download Interceptor",
                "filepath": d.get("filepath"),
                "sha256": d.get("sha256", "N/A"),
                "entropy": d.get("entropy", 0.0),
                "evidence": f"File '{d.get('filename')}' intercepted with entropy {d.get('entropy')}. Dispatching to Atria AI.",
                "timestamp": now_iso,
                "recommended_action": "Atria AI cloud sandbox evaluating file payload safety."
            })

        # 3. Check for Suspicious Process Execution from Temp / Downloads
        new_procs = process_data.get("new_processes", [])
        for p in new_procs:
            if p.get("is_suspicious_location"):
                detected_incidents.append({
                    "incident_type": "SUSPICIOUS_BINARY_LOCATION",
                    "attack_category": "MALWARE-LIKE BEHAVIOR",
                    "severity": "HIGH",
                    "confidence": 88.0,
                    "title": f"Binary Executed from Temp/Downloads: {p.get('name')}",
                    "process": p.get("name"),
                    "pid": p.get("pid"),
                    "exe_path": p.get("exe_path"),
                    "evidence": f"Process '{p.get('name')}' (PID {p.get('pid')}) executed from untrusted directory '{p.get('exe_path')}'.",
                    "timestamp": now_iso,
                    "recommended_action": "Inspect process digital signature and verify parent process origin."
                })

        # 4. Check Network Flows for C2 Sockets, External Port Scans & Inbound Exploit Vectors
        HIGH_RISK_INBOUND_PORTS = {
            445: "SMB / EternalBlue",
            3389: "RDP / BlueKeep",
            135: "MSRPC / DCOM",
            139: "NetBIOS Session",
            21: "FTP Service",
            23: "Telnet Cleartext",
            1433: "MSSQL Database",
            3306: "MySQL Database",
            5900: "VNC Remote Desktop",
            4444: "Metasploit C2 Listener",
            1337: "Backdoor Shell",
            5555: "ADB / Trojan"
        }

        flows = network_data.get("flows", [])
        inbound_ports_by_ip: Dict[str, set] = {}
        syn_recv_by_ip: Dict[str, int] = {}

        for f in flows:
            r_port = f.get("remote_port", 0)
            r_ip = f.get("remote_address", "")
            l_port = f.get("local_port", 0)
            proc_name = (f.get("process_name") or "").lower()
            r_type = f.get("remote_type", "")
            status = f.get("status", "")
            direction = f.get("direction", "")

            # A. Check shell / interpreter process connecting externally
            if proc_name in SHELL_PROCESSES and r_type == "EXTERNAL":
                detected_incidents.append({
                    "incident_type": "C2_SHELL_ACTIVITY",
                    "attack_category": "COMMAND & CONTROL (C2)",
                    "severity": "CRITICAL",
                    "confidence": 98.0,
                    "title": f"Shell Process Connected to External IP: {proc_name} -> {r_ip}:{r_port}",
                    "process": proc_name,
                    "pid": f.get("pid"),
                    "source_ip": r_ip,
                    "target_port": r_port,
                    "input_features": f,
                    "evidence": f"Process '{proc_name}' (PID {f.get('pid')}) established an active connection to external endpoint {r_ip}:{r_port}.",
                    "timestamp": now_iso,
                    "recommended_action": f"Terminate PID {f.get('pid')} and block IP {r_ip} with netsh firewall rule."
                })

            # B. Check known exploit / backdoor ports (outbound)
            elif r_port in SUSPICIOUS_C2_PORTS and r_type == "EXTERNAL":
                detected_incidents.append({
                    "incident_type": "SUSPICIOUS_PORT_C2",
                    "attack_category": "REVERSE SHELL / BACKDOOR",
                    "severity": "CRITICAL",
                    "confidence": 96.5,
                    "title": f"Connection on Known Exploit Port: {r_ip}:{r_port} ({proc_name})",
                    "process": proc_name,
                    "pid": f.get("pid"),
                    "source_ip": r_ip,
                    "target_port": r_port,
                    "input_features": f,
                    "evidence": f"Active socket connection directed to high-risk port {r_port} by {proc_name}.",
                    "timestamp": now_iso,
                    "recommended_action": f"Block outbound traffic to {r_ip}:{r_port} and inspect {proc_name} binary."
                })

            # C. Inbound external attack detection (Someone attacking from the outside)
            if r_type in ["EXTERNAL", "PRIVATE"] and r_ip not in ["127.0.0.1", "::1", "0.0.0.0", ""]:
                # Inbound connection attempt to local machine
                if direction in ["INBOUND", "LISTENING"] or l_port < 1024 or status in ["SYN_RECV", "ESTABLISHED"]:
                    inbound_ports_by_ip.setdefault(r_ip, set()).add(l_port)
                    if status == "SYN_RECV":
                        syn_recv_by_ip[r_ip] = syn_recv_by_ip.get(r_ip, 0) + 1

                    # C1. Direct exploit attack on sensitive local service ports
                    if l_port in HIGH_RISK_INBOUND_PORTS and r_type == "EXTERNAL":
                        detected_incidents.append({
                            "incident_type": "INBOUND_EXPLOIT_ATTEMPT",
                            "attack_category": "EXPLOIT / UNAUTHORIZED INGRESS",
                            "severity": "CRITICAL",
                            "confidence": 99.0,
                            "title": f"Inbound Attack on {HIGH_RISK_INBOUND_PORTS[l_port]} Port {l_port} from {r_ip}",
                            "process": f.get("process_name", "System"),
                            "pid": f.get("pid"),
                            "source_ip": r_ip,
                            "target_port": l_port,
                            "input_features": f,
                            "evidence": f"Remote host {r_ip} attempted unauthorized ingress against high-risk service {HIGH_RISK_INBOUND_PORTS[l_port]} on local port {l_port}.",
                            "timestamp": now_iso,
                            "recommended_action": f"Block IP {r_ip} in Windows Firewall immediately and close port {l_port}."
                        })

        # D. Port Scanning / Host Reconnaissance (3+ distinct ports probed by external IP)
        for scan_ip, probed_ports in inbound_ports_by_ip.items():
            if len(probed_ports) >= 3:
                detected_incidents.append({
                    "incident_type": "EXTERNAL_PORT_SCAN",
                    "attack_category": "RECONNAISSANCE / PORT SCAN",
                    "severity": "HIGH",
                    "confidence": 98.0,
                    "title": f"External Port Reconnaissance Scan Detected from {scan_ip} ({len(probed_ports)} ports)",
                    "process": "Network Sentinel",
                    "source_ip": scan_ip,
                    "target_port": list(probed_ports)[0],
                    "evidence": f"Remote IP {scan_ip} actively probed multiple local service ports ({list(probed_ports)[:5]}).",
                    "timestamp": now_iso,
                    "recommended_action": f"Add persistent block rule for {scan_ip} in Windows Defender Firewall."
                })

        # E. Inbound SYN Flood / Denial of Service
        for flood_ip, syn_count in syn_recv_by_ip.items():
            if syn_count >= 5:
                detected_incidents.append({
                    "incident_type": "INBOUND_SYN_FLOOD",
                    "attack_category": "DENIAL OF SERVICE (SYN FLOOD)",
                    "severity": "CRITICAL",
                    "confidence": 97.5,
                    "title": f"Inbound SYN Flood / DoS Detected from {flood_ip} ({syn_count} half-open sockets)",
                    "process": "Network Kernel",
                    "source_ip": flood_ip,
                    "evidence": f"Received {syn_count} concurrent unacknowledged SYN connection bursts from {flood_ip}.",
                    "timestamp": now_iso,
                    "recommended_action": f"Block IP {flood_ip} with high-priority Netsh firewall drop rule."
                })

        # 5. Check Persistence Additions
        startup_items = persistence_data.get("startup_items", [])
        for item in startup_items:
            path = (item.get("path") or "").lower()
            if any(bad in path for bad in ["\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "\\public\\"]):
                detected_incidents.append({
                    "incident_type": "SUSPICIOUS_PERSISTENCE",
                    "attack_category": "PERSISTENCE MECHANISM",
                    "severity": "HIGH",
                    "confidence": 91.0,
                    "title": f"Suspicious Startup Registry Persistence: {item.get('name')}",
                    "process": item.get("name"),
                    "evidence": f"Startup item '{item.get('name')}' points to untrusted location '{item.get('path')}'.",
                    "timestamp": now_iso,
                    "recommended_action": "Remove registry entry and scan referenced executable."
                })

        return detected_incidents
