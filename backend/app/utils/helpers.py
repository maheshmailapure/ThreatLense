from typing import Dict, Any, Tuple

# NSL-KDD 41 standard features
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]

CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]

NUMERICAL_COLUMNS = [col for col in NSL_KDD_COLUMNS if col not in CATEGORICAL_COLUMNS]

# NSL-KDD Attack Types to Main 4 Attack Classes + Normal
ATTACK_MAPPING: Dict[str, str] = {
    "normal": "Normal",
    # DoS
    "neptune": "DoS",
    "back": "DoS",
    "land": "DoS",
    "pod": "DoS",
    "smurf": "DoS",
    "teardrop": "DoS",
    "mailbomb": "DoS",
    "apache2": "DoS",
    "processtable": "DoS",
    "udpstorm": "DoS",
    "worm": "DoS",
    # Probe
    "ipsweep": "Probe",
    "nmap": "Probe",
    "portsweep": "Probe",
    "satan": "Probe",
    "mscan": "Probe",
    "saint": "Probe",
    # R2L
    "ftp_write": "R2L",
    "guess_passwd": "R2L",
    "imap": "R2L",
    "multihop": "R2L",
    "phf": "R2L",
    "spy": "R2L",
    "warezclient": "R2L",
    "warezmaster": "R2L",
    "sendmail": "R2L",
    "named": "R2L",
    "snmpgetattack": "R2L",
    "snmpguess": "R2L",
    "xlock": "R2L",
    "xsnoop": "R2L",
    "httptunnel": "R2L",
    # U2R
    "buffer_overflow": "U2R",
    "loadmodule": "U2R",
    "perl": "U2R",
    "rootkit": "U2R",
    "sqlattack": "U2R",
    "xterm": "U2R",
    "ps": "U2R"
}

def map_attack_category(raw_label: str) -> str:
    """Map raw NSL-KDD dataset label to 5 primary categories: Normal, DoS, Probe, R2L, U2R."""
    clean_label = str(raw_label).strip().lower().rstrip(".")
    if clean_label == "normal":
        return "Normal"
    return ATTACK_MAPPING.get(clean_label, "Unknown Attack" if clean_label != "normal" else "Normal")

def evaluate_risk(
    prediction: str,
    attack_type: str,
    anomaly_score: float,
    confidence: float = 1.0,
    anomaly_threshold: float = 0.65
) -> Tuple[str, str]:
    """
    Configurable risk evaluation engine.
    Returns (risk_level, explanation_summary).
    Risk Levels: LOW, MEDIUM, HIGH, CRITICAL.
    """
    is_attack = (prediction.upper() == "ATTACK" or (attack_type != "Normal" and attack_type != "normal"))
    is_anomaly = anomaly_score >= anomaly_threshold

    if is_attack:
        if attack_type == "U2R":
            # Privilege escalation is critical
            return "CRITICAL", f"Critical privilege escalation threat ({attack_type}) detected with confidence {confidence:.2f}."
        elif attack_type == "DoS":
            if anomaly_score > 0.8:
                return "CRITICAL", f"High-volume DoS flood attack detected with elevated anomaly score ({anomaly_score:.2f})."
            return "HIGH", f"Denial of Service attack detected ({attack_type})."
        elif attack_type in ["R2L", "Probe"]:
            return "HIGH", f"Active network intrusion/probe pattern detected ({attack_type})."
        else:
            return "HIGH", f"Suspicious malicious traffic detected ({attack_type})."
    else:
        if is_anomaly:
            if anomaly_score >= 0.85:
                return "HIGH", f"Unusual traffic behavior flagged as high-deviation zero-day anomaly (score: {anomaly_score:.2f})."
            return "MEDIUM", f"Statistical anomaly detected in packet attributes (score: {anomaly_score:.2f})."
        else:
            return "LOW", "Standard baseline network traffic pattern observed."
