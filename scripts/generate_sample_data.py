import os
import random
import csv
import numpy as np

# NSL-KDD Standard Columns
COLUMNS = [
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
    "dst_host_srv_rerror_rate", "label", "difficulty_level"
]

PROTOCOLS = ["tcp", "udp", "icmp"]
SERVICES = ["http", "smtp", "ftp", "ftp_data", "finger", "telnet", "eco_i", "ecr_i", "private", "domain_u", "auth", "other"]
FLAGS = ["SF", "S0", "REJ", "RSTO", "RSTR", "SH", "S1", "S2", "RSTOS0", "OTH"]

def generate_record(attack_class="normal"):
    """Generate a single synthetic network flow record matching NSL-KDD distributions."""
    rec = {col: 0 for col in COLUMNS}
    
    if attack_class == "normal":
        rec["duration"] = random.randint(0, 10)
        rec["protocol_type"] = random.choice(["tcp", "tcp", "tcp", "udp", "http"]) if "http" in PROTOCOLS else random.choice(["tcp", "tcp", "udp"])
        rec["service"] = random.choice(["http", "http", "smtp", "ftp_data", "domain_u"])
        rec["flag"] = "SF"
        rec["src_bytes"] = random.randint(150, 2500)
        rec["dst_bytes"] = random.randint(200, 15000)
        rec["logged_in"] = 1 if rec["service"] in ["http", "smtp", "ftp_data"] else 0
        rec["count"] = random.randint(1, 15)
        rec["srv_count"] = random.randint(1, 12)
        rec["serror_rate"] = round(random.uniform(0.0, 0.05), 2)
        rec["srv_serror_rate"] = rec["serror_rate"]
        rec["same_srv_rate"] = round(random.uniform(0.9, 1.0), 2)
        rec["diff_srv_rate"] = round(1.0 - rec["same_srv_rate"], 2)
        rec["dst_host_count"] = random.randint(10, 255)
        rec["dst_host_srv_count"] = random.randint(10, 255)
        rec["dst_host_same_srv_rate"] = round(random.uniform(0.85, 1.0), 2)
        rec["dst_host_diff_srv_rate"] = round(1.0 - rec["dst_host_same_srv_rate"], 2)
        rec["label"] = "normal"
        rec["difficulty_level"] = 21

    elif attack_class == "dos":
        attack_sub = random.choice(["neptune", "smurf", "back", "teardrop"])
        rec["duration"] = 0
        rec["protocol_type"] = "icmp" if attack_sub == "smurf" else "tcp"
        rec["service"] = "ecr_i" if attack_sub == "smurf" else random.choice(["private", "http"])
        rec["flag"] = "SF" if attack_sub == "smurf" else random.choice(["S0", "REJ"])
        rec["src_bytes"] = 1032 if attack_sub == "smurf" else random.randint(0, 50)
        rec["dst_bytes"] = 0
        rec["logged_in"] = 0
        rec["count"] = random.randint(100, 511)
        rec["srv_count"] = random.randint(100, 511)
        rec["serror_rate"] = 0.0 if attack_sub == "smurf" else round(random.uniform(0.8, 1.0), 2)
        rec["srv_serror_rate"] = rec["serror_rate"]
        rec["same_srv_rate"] = round(random.uniform(0.9, 1.0), 2)
        rec["diff_srv_rate"] = round(random.uniform(0.0, 0.1), 2)
        rec["dst_host_count"] = 255
        rec["dst_host_srv_count"] = random.randint(1, 50) if attack_sub != "smurf" else 255
        rec["dst_host_same_srv_rate"] = round(random.uniform(0.01, 0.2), 2) if attack_sub != "smurf" else 1.0
        rec["dst_host_serror_rate"] = rec["serror_rate"]
        rec["label"] = attack_sub
        rec["difficulty_level"] = random.randint(15, 20)

    elif attack_class == "probe":
        attack_sub = random.choice(["satan", "ipsweep", "portsweep", "nmap"])
        rec["duration"] = random.randint(0, 5)
        rec["protocol_type"] = random.choice(["tcp", "icmp"])
        rec["service"] = random.choice(["other", "private", "eco_i"])
        rec["flag"] = random.choice(["SH", "REJ", "RSTO", "SF"])
        rec["src_bytes"] = random.randint(0, 100)
        rec["dst_bytes"] = random.randint(0, 50)
        rec["logged_in"] = 0
        rec["count"] = random.randint(1, 20)
        rec["srv_count"] = 1
        rec["same_srv_rate"] = round(random.uniform(0.05, 0.2), 2)
        rec["diff_srv_rate"] = round(random.uniform(0.6, 1.0), 2)
        rec["dst_host_count"] = random.randint(150, 255)
        rec["dst_host_srv_count"] = random.randint(1, 10)
        rec["dst_host_diff_srv_rate"] = round(random.uniform(0.5, 0.95), 2)
        rec["dst_host_same_src_port_rate"] = round(random.uniform(0.6, 1.0), 2)
        rec["label"] = attack_sub
        rec["difficulty_level"] = random.randint(12, 18)

    elif attack_class == "r2l":
        attack_sub = random.choice(["guess_passwd", "warezclient", "ftp_write"])
        rec["duration"] = random.randint(2, 60)
        rec["protocol_type"] = "tcp"
        rec["service"] = "telnet" if attack_sub == "guess_passwd" else "ftp"
        rec["flag"] = "SF"
        rec["src_bytes"] = random.randint(120, 800)
        rec["dst_bytes"] = random.randint(200, 3000)
        rec["num_failed_logins"] = random.randint(1, 5) if attack_sub == "guess_passwd" else 0
        rec["logged_in"] = 1 if attack_sub != "guess_passwd" else 0
        rec["is_guest_login"] = 1 if attack_sub == "warezclient" else 0
        rec["hot"] = random.randint(1, 4)
        rec["count"] = 1
        rec["srv_count"] = 1
        rec["dst_host_count"] = random.randint(1, 30)
        rec["dst_host_srv_count"] = random.randint(1, 30)
        rec["label"] = attack_sub
        rec["difficulty_level"] = random.randint(8, 14)

    elif attack_class == "u2r":
        attack_sub = random.choice(["buffer_overflow", "rootkit", "loadmodule"])
        rec["duration"] = random.randint(10, 120)
        rec["protocol_type"] = "tcp"
        rec["service"] = "telnet"
        rec["flag"] = "SF"
        rec["src_bytes"] = random.randint(1500, 6000)
        rec["dst_bytes"] = random.randint(2000, 10000)
        rec["logged_in"] = 1
        rec["root_shell"] = 1
        rec["num_root"] = random.randint(1, 5)
        rec["num_file_creations"] = random.randint(1, 3)
        rec["su_attempted"] = 1
        rec["count"] = 1
        rec["srv_count"] = 1
        rec["dst_host_count"] = random.randint(1, 20)
        rec["dst_host_srv_count"] = random.randint(1, 20)
        rec["label"] = attack_sub
        rec["difficulty_level"] = random.randint(5, 12)

    return rec

def generate_dataset(output_path: str, n_samples: int = 2500):
    """Generate synthetic NSL-KDD dataset with realistic class distributions."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # 52% Normal, 30% DoS, 12% Probe, 4% R2L, 2% U2R
    classes = (
        ["normal"] * int(n_samples * 0.52) +
        ["dos"] * int(n_samples * 0.30) +
        ["probe"] * int(n_samples * 0.12) +
        ["r2l"] * int(n_samples * 0.04) +
        ["u2r"] * int(n_samples * 0.02)
    )
    random.shuffle(classes)

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        for c in classes:
            writer.writerow(generate_record(c))

    print(f"Successfully generated synthetic dataset with {len(classes)} records at: {output_path}")

if __name__ == "__main__":
    out_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "sample.csv")
    generate_dataset(out_file, n_samples=3000)
