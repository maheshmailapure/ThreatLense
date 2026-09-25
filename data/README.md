# NSL-KDD Dataset Reference & Specifications

## Overview
The NSL-KDD dataset is an industry and academic benchmark dataset for network intrusion detection systems, designed to address inherent redundancies and statistical biases present in the original KDD'99 dataset.

## Dataset Structure
Each connection record is characterized by **41 quantitative and qualitative features**, plus a target attack label and difficulty rating.

### Categorical Attributes (3 Features)
- `protocol_type`: Network protocol utilized (`tcp`, `udp`, `icmp`).
- `service`: Network service requested (`http`, `smtp`, `ftp`, `telnet`, `domain_u`, etc.).
- `flag`: Normal or error status of the connection (`SF`, `S0`, `REJ`, `RSTO`, `RSTR`, etc.).

### Numerical Traffic & Host Features (38 Features)
- **Basic features**: `duration`, `src_bytes`, `dst_bytes`, `land`, `wrong_fragment`, `urgent`.
- **Content features**: `hot`, `num_failed_logins`, `logged_in`, `num_compromised`, `root_shell`, `su_attempted`, `num_root`, `num_file_creations`, `num_shells`, `num_access_files`, `num_outbound_cmds`, `is_host_login`, `is_guest_login`.
- **Time-based traffic features**: `count`, `srv_count`, `serror_rate`, `srv_serror_rate`, `rerror_rate`, `srv_rerror_rate`, `same_srv_rate`, `diff_srv_rate`, `srv_diff_host_rate`.
- **Host-based traffic features**: `dst_host_count`, `dst_host_srv_count`, `dst_host_same_srv_rate`, `dst_host_diff_srv_rate`, `dst_host_same_src_port_rate`, `dst_host_srv_diff_host_rate`, `dst_host_serror_rate`, `dst_host_srv_serror_rate`, `dst_host_rerror_rate`, `dst_host_srv_rerror_rate`.

### Target Attack Classes
1. **Normal**: Standard legitimate network traffic.
2. **DoS (Denial of Service)**: Flooding attacks designed to deny access to authorized users (e.g., `neptune`, `smurf`, `back`, `teardrop`, `pod`, `land`).
3. **Probe**: Surveillance and port-scanning attacks to discover network vulnerabilities (e.g., `satan`, `ipsweep`, `nmap`, `portsweep`).
4. **R2L (Remote to Local)**: Unauthorized access from a remote machine (e.g., `guess_passwd`, `warezclient`, `ftp_write`, `imap`, `phf`).
5. **U2R (User to Root)**: Privilege escalation attacks attempting to gain root privileges from a regular account (e.g., `buffer_overflow`, `rootkit`, `loadmodule`, `perl`).

## Synthetic Data
The dataset located at `data/sample.csv` is synthetically produced with realistic feature distributions strictly for offline testing, local validation, and academic demonstration.
