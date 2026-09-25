# 🛡️ ThreatLense - Autonomous AI Intrusion Detection & Defense System

> **Enterprise-Grade Network Intrusion Detection & Autonomous Threat Defense Powered by Atria-Dawn-Preview AI Engine**

<p align="center">
  <a href="https://github.com/maheshmailapure/ThreatLense/releases/download/v1.0.0/ThreatLense-Setup.exe">
    <img src="https://img.shields.io/badge/DOWNLOAD-ThreatLense_Setup.exe_(Windows_Installer)-00E5FF?style=for-the-badge&logo=windows&logoColor=black" alt="Download Windows Installer" />
  </a>
  <a href="https://github.com/maheshmailapure/ThreatLense/releases/download/v1.0.0/ThreatLense-Windows.zip">
    <img src="https://img.shields.io/badge/PORTABLE_ZIP-ThreatLense--Windows.zip-7C3AED?style=for-the-badge&logo=archive&logoColor=white" alt="Portable Zip Release" />
  </a>
  <a href="https://github.com/maheshmailapure/ThreatLense/releases">
    <img src="https://img.shields.io/badge/RELEASES-All_Versions-10B981?style=for-the-badge&logo=github&logoColor=white" alt="All Releases" />
  </a>
</p>

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20(64--bit)-lightgrey.svg)]()
[![Atria AI](https://img.shields.io/badge/AI%20Core-Atria--Dawn--Preview%20MoE-purple.svg)]()
[![Build](https://img.shields.io/badge/Installer-Standalone%20Setup%20EXE-green.svg)]()

---

## 📥 Direct Download & Windows Installation

ThreatLense provides a dedicated single-file Windows installer (**`ThreatLense-Setup.exe`**). Anyone can download and install it on any Windows 10 or Windows 11 PC without needing Python, Node.js, npm, or any external database.

| Package | Supported Platform | Format | Size | Direct Download Link |
| :--- | :--- | :--- | :--- | :--- |
| 🛡️ **ThreatLense Official Setup** | Windows 10 / 11 (64-bit) | Standalone `.exe` Installer with EULA & Desktop Setup | ~109.8 MB | [⬇️ **Download ThreatLense-Setup.exe**](https://github.com/maheshmailapure/ThreatLense/releases/download/v1.0.0/ThreatLense-Setup.exe) |
| 📦 **ThreatLense Portable Zip** | Windows 10 / 11 (64-bit) | Portable Zero-Install `.zip` Archive | ~95 MB | [⬇️ **Download ThreatLense-Windows.zip**](https://github.com/maheshmailapure/ThreatLense/releases/download/v1.0.0/ThreatLense-Windows.zip) |
| 🌐 **All Versions & Release Assets**| Any Supported | GitHub Releases Portal | - | [📦 **GitHub Releases Portal**](https://github.com/maheshmailapure/ThreatLense/releases) |

### ⚡ 3-Step Instant Windows Installation
1. **Download**: Click [⬇️ **Download ThreatLense-Setup.exe**](https://github.com/maheshmailapure/ThreatLense/releases/download/v1.0.0/ThreatLense-Setup.exe).
2. **Run Setup**: Double-click `ThreatLense-Setup.exe` to open the ThreatLense Setup Wizard.
3. **Accept Terms & Finish**:
   - Review the **End User License Agreement (EULA)** and select *"I accept the agreement"*.
   - Click **Install** to unpack and register the application.
   - Setup automatically generates a **Desktop Shortcut** and **Start Menu entry**.
   - ThreatLense opens immediately as a **Dedicated Native Desktop Security Window** (like McAfee Antivirus / Windows Security) with **zero browser chrome, zero tabs, and no localhost address**.
   - Audio cyber speech initialization greets you: *"Loading ThreatLense System"*.

---

## ⚡ Atria AI Autonomous Threat Engine (Trigger-Based Token Saver)
- **Zero Token Idle Consumption**: During routine operating baseline, Atria AI sleeps at 0 tokens consumed.
- **Trigger-Based Auto-Wake**: Wakes autonomously when an anomalous external ingress (SMB 445, RDP 3389, MSRPC 135, port scan, SYN flood) or high-entropy download is detected.
- **AI-Governed Alarm Policy**: Telemetry is first evaluated by Atria AI. Sirens sound **only** if Atria AI confirms a genuine threat (`is_harmful = True`). Benign anomalies are verified and silenced.
- **Persistent Anti-Repeat Guard**: Pre-existing downloads and historical threats are indexed on boot. Alarms will **never repeatedly fire** for files already sitting on disk.

---

## 4. Objectives
- Ingest and preprocess standard NSL-KDD network intrusion benchmark data (`KDDTrain+.txt`, `KDDTest+.txt`, and CSV formats).
- Implement robust categorical one-hot encoding and numerical feature standardization with zero data leakage.
- Apply ANOVA F-value feature selection (`SelectKBest`) and Principal Component Analysis (`PCA`) for dimensionality reduction.
- Train, benchmark, and evaluate multiple ML algorithms:
  - **Random Forest** (Supervised Multi-Class & Binary Classifier)
  - **Support Vector Machine - SVM** (Supervised Margin Classifier)
  - **K-Means Clustering** (Unsupervised Centroid Distance Anomaly Detection)
  - **Isolation Forest** (Unsupervised Outlier Isolation)
- Deliver true, non-fabricated academic evaluation metrics: **Accuracy, Precision, Recall, F1 Score, False Positive Rate (FPR)**, and interactive **Confusion Matrices**.
- Provide a responsive, dark SOC cybersecurity dashboard with live threat streams, SIEM alert triage, explainable detection breakdowns, and CSV export capabilities.

---

## 5. Key Features
- **NSL-KDD Adapter & Dataset Management**: Auto-detects 41-feature NSL-KDD formats and custom flow CSVs; handles missing/inf/duplicate values; provides sample previews and column statistical distribution analytics.
- **Leakage-Free ML Training Pipeline**: Preprocessing transformers, SelectKBest feature selectors, and PCA are strictly fitted on training partitions only (70:30 stratified split).
- **Dual-Paradigm Detection Engine**: Combines supervised attack classification with unsupervised continuous anomaly scoring ($[0.0, 1.0]$).
- **Explainable Threat Reasoning ("Detection Explanation")**: Shows contributing flow attributes, model confidence, and centroid distance deviation.
- **Configurable Multi-Tier Risk Engine**: Classifies flows into `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` based on attack severity and anomaly thresholds.
- **SIEM Security Incident Queue**: Full alert lifecycle triage (`NEW` $\to$ `INVESTIGATING` $\to$ `RESOLVED` / `FALSE_POSITIVE`).
- **Simulated Real-Time Packet Stream**: Sequential packet-by-packet streaming playback with adjustable inspection speed ($100\text{ms} - 1500\text{ms}$).
- **Interactive Dark SOC Dashboard**: Executive KPI cards, Normal vs Attack Donut, Attack Vector Bar Chart, Activity Timeline, Protocol & Threat Distribution.

---

## 6. System Architecture

```
                                 [ NSL-KDD / CSV Traffic Data ]
                                               │
                                               ▼
                              ┌──────────────────────────────────┐
                              │     Data Ingestion & Adapter     │
                              └──────────────────────────────────┘
                                               │
                                               ▼
                              ┌──────────────────────────────────┐
                              │ Preprocessing, Encoding, Scaling │
                              └──────────────────────────────────┘
                                               │
                                               ▼
                              ┌──────────────────────────────────┐
                              │  Feature Selection (SelectKBest) │
                              └──────────────────────────────────┘
                                               │
                                               ▼
                              ┌──────────────────────────────────┐
                              │    PCA Dimensionality Reduction  │
                              └──────────────────────────────────┘
                                               │
                                               ▼
                              ┌──────────────────────────────────┐
                              │ 70:30 Stratified Train/Test Split│
                              └──────────────────────────────────┘
                                 │              │              │
                    ┌────────────┘              │              └────────────┐
                    ▼                           ▼                           ▼
          ┌───────────────────┐       ┌───────────────────┐       ┌───────────────────┐
          │   Random Forest   │       │        SVM        │       │  K-Means Anomaly  │
          │   (Supervised)    │       │   (Supervised)    │       │  (Unsupervised)   │
          └───────────────────┘       └───────────────────┘       └───────────────────┘
                    │                           │                           │
                    └────────────┬──────────────┴──────────────┬────────────┘
                                 ▼                             ▼
                    ┌─────────────────────────┐   ┌─────────────────────────┐
                    │ Multi-Class Attack Map  │   │ Anomaly & Risk Engine   │
                    │(Normal, DoS, Probe, ...)│   │(LOW, MED, HIGH, CRITICAL│
                    └─────────────────────────┘   └─────────────────────────┘
                                 │                             │
                                 └──────────────┬──────────────┘
                                                ▼
                                  ┌───────────────────────────┐
                                  │   SIEM Alerts & DB Store  │
                                  │       (SQLite ORM)        │
                                  └───────────────────────────┘
                                                │
                                                ▼
                                  ┌───────────────────────────┐
                                  │ React SOC Dashboard & UI  │
                                  └───────────────────────────┘
```

---

## 7. Technology Stack

### Backend
- **Framework**: Python 3.10+ / FastAPI / Uvicorn
- **ORM & Database**: SQLAlchemy 2.0 / SQLite (`ids.db`)
- **Validation**: Pydantic v2
- **Security & Auth**: JWT (PyJWT/python-jose), native `bcrypt` password hashing

### Machine Learning & Data Processing
- **Scikit-Learn**: `RandomForestClassifier`, `SVC`, `KMeans`, `IsolationForest`, `SelectKBest`, `PCA`, `ColumnTransformer`, `StandardScaler`, `OneHotEncoder`
- **Scientific Computing**: NumPy, Pandas
- **Persistence**: Joblib, JSON metadata

### Frontend
- **Core**: React 18, Vite 5, JavaScript (ESM)
- **Styling**: Tailwind CSS (Dark SOC Theme), Custom Neon Cyber Glows
- **Icons**: Lucide React
- **Data Visualizations**: Recharts (Pie/Donut, Bar, Area, Timeline)
- **HTTP Client**: Axios with JWT request/response interceptors
- **Routing**: React Router v6 with Protected Layout wrappers

---

## 8. Project Structure

```
threatlense/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI entrypoint, middleware, routes
│   │   ├── api/
│   │   │   ├── auth.py                 # JWT login, me, user management
│   │   │   ├── datasets.py             # Dataset upload, preview, stats, delete
│   │   │   ├── models.py               # ML training orchestrator & model metadata
│   │   │   ├── detection.py            # Batch detection, results query, CSV export
│   │   │   ├── alerts.py               # SIEM alerts, status update, severity filtering
│   │   │   ├── dashboard.py            # Aggregated SOC stats & chart data
│   │   │   ├── evaluation.py           # Model comparisons & confusion matrices
│   │   │   └── simulation.py           # Real-time traffic stream simulation
│   │   ├── database/
│   │   │   ├── database.py             # SQLite engine & sessionmaker
│   │   │   └── models.py               # User, Dataset, MLModel, Detection, Alert
│   │   ├── schemas/                    # Pydantic validation schemas
│   │   ├── ml/
│   │   │   ├── preprocessing.py        # NSL-KDD adapter, encoding, scaling, save/load
│   │   │   ├── feature_selection.py    # SelectKBest (ANOVA f_classif)
│   │   │   ├── pca.py                  # PCA dimensionality reduction
│   │   │   ├── random_forest.py        # Supervised RF, feature importances
│   │   │   ├── svm.py                  # Supervised SVM (RBF/Linear)
│   │   │   ├── kmeans.py               # Unsupervised K-Means clustering & anomaly scoring
│   │   │   ├── isolation_forest.py     # Unsupervised Isolation Forest anomaly detector
│   │   │   ├── training.py             # End-to-end training pipeline orchestrator
│   │   │   ├── prediction.py           # Real-time inference & anomaly scoring engine
│   │   │   └── evaluation.py           # Accuracy, Precision, Recall, F1, FPR, Confusion Matrix
│   │   ├── services/                   # Business logic service layer
│   │   └── utils/                      # Security, logging, and attack/risk helpers
│   ├── models/                         # Serialized joblib artifacts & metadata.json
│   ├── uploads/                        # Uploaded datasets directory
│   ├── logs/                           # System activity logs
│   ├── tests/                          # Pytest automated test suite
│   ├── requirements.txt                # Python dependencies
│   ├── .env.example                    # Environment template
│   └── seed.py                         # Database initialization & seed script
│
├── frontend/
│   ├── src/
│   │   ├── components/                 # Sidebar, Navbar, StatCard, AlertTable, TrafficChart, etc.
│   │   ├── pages/                      # Login, Dashboard, Datasets, Detection, Results, Alerts, etc.
│   │   ├── services/api.js             # Axios client with JWT interceptor
│   │   ├── context/AuthContext.jsx     # Global authentication provider
│   │   ├── App.jsx, main.jsx, index.css# Tailwind dark SOC theme & routing
│   ├── package.json, vite.config.js, tailwind.config.js
│
├── data/
│   ├── sample.csv                      # Synthetic NSL-KDD dataset for instant testing
│   └── README.md                       # Dataset specifications & feature glossary
│
├── notebooks/
│   └── model_experiment.ipynb          # Jupyter notebook for academic demonstration & viva
│
├── scripts/
│   └── generate_sample_data.py         # Realistic synthetic NSL-KDD data generator
│
├── docker-compose.yml                  # Docker deployment configuration
└── README.md                           # Comprehensive documentation
```

---

## 9. Installation & Quickstart

### Prerequisites
- Python 3.10, 3.11, 3.12, 3.13, or 3.14
- Node.js 18+ and npm
- Git

---

## 10. Backend Setup

1. Open a terminal in the `backend/` directory:
   ```bash
   cd backend
   ```
2. Create and activate a Python virtual environment:
   ```bash
   # Windows PowerShell
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install backend dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Initialize database, seed accounts, and pre-train models:
   ```bash
   python seed.py
   ```
   *Default Admin User:* `admin` / `Admin@1234`
   *Default Analyst User:* `analyst` / `Analyst@1234`

5. Start the FastAPI backend server:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
   API interactive Swagger documentation available at: `http://localhost:8000/docs`

---

## 11. Frontend Setup

1. Open a second terminal in the `frontend/` directory:
   ```bash
   cd frontend
   ```
2. Install npm dependencies:
   ```bash
   npm install
   ```
3. Launch the Vite development server:
   ```bash
   npm run dev
   ```
4. Access the web application in your browser at:
   `http://localhost:5173`

---

## 12. Database Setup & Supabase Integration
The application supports dual database environments:

### Option A: Local SQLite (Default for offline MVP / Viva demo)
Configured out-of-the-box (`backend/ids.db`). No external database servers or internet connection required.

### Option B: Cloud Supabase PostgreSQL
Connected Supabase Project:
- **Project Name:** `ai based intrusion detection system`
- **Project Reference ID:** `lofljkxtgdhvdfijstfs`
- **Project URL:** `https://lofljkxtgdhvdfijstfs.supabase.co`
- **Host:** `db.lofljkxtgdhvdfijstfs.supabase.co` (PostgreSQL 17)

To connect the backend to Supabase PostgreSQL, set `DATABASE_URL` in `backend/.env`:
```env
DATABASE_URL=postgresql://postgres:[YOUR-PASSWORD]@db.lofljkxtgdhvdfijstfs.supabase.co:5432/postgres
```

### Key Database Tables Created in Supabase & SQLite:
- **`users`**: User account credentials, hashed passwords, and RBAC roles (`admin`, `analyst`).
- **`datasets`**: Uploaded file metadata, column counts, missing values, duplicates, and storage paths.
- **`models`**: Trained ML algorithm records, versions, hyperparameters, and evaluated benchmark metrics.
- **`detections`**: Individual network packet scan results, predictions, attack categories, anomaly scores, and feature snapshots.
- **`alerts`**: SIEM security incidents linked to detections, risk severity ratings, and triage status (`NEW`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).

---

## 13. Dataset Setup
The system supports:
1. Standard NSL-KDD benchmark files (`KDDTrain+.txt`, `KDDTest+.txt`).
2. General network flow CSVs with headers.
3. Automated sample dataset generated via `scripts/generate_sample_data.py` located at `data/sample.csv`.

To generate a fresh synthetic test dataset:
```bash
python scripts/generate_sample_data.py
```

---

## 14. Model Training Pipeline
The ML pipeline executes sequentially:
1. **Data Ingestion**: Separates target labels from features.
2. **Stratified Split**: Partitions into 70% Train and 30% Test splits with fixed random seed ($42$).
3. **Preprocessing**: OneHotEncodes categorical attributes (`protocol_type`, `service`, `flag`) and StandardScales numerical features.
4. **Feature Selection**: Selects top $K$ discriminative features via ANOVA $f\_classif$ (SelectKBest).
5. **PCA Dimensionality Reduction**: Reduces selected dimensions to principal components while capturing $>90\%$ variance.
6. **Model Training**:
   - Random Forest: 100 decision trees, Gini impurity, extracts feature importance weights.
   - SVM: RBF Support Vector Classifier with confidence estimation.
   - K-Means: Clusters normal baseline traffic into $K=5$ centroids and computes distance threshold for outlier detection.
   - Isolation Forest: Recursive tree isolation for anomaly scoring.
7. **Model Artifacts Saved**: Serialized to `backend/models/*.joblib` and `backend/models/metadata.json`.

---

## 15. Detection & Risk Engine
During inference on single packets or batch files:
- Raw packet attributes are validated and passed through the saved preprocessing pipeline.
- Model evaluates classification: `NORMAL` vs `ATTACK`.
- Anomaly engine computes normalized distance $[0.0, 1.0]$ to nearest cluster centroid.
- Attack categories mapped: `Normal`, `DoS`, `Probe`, `R2L`, `U2R`.
- Risk engine assigns risk levels:
  - `LOW`: Verified baseline traffic.
  - `MEDIUM`: Statistical anomaly detected.
  - `HIGH`: Confirmed signature attack (Probe, R2L, DoS).
  - `CRITICAL`: High-volume DoS flood or root privilege escalation (U2R).

---

## 16. Simulated Real-Time Detection
- Navigate to `/simulation` in the web application.
- Select an active model (e.g. Random Forest) and a traffic dataset.
- Adjust the stream playback interval ($100\text{ms} - 1500\text{ms}$).
- Click **"Start Live Stream"** to observe real-time packet ingestion, instant verdict classification, anomaly scoring, and automated alert escalation in the live ticker feed.

---

## 17. REST API Documentation

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/auth/login` | Authenticate user and receive JWT bearer token |
| `GET` | `/api/auth/me` | Fetch current user profile |
| `POST` | `/api/datasets/upload` | Upload and index NSL-KDD dataset |
| `GET` | `/api/datasets` | List all uploaded datasets |
| `GET` | `/api/datasets/{id}/preview` | Preview sample records and column stats |
| `DELETE` | `/api/datasets/{id}` | Delete a dataset and its stored file |
| `POST` | `/api/models/train` | Execute ML training pipeline on dataset |
| `GET` | `/api/models` | List all trained models and metrics |
| `POST` | `/api/detection/run` | Run batch packet inspection on dataset |
| `GET` | `/api/detection/results` | Filter, search, and paginate detection logs |
| `GET` | `/api/detection/results/{id}` | Inspect packet attributes and XAI explanation |
| `GET` | `/api/detection/export` | Download detection results as CSV |
| `GET` | `/api/alerts` | Query SIEM security alerts queue |
| `PUT` | `/api/alerts/{id}/status` | Update incident triage status |
| `GET` | `/api/dashboard/stats` | Retrieve aggregated SOC KPI statistics |
| `GET` | `/api/dashboard/charts` | Retrieve chart data points for visualization |
| `GET` | `/api/evaluation/compare` | Retrieve side-by-side model comparisons |
| `POST` | `/api/simulation/start` | Start background simulated packet stream |
| `POST` | `/api/simulation/stop` | Stop ongoing simulated packet stream |
| `GET` | `/api/simulation/status` | Poll simulation counters and latest detections |
| `GET` | `/api/health` | Health check endpoint |

---

## 18. Testing & Validation

### Automated Backend Tests
Run the pytest test suite:
```bash
cd backend
python -m pytest tests/ -v
```
**Test Coverage Includes:**
- Auth login, JWT generation, and protected route access.
- Dataset upload, validation, and sample preview.
- ML training orchestrator, SelectKBest, PCA, and model evaluation metrics.
- Batch detection runs and SIEM alert generation.
- Alert triage status transitions (`NEW` $\to$ `INVESTIGATING` $\to$ `RESOLVED`).
- Dashboard statistics calculation and simulation runner state.

---

## 19. Academic Viva & Defense Questions

**Q1: How does ThreatLense avoid data leakage in the ML pipeline?**
*Answer:* Preprocessing scalers (`StandardScaler`), encoders (`OneHotEncoder`), feature selectors (`SelectKBest`), and dimensionality reducers (`PCA`) are fitted exclusively on the 70% training partition. The 30% test partition and subsequent inference packets are only transformed using the pre-fitted parameters.

**Q2: What is the difference between supervised classification and unsupervised anomaly detection in this system?**
*Answer:* Supervised models (Random Forest, SVM) learn boundaries from labeled training data to classify known attack classes (`DoS`, `Probe`, `R2L`, `U2R`). Unsupervised models (K-Means, Isolation Forest) learn normal cluster geometries without labels and flag outliers based on centroid Euclidean distance to detect potential zero-day threats.

**Q3: How are mathematical evaluation metrics computed?**
*Answer:*
- $\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$
- $\text{Precision} = \frac{TP}{TP + FP}$
- $\text{Recall} = \frac{TP}{TP + FN}$
- $\text{F1 Score} = \frac{2 \times \text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$
- $\text{False Positive Rate (FPR)} = \frac{FP}{FP + TN}$

---

---

## 20. Live Host Tracking, Automatic Alarms, Ollama LLM Gateway & Attack Lab

### A. Live Continuous Host & Network Socket Tracking
- **Hardware & Interface Telemetry**: Live CPU load, RAM usage, throughput in MB/s, packet counters, and network interfaces.
- **Active Socket Sniffing**: Uses `psutil` to inspect actual active network connections, open ports (HTTP, HTTPS, SSH, FTP, RDP, Telnet, SMB), socket states (`ESTABLISHED`, `SYN_SENT`, `CLOSE_WAIT`, `TIME_WAIT`, `LISTEN`), and associated process PIDs.
- **Real-Time ML Ingestion**: Evaluates active network connections through trained Machine Learning models (Random Forest, SVM, K-Means, Isolation Forest) and flags malicious socket activity.

### B. Automatic Audio & Visual Alarm System
- **Synthesized Web Audio Siren**: Generates an audible security siren using native Web Audio API oscillators ($660\text{Hz} - 1320\text{Hz}$ dual-tone sweep). Operates in any browser with zero external audio assets.
- **SOC Emergency Alert Banner**: Displays a pulsing red emergency alert with threat classification, anomaly score, and one-click **"AI Incident Response"** navigation.
- **Audible Siren Controls**: Top navigation bar includes instant Siren Testing and Audio Mute toggles.

### C. Remote Ollama LLM Decision Gateway
- **Configurable Network Host Gateway**: Connects to remote or local Ollama instances (`http://[GATEWAY-IP]:11434`, e.g. running on another server or workstation).
- **Supported Models**: `llama3`, `mistral`, `deepseek-r1`, `qwen2.5-coder`, `llama2`.
- **Autonomous Incident Decisions**:
  - Executive Threat Summary
  - Technical Root Cause & Exploit Breakdown
  - Immediate Priority Defensive Actions
  - Copyable Firewall Mitigation Commands (`iptables`, `UFW`, `netsh`)
  - Long-Term Hardening & Containment Recommendations
- **Heuristic Fallback Engine**: If the remote Ollama server is offline or unreachable, the system automatically activates its built-in cybersecurity expert rule engine.

### D. Web Application & Server Attack Testing Lab
Interactive simulation platform located at `/attack-lab`:
1. **Web Application Attack Vectors**:
   - SQL Injection (SQLi)
   - Cross-Site Scripting (XSS)
   - Path Traversal & Local File Inclusion (LFI)
   - HTTP Slowloris Application Flood
2. **Server & Network Infrastructure Vectors**:
   - TCP SYN Flood DDoS ($100\%$ SYN error rate)
   - Nmap Aggressive Port Sweep Probe
   - SSH / Telnet Remote Brute Force (R2L)
   - Linux/Windows Root Shell Privilege Escalation (U2R)
3. **Custom Payload & Port Exploit Crafter**: Test custom raw payloads against target IP/ports with real-time AI classification and automatic siren alarm triggering.

---

## 21. Limitations & Future Enhancements

### Current System Features
- Supports both local SQLite and Cloud Supabase PostgreSQL with Realtime replication.
- Real-time live host socket scanning and background packet stream simulation.
- Autonomous LLM incident response gateway ready for Ollama (`llama3`, `mistral`, `deepseek-r1`).
- Native synthesized Web Audio siren alarm and interactive attack testing lab.

### Future Expansion
- **Promiscuous NIC Sniffing**: Native Scapy/AF_PACKET packet decoding.
- **Automated SOAR Execution**: Direct shell execution of generated `iptables` / `netsh` firewall rules upon high-confidence alert triggers.
