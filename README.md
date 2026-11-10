# AI-Based IoT Cyberattack Detection System (AEGIS-IoT)

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask 3.1+](https://img.shields.io/badge/Flask-3.1-black.svg)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.4%2B-orange.svg)](https://scikit-learn.org/)
[![Bootstrap 5](https://img.shields.io/badge/Bootstrap-5.3-purple.svg)](https://getbootstrap.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An intelligent, enterprise-grade cybersecurity web platform engineered to monitor Internet-of-Things (IoT) network traffic, detect malicious activities using Machine Learning, identify multiple cyberattack vectors, and display real-time security telemetry through a modern Security Operations Center (SOC) dashboard.

---

## 🛡️ Core Highlights

- **Real Machine Learning Pipeline**: Built on Scikit-Learn **Random Forest Classifier** trained on a harmonized dataset modeled after the **CIC-DDoS2019 and BoT-IoT benchmark datasets**.
- **10 Integrated Modules**: Every single navigation link, button, chart, and API endpoint is fully functional with persistent SQLite storage.
- **Sub-Millisecond Inference**: Microsecond latency flow inspection suitable for edge gateways.
- **Zero Fabrication**: All metrics (Accuracy, Precision, Recall, F1-Score, Confusion Matrix) are genuinely calculated on an 80/20 test split.
- **Commercial SOC Design**: Cyberpunk dark navy theme (`#050811`, `#0f172a`) with neon blue, cyan, and green accents inspired by Darktrace and CrowdStrike.
- **Demonstration Mode**: Includes an interactive IoT network traffic simulator with attack injection (DDoS, DoS, Mirai Botnet, Brute Force, Port Scan) clearly separated from real traffic.

---

## 📂 Project Directory Structure

```text
iot-cyberattack-detection/
├── app.py                      # Flask Application Server & RESTful API Endpoints
├── config.py                   # Centralized Configuration & Attack Metadata
├── requirements.txt            # Python Dependencies
├── README.md                   # Complete Documentation & Viva Guide
│
├── backend/                    # Backend Logic & Core Engines
│   ├── __init__.py
│   ├── database.py             # SQLite Database Manager (Alerts, History, Telemetry)
│   ├── ml_engine.py            # Singleton Machine Learning Inference Engine
│   └── simulator.py            # Simulated IoT Network Stream Generator
│
├── model/                      # Serialized ML Artifacts & Training Script
│   ├── train_model.py          # Complete ML Training & Evaluation Pipeline
│   ├── iot_attack_detector.joblib # Serialized Random Forest Model
│   ├── scaler.joblib           # StandardScaler Feature Preprocessor
│   ├── label_encoder.joblib    # LabelEncoder Class Mapper
│   └── model_metadata.json     # Genuine Evaluation Metrics & Confusion Matrix
│
├── dataset/                    # Dataset Generator & Sample CSVs
│   ├── generate_iot_dataset.py # Harmonized IoT Dataset Generator
│   ├── iot_cyberattack_dataset.csv # Full Training Dataset (10,800 rows)
│   └── sample_test_packets.csv # Sample Test CSV for Upload Testing (120 rows)
│
├── templates/                  # Jinja2 HTML Templates (10 Modules)
│   ├── base.html               # Master Layout (Sidebar, Navbar, Cyber Theme)
│   ├── index.html              # Module 1: Home Page & Project Overview
│   ├── dashboard.html          # Module 2: SOC Dashboard (Charts & Live Counters)
│   ├── detection.html          # Module 3: AI Flow Inspector (Single Packet Predictor)
│   ├── monitoring.html         # Module 4: Live IoT Monitoring & Stream Inspector
│   ├── upload.html             # Module 5: Dataset Upload & Batch CSV Analyzer
│   ├── alerts.html             # Module 6: Security Alerts Ledger & Triage
│   ├── history.html            # Module 7: Forensic Attack History Logs
│   ├── performance.html        # Module 8: ML Performance (Confusion Matrix, Metrics)
│   ├── reports.html            # Module 9: Executive Reports & Printable Audit
│   └── about.html              # Module 10: Project Documentation & Viva Guide
│
└── static/                     # Static Assets
    ├── css/
    │   └── style.css           # Custom Cyberpunk SOC Design System
    └── js/
        ├── main.js             # Sidebar Toggle, Clock, Cyber Toasts
        ├── dashboard.js        # Dashboard Chart.js Integration & Refresh
        ├── detection.js        # Single Flow Predictor & Preset Loader
        ├── monitoring.js       # Live Packet Stream & Modal Forensics
        ├── upload.js           # CSV Upload Preview & Batch Classification
        ├── alerts.js           # Alert Status Triage & Batch Actions
        └── performance.js      # Confusion Matrix Heatmap & Feature Chart
```

---

## 🎯 6 Supported Attack Classes

| Category | Severity | MITRE ATT&CK ID | Key Flow Characteristics |
| :--- | :--- | :--- | :--- |
| **Normal Traffic** | `Safe` | N/A | Balanced forward/backward packets, standard IoT ports (1883 MQTT, 5683 CoAP, 80 HTTP), low packet rate. |
| **DDoS Attack** | `Critical` | T1498 (Network DoS) | Massive packet rate, asymmetric forward bytes, high SYN/UDP flag flood overwhelming gateway port 80/443. |
| **DoS Attack** | `High` | T1499 (Endpoint DoS) | Extended flow duration, persistent connection pool exhaustion (Slowloris), unbalanced packets. |
| **Botnet** | `Critical` | T1584 (Botnet C2) | Periodic C2 beacons, outbound IRC/custom traffic (ports 6667, 2323), compromised smart cameras/thermostats. |
| **Brute Force** | `High` | T1110 (Brute Force) | Repeated automated authentication attempts on SSH (22) or Telnet (23), frequent RST flags. |
| **Port Scanning** | `Medium` | T1046 (Network Discovery) | Rapid reconnaissance sweep across port ranges (1-1024), 1-2 packets per flow, high SYN flags. |

---

## 🚀 Step-by-Step Installation & Running Guide

### 1. Prerequisites
- Python 3.10, 3.11, 3.12, 3.13, or 3.14 installed on your system.
- VS Code (or any preferred code editor).

### 2. Open Project in VS Code
Open VS Code and choose **File > Open Folder...**, then select:
```text
C:\AI BASED IOT CYBERATTACK DETECTION
```

### 3. Install Dependencies
Open the built-in terminal (`Ctrl + ~`) in VS Code and run:
```bash
pip install -r requirements.txt
```

### 4. (Optional) Regenerate Dataset & Train Model
The dataset and trained model are already pre-generated and ready out-of-the-box! If you ever wish to regenerate the dataset and retrain from scratch:
```bash
python dataset/generate_iot_dataset.py
python model/train_model.py
```

### 5. Launch the Application
Run the Flask server:
```bash
python app.py
```

Open your browser and navigate to:
```text
http://127.0.0.1:5000
```

---

## 🧪 Testing Every Module

1. **Home Page (`/`)**:
   - Check the hero banner, real-time live counters, objectives, and feature matrix.
2. **SOC Dashboard (`/dashboard`)**:
   - View live KPI cards, traffic trend graph, attack distribution chart, and recent alerts. Click **Refresh Data** or **Resolve** on an alert.
3. **AI Flow Inspector (`/detection`)**:
   - Click any preset button (`DDoS Flood`, `Mirai Botnet`, `SSH Brute Force`, etc.) to auto-populate features.
   - Click **Execute AI Detection** to inspect the flow and observe genuine confidence, Mitre ID, and multi-class probability distributions.
4. **Live Network Monitoring (`/monitoring`)**:
   - Observe live incoming packets streaming into the table and rolling activity graph.
   - Change the **Scenario Injection** dropdown (e.g. inject *Volumetric DDoS* or *Mirai Botnet*).
   - Click the eye icon on any row to open the **Forensic Inspector Modal**.
5. **Dataset Upload (`/upload`)**:
   - Click **Download Sample Test CSV** to save a sample dataset.
   - Drag & drop or upload the CSV to preview rows and validate schema.
   - Click **Run AI Model Prediction** to run batch inference and download the classified CSV report.
6. **Security Alerts (`/alerts`)**:
   - Filter alerts by Severity, Status, or Attack type.
   - Click **Ack** or **Resolve** on individual alerts, or use **Acknowledge All** / **Resolve All**.
7. **Attack History (`/history`)**:
   - Search by IP or keyword, filter by attack type, paginate through records, and click **Export Audit CSV**.
8. **ML Model Performance (`/performance`)**:
   - Inspect true Accuracy, Precision, Recall, and F1-Scores.
   - Review the Confusion Matrix heatmap and Top Feature Importances bar chart.
   - Click **Retrain Model** to trigger real-time retraining!
9. **Threat Reports (`/reports`)**:
   - Review executive and technical summaries. Click **Print / Save PDF** for a printable college report.
10. **About Project (`/about`)**:
    - Study the system architecture, Machine Learning justification, and read the **College Viva Q&A Guide**.

---

## 🎓 College Viva Q&A Quick Reference

- **Q: Why Random Forest over Deep Learning for IoT?**
  - *A: Inference latency is under 1 millisecond per packet flow, non-linear decision thresholds handle network flags accurately, and the model provides transparent Gini feature importances.*
- **Q: How are predictions calculated?**
  - *A: Raw flow inputs are preprocessed through a persisted `StandardScaler`, passed to the `RandomForestClassifier`, and confidence is derived from `predict_proba()` across 100 decision trees.*
- **Q: What is the database used?**
  - *A: An embedded SQLite 3 database (`iot_cybersecurity.db`) persisting alerts, detection history, and system settings.*

---

## 📜 License
Developed for Academic Research & College Capstone Demonstration. MIT License.
