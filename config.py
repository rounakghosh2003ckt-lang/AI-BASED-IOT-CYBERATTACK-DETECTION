import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "iot-cyberattack-detection-secret-key-2026")
    DATABASE_PATH = os.path.join(BASE_DIR, "backend", "iot_cybersecurity.db")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32 MB max
    
    MODEL_DIR = os.path.join(BASE_DIR, "model")
    MODEL_FILE = os.path.join(MODEL_DIR, "iot_attack_detector.joblib")
    SCALER_FILE = os.path.join(MODEL_DIR, "scaler.joblib")
    ENCODER_FILE = os.path.join(MODEL_DIR, "label_encoder.joblib")
    METADATA_FILE = os.path.join(MODEL_DIR, "model_metadata.json")
    
    DATASET_DIR = os.path.join(BASE_DIR, "dataset")
    DATASET_PATH = os.path.join(DATASET_DIR, "iot_cyberattack_dataset.csv")
    SAMPLE_TEST_CSV = os.path.join(DATASET_DIR, "sample_test_packets.csv")

    ATTACK_METADATA = {
        "DDoS Attack": {
            "severity": "Critical",
            "badge": "danger",
            "color": "#ef4444",
            "mitre_id": "T1498 (Network Denial of Service)",
            "description": "Massive volumetric flood exhausting IoT gateway and edge server bandwidth.",
            "recommendation": "Activate upstream edge rate-limiting, drop non-whitelisted UDP traffic, enable GeoIP blocking."
        },
        "DoS Attack": {
            "severity": "High",
            "badge": "warning",
            "color": "#f59e0b",
            "mitre_id": "T1499 (Endpoint Denial of Service)",
            "description": "Targeted resource depletion (SYN flood or Slowloris) exhausting device connection pools.",
            "recommendation": "Reduce TCP connection timeout, enable SYN cookies (syncookies=1), isolate affected IP."
        },
        "Botnet": {
            "severity": "Critical",
            "badge": "danger",
            "color": "#dc2626",
            "mitre_id": "T1584 (Compromise Infrastructure: Botnet)",
            "description": "Compromised IoT device communicating with Command & Control (C2) or propagating worms (Mirai/Gafgyt).",
            "recommendation": "Quarantine device immediately, block outbound C2 ports (6667, 2323), re-flash firmware, revoke API keys."
        },
        "Brute Force": {
            "severity": "High",
            "badge": "warning",
            "color": "#f97316",
            "mitre_id": "T1110 (Brute Force Credentials)",
            "description": "Repeated automated authentication attempts on management ports (SSH 22, Telnet 23).",
            "recommendation": "Enforce fail2ban / rate-limiting, disable default credentials, mandate public-key authentication."
        },
        "Port Scanning": {
            "severity": "Medium",
            "badge": "info",
            "color": "#06b6d4",
            "mitre_id": "T1046 (Network Service Discovery)",
            "description": "Reconnaissance scan probing open ports and services across IoT device nodes.",
            "recommendation": "Block source IP at gateway firewall, disable unused IoT services, enable port-knocking or stealth mode."
        },
        "Normal Traffic": {
            "severity": "Safe",
            "badge": "success",
            "color": "#10b981",
            "mitre_id": "N/A (Legitimate Telemetry)",
            "description": "Legitimate sensor readings, MQTT/CoAP telemetry, and authorized IoT communication.",
            "recommendation": "No action needed. Traffic passes normal heuristic and ML inspection."
        }
    }
