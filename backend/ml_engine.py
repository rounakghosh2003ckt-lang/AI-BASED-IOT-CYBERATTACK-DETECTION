import os
import json
from datetime import datetime
import numpy as np
import pandas as pd
import joblib

from config import Config

class IoTModelEngine:
    _instance = None

    def __init__(self):
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.metadata = None
        self.load_artifacts()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = IoTModelEngine()
        return cls._instance

    def load_artifacts(self):
        if os.path.exists(Config.MODEL_FILE):
            self.model = joblib.load(Config.MODEL_FILE)
            self.scaler = joblib.load(Config.SCALER_FILE)
            self.label_encoder = joblib.load(Config.ENCODER_FILE)
        else:
            print("[!] Model files not found. Triggering training...")
            from model.train_model import train_and_evaluate
            train_and_evaluate()
            self.model = joblib.load(Config.MODEL_FILE)
            self.scaler = joblib.load(Config.SCALER_FILE)
            self.label_encoder = joblib.load(Config.ENCODER_FILE)

        if os.path.exists(Config.METADATA_FILE):
            with open(Config.METADATA_FILE, "r") as f:
                self.metadata = json.load(f)
        else:
            self.metadata = {}

        print(f"[+] IoT ML Engine loaded successfully. Classes: {list(self.label_encoder.classes_)}")

    def get_metadata(self):
        if not self.metadata and os.path.exists(Config.METADATA_FILE):
            with open(Config.METADATA_FILE, "r") as f:
                self.metadata = json.load(f)
        return self.metadata

    def predict_single(self, feature_dict, src_ip=None, dst_ip=None):
        feature_cols = self.metadata.get("feature_columns", [
            "flow_duration", "protocol", "src_port", "dst_port",
            "total_fwd_packets", "total_bwd_packets", "total_fwd_bytes",
            "total_bwd_bytes", "packet_length_mean", "packet_length_std",
            "packet_length_max", "flow_bytes_per_sec", "flow_packets_per_sec",
            "syn_flag_count", "ack_flag_count", "fin_flag_count",
            "rst_flag_count", "header_length"
        ])

        # Prepare 1-row DataFrame with defaults for any missing features
        row = {}
        for col in feature_cols:
            val = feature_dict.get(col, None)
            if val is None or val == "":
                row[col] = 0.0
            else:
                try:
                    row[col] = float(val)
                except ValueError:
                    row[col] = 0.0

        input_df = pd.DataFrame([row], columns=feature_cols)

        # Scale features
        scaled_features = self.scaler.transform(input_df)

        # Predict
        pred_idx = self.model.predict(scaled_features)[0]
        pred_class = self.label_encoder.inverse_transform([pred_idx])[0]
        probabilities = self.model.predict_proba(scaled_features)[0]

        confidence = round(float(np.max(probabilities)) * 100, 2)

        # Build class-probability distribution
        prob_dist = {}
        for cls_name, prob in zip(self.label_encoder.classes_, probabilities):
            prob_dist[cls_name] = round(float(prob) * 100, 2)

        meta = Config.ATTACK_METADATA.get(pred_class, {
            "severity": "Medium",
            "badge": "warning",
            "color": "#f59e0b",
            "mitre_id": "Unknown",
            "description": "Suspicious network pattern",
            "recommendation": "Inspect flow details"
        })

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        result = {
            "attack_type": pred_class,
            "confidence": confidence,
            "severity": meta["severity"],
            "badge": meta["badge"],
            "color": meta["color"],
            "mitre_id": meta["mitre_id"],
            "description": meta["description"],
            "recommendation": meta["recommendation"],
            "source_ip": src_ip or feature_dict.get("src_ip", "192.168.1.100"),
            "destination_ip": dst_ip or feature_dict.get("dst_ip", "10.0.0.1"),
            "detection_time": now_str,
            "probabilities": prob_dist,
            "input_features": row
        }

        return result

    def predict_dataframe(self, df):
        feature_cols = self.metadata.get("feature_columns", [
            "flow_duration", "protocol", "src_port", "dst_port",
            "total_fwd_packets", "total_bwd_packets", "total_fwd_bytes",
            "total_bwd_bytes", "packet_length_mean", "packet_length_std",
            "packet_length_max", "flow_bytes_per_sec", "flow_packets_per_sec",
            "syn_flag_count", "ack_flag_count", "fin_flag_count",
            "rst_flag_count", "header_length"
        ])

        # Validate matching columns
        df_clean = df.copy()
        for col in feature_cols:
            if col not in df_clean.columns:
                df_clean[col] = 0.0
            else:
                df_clean[col] = pd.to_numeric(df_clean[col], errors="coerce").fillna(0.0)

        X = df_clean[feature_cols]
        X_scaled = self.scaler.transform(X)

        preds = self.model.predict(X_scaled)
        probs = self.model.predict_proba(X_scaled)

        pred_labels = self.label_encoder.inverse_transform(preds)
        max_probs = np.max(probs, axis=1) * 100

        result_df = df.copy()
        result_df["predicted_attack"] = pred_labels
        result_df["confidence_score"] = np.round(max_probs, 2)
        result_df["severity"] = [
            Config.ATTACK_METADATA.get(label, {}).get("severity", "Medium") for label in pred_labels
        ]

        return result_df

    def retrain_model(self):
        from model.train_model import train_and_evaluate
        meta = train_and_evaluate(save_artifacts=True)
        self.load_artifacts()
        return meta
