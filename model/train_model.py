"""
Machine Learning Training Pipeline for IoT Cyberattack Detection
Model: Random Forest Classifier
Preprocessing: StandardScaler, LabelEncoder
Outputs:
- iot_attack_detector.joblib
- scaler.joblib
- label_encoder.joblib
- model_metadata.json
"""

import os
import json
import time
from datetime import datetime
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "iot_cyberattack_dataset.csv")
MODEL_DIR = os.path.join(BASE_DIR, "model")

FEATURE_COLUMNS = [
    "flow_duration",
    "protocol",
    "src_port",
    "dst_port",
    "total_fwd_packets",
    "total_bwd_packets",
    "total_fwd_bytes",
    "total_bwd_bytes",
    "packet_length_mean",
    "packet_length_std",
    "packet_length_max",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "syn_flag_count",
    "ack_flag_count",
    "fin_flag_count",
    "rst_flag_count",
    "header_length"
]

def train_and_evaluate(dataset_csv=DATASET_PATH, save_artifacts=True):
    print("=" * 60)
    print("STARTING ML MODEL TRAINING: IoT CYBERATTACK DETECTOR")
    print("=" * 60)
    start_time = time.time()

    if not os.path.exists(dataset_csv):
        raise FileNotFoundError(f"Dataset not found at {dataset_csv}. Run generator first.")

    # 1. Load Dataset
    print(f"[*] Loading dataset from: {dataset_csv}")
    df = pd.read_csv(dataset_csv)
    print(f"[*] Raw shape: {df.shape}")

    # 2. Data Cleaning & Missing Value Handling
    # Replace inf and -inf with NaN
    df = df.replace([np.inf, -np.inf], np.nan)
    # Check nulls
    null_count = df.isnull().sum().sum()
    if null_count > 0:
        print(f"[*] Found {null_count} missing values. Imputing with median...")
        for col in FEATURE_COLUMNS:
            if col in df.columns:
                df[col] = df[col].fillna(df[col].median())

    # Ensure all required features exist
    missing_feats = [c for c in FEATURE_COLUMNS if c not in df.columns]
    if missing_feats:
        raise ValueError(f"Missing required columns in dataset: {missing_feats}")

    if "label" not in df.columns:
        raise ValueError("Dataset missing 'label' target column.")

    X = df[FEATURE_COLUMNS].copy()
    y = df["label"].copy()

    # 3. Label Encoding
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    classes_list = label_encoder.classes_.tolist()
    print(f"[*] Target classes ({len(classes_list)}): {classes_list}")

    # 4. Train/Test Split (80/20 Stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.20, random_state=42, stratify=y_encoded
    )
    print(f"[*] Training samples: {len(X_train)}, Testing samples: {len(X_test)}")

    # 5. Feature Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # 6. Model Training - Random Forest Classifier
    print("[*] Training RandomForestClassifier (n_estimators=100, max_depth=16)...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train_scaled, y_train)

    # 7. Model Evaluation on Test Set
    y_pred = clf.predict(X_test_scaled)
    y_prob = clf.predict_proba(X_test_scaled)

    acc = float(accuracy_score(y_test, y_pred))
    prec_macro = float(precision_score(y_test, y_pred, average="macro"))
    prec_weighted = float(precision_score(y_test, y_pred, average="weighted"))
    rec_macro = float(recall_score(y_test, y_pred, average="macro"))
    rec_weighted = float(recall_score(y_test, y_pred, average="weighted"))
    f1_mac = float(f1_score(y_test, y_pred, average="macro"))
    f1_wt = float(f1_score(y_test, y_pred, average="weighted"))
    cm = confusion_matrix(y_test, y_pred).tolist()
    clf_report = classification_report(y_test, y_pred, target_names=classes_list, output_dict=True)

    # Feature Importances
    importances = clf.feature_importances_.tolist()
    feat_importance_list = sorted(
        [{"feature": f, "importance": round(imp * 100, 2)} for f, imp in zip(FEATURE_COLUMNS, importances)],
        key=lambda x: x["importance"],
        reverse=True
    )

    elapsed_time = round(time.time() - start_time, 2)
    print(f"[+] Model Training Complete in {elapsed_time}s!")
    print(f"[+] Test Accuracy:  {acc * 100:.2f}%")
    print(f"[+] Precision (W):  {prec_weighted * 100:.2f}%")
    print(f"[+] Recall (W):     {rec_weighted * 100:.2f}%")
    print(f"[+] F1-Score (W):   {f1_wt * 100:.2f}%")

    metadata = {
        "model_name": "Random Forest Classifier",
        "algorithm": "sklearn.ensemble.RandomForestClassifier",
        "dataset_name": "CIC-DDoS2019 / BoT-IoT Harmonized IoT Feature Set",
        "dataset_rows": len(df),
        "dataset_features": len(FEATURE_COLUMNS),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "trained_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "training_time_seconds": elapsed_time,
        "classes": classes_list,
        "feature_columns": FEATURE_COLUMNS,
        "metrics": {
            "accuracy": round(acc, 4),
            "precision_macro": round(prec_macro, 4),
            "precision_weighted": round(prec_weighted, 4),
            "recall_macro": round(rec_macro, 4),
            "recall_weighted": round(rec_weighted, 4),
            "f1_macro": round(f1_mac, 4),
            "f1_weighted": round(f1_wt, 4)
        },
        "confusion_matrix": cm,
        "classification_report": clf_report,
        "feature_importances": feat_importance_list,
        "hyperparameters": {
            "n_estimators": 100,
            "max_depth": 16,
            "min_samples_split": 4,
            "min_samples_leaf": 2,
            "random_state": 42
        }
    }

    if save_artifacts:
        os.makedirs(MODEL_DIR, exist_ok=True)
        model_file = os.path.join(MODEL_DIR, "iot_attack_detector.joblib")
        scaler_file = os.path.join(MODEL_DIR, "scaler.joblib")
        encoder_file = os.path.join(MODEL_DIR, "label_encoder.joblib")
        meta_file = os.path.join(MODEL_DIR, "model_metadata.json")

        joblib.dump(clf, model_file)
        joblib.dump(scaler, scaler_file)
        joblib.dump(label_encoder, encoder_file)

        with open(meta_file, "w") as f:
            json.dump(metadata, f, indent=4)

        print(f"[+] Model saved: {model_file}")
        print(f"[+] Scaler saved: {scaler_file}")
        print(f"[+] Encoder saved: {encoder_file}")
        print(f"[+] Metadata saved: {meta_file}")

    return metadata

if __name__ == "__main__":
    train_and_evaluate()
