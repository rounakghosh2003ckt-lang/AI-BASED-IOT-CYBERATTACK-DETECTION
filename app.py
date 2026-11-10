import os
import json
import uuid
from datetime import datetime
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
    Response,
    redirect,
    url_for,
    flash
)
from werkzeug.utils import secure_filename
import pandas as pd

from config import Config
from backend.database import (
    init_db,
    add_detection,
    get_alerts,
    update_alert_status,
    batch_update_alerts,
    get_alert_counts,
    get_detection_history,
    get_dashboard_stats,
    get_traffic_trend,
    get_attack_distribution,
    export_history_as_csv_string
)
from backend.ml_engine import IoTModelEngine
from backend.simulator import get_simulator

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Ensure upload directory exists
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

# Initialize Database and ML Engine
init_db()
ml_engine = IoTModelEngine.get_instance()
simulator = get_simulator()

# -------------------------------------------------------------
# PAGE ROUTES (10 MODULES)
# -------------------------------------------------------------

@app.route("/")
def index():
    """Module 1: HOME PAGE"""
    stats = get_dashboard_stats()
    metadata = ml_engine.get_metadata()
    return render_template("index.html", stats=stats, metadata=metadata)

@app.route("/dashboard")
def dashboard():
    """Module 2: SOC DASHBOARD"""
    stats = get_dashboard_stats()
    alert_counts = get_alert_counts()
    return render_template("dashboard.html", stats=stats, alert_counts=alert_counts)

@app.route("/detection")
def detection():
    """Module 3: AI CYBERATTACK DETECTION"""
    return render_template("detection.html", attacks=Config.ATTACK_METADATA)

@app.route("/monitoring")
def monitoring():
    """Module 4: LIVE NETWORK MONITORING"""
    return render_template("monitoring.html")

@app.route("/upload")
def upload():
    """Module 5: DATASET UPLOAD"""
    return render_template("upload.html")

@app.route("/alerts")
def alerts_page():
    """Module 6: SECURITY ALERTS"""
    alert_counts = get_alert_counts()
    return render_template("alerts.html", counts=alert_counts)

@app.route("/history")
def history_page():
    """Module 7: ATTACK HISTORY"""
    return render_template("history.html")

@app.route("/performance")
def performance_page():
    """Module 8: ML MODEL PERFORMANCE"""
    metadata = ml_engine.get_metadata()
    return render_template("performance.html", meta=metadata)

@app.route("/reports")
def reports_page():
    """Module 9: REPORTS"""
    stats = get_dashboard_stats()
    dist = get_attack_distribution()
    return render_template("reports.html", stats=stats, distribution=dist)

@app.route("/about")
def about_page():
    """Module 10: ABOUT PROJECT"""
    metadata = ml_engine.get_metadata()
    return render_template("about.html", meta=metadata)


# -------------------------------------------------------------
# REST API ENDPOINTS
# -------------------------------------------------------------

# --- DASHBOARD & METRICS APIS ---
@app.route("/api/dashboard/stats", methods=["GET"])
def api_dashboard_stats():
    stats = get_dashboard_stats()
    return jsonify({"success": True, "data": stats})

@app.route("/api/dashboard/traffic-trend", methods=["GET"])
def api_traffic_trend():
    trend = get_traffic_trend()
    return jsonify({"success": True, "data": trend})

@app.route("/api/dashboard/attack-distribution", methods=["GET"])
def api_attack_distribution():
    dist = get_attack_distribution()
    return jsonify({"success": True, "data": dist})


# --- AI PREDICTION APIS ---
@app.route("/api/predict/single", methods=["POST"])
def api_predict_single():
    try:
        data = request.get_json() or {}
        features = data.get("features", {})
        src_ip = data.get("source_ip", "192.168.1.100")
        dst_ip = data.get("destination_ip", "10.0.0.1")
        save_db = data.get("save_to_history", True)

        result = ml_engine.predict_single(features, src_ip=src_ip, dst_ip=dst_ip)

        if save_db:
            protocol = "TCP" if float(features.get("protocol", 6)) == 6 else "UDP"
            flow_dur = float(features.get("flow_duration", 100))
            pkts = int(float(features.get("total_fwd_packets", 1)) + float(features.get("total_bwd_packets", 0)))
            total_bytes = float(features.get("total_fwd_bytes", 64)) + float(features.get("total_bwd_bytes", 0))

            db_res = add_detection(
                source_ip=src_ip,
                destination_ip=dst_ip,
                attack_type=result["attack_type"],
                confidence=result["confidence"],
                severity=result["severity"],
                protocol=protocol,
                flow_duration=flow_dur,
                total_packets=pkts,
                total_bytes=round(total_bytes, 2),
                is_simulated=0
            )
            result["db_record"] = db_res

        return jsonify({"success": True, "prediction": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


# --- LIVE MONITORING & SIMULATION APIS ---
@app.route("/api/monitoring/stream", methods=["GET"])
def api_monitoring_stream():
    """Generates next live packet telemetry from IoT simulator."""
    record = request.args.get("record", "false").lower() == "true"
    scenario = request.args.get("scenario", None)
    packet = simulator.generate_flow_packet(scenario_override=scenario, record_to_db=record)
    return jsonify({"success": True, "packet": packet})

@app.route("/api/monitoring/scenario", methods=["POST"])
def api_monitoring_scenario():
    data = request.get_json() or {}
    scenario = data.get("scenario", "Normal Traffic")
    success = simulator.set_scenario(scenario)
    return jsonify({"success": success, "current_scenario": simulator.active_mode})


# --- DATASET UPLOAD & BATCH PREDICTION APIS ---
@app.route("/api/upload/preview", methods=["POST"])
def api_upload_preview():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No selected file"}), 400

    if not file.filename.endswith(".csv"):
        return jsonify({"success": False, "error": "Only CSV files are supported"}), 400

    try:
        df = pd.read_csv(file)
        row_count, col_count = df.shape
        columns = list(df.columns)
        
        # Check required columns
        required_cols = ml_engine.metadata.get("feature_columns", [])
        matched = [c for c in required_cols if c in columns]
        missing = [c for c in required_cols if c not in columns]

        preview_data = df.head(8).to_dict(orient="records")

        return jsonify({
            "success": True,
            "filename": secure_filename(file.filename),
            "rows": row_count,
            "columns": col_count,
            "column_list": columns,
            "matched_features": len(matched),
            "total_required": len(required_cols),
            "missing_features": missing,
            "preview": preview_data
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to parse CSV: {str(e)}"}), 400

@app.route("/api/upload/predict", methods=["POST"])
def api_upload_predict():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400

    file = request.files["file"]
    if not file.filename.endswith(".csv"):
        return jsonify({"success": False, "error": "Only CSV files are allowed"}), 400

    try:
        df = pd.read_csv(file)
        if len(df) > 10000:
            df = df.head(10000) # Safety limit for web upload

        result_df = ml_engine.predict_dataframe(df)

        # Attack summary
        attack_counts = result_df["predicted_attack"].value_counts().to_dict()
        severity_counts = result_df["severity"].value_counts().to_dict()

        total = len(result_df)
        malicious = sum(cnt for atk, cnt in attack_counts.items() if atk != "Normal Traffic")
        normal = attack_counts.get("Normal Traffic", 0)

        # Save result file for user download
        result_id = str(uuid.uuid4())[:8]
        result_filename = f"detection_results_{result_id}.csv"
        result_path = os.path.join(Config.UPLOAD_FOLDER, result_filename)
        result_df.to_csv(result_path, index=False)

        preview_rows = result_df.head(25).to_dict(orient="records")

        return jsonify({
            "success": True,
            "total_samples": total,
            "normal_samples": normal,
            "malicious_samples": malicious,
            "attack_breakdown": attack_counts,
            "severity_breakdown": severity_counts,
            "download_filename": result_filename,
            "results_preview": preview_rows
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Prediction failed: {str(e)}"}), 500

@app.route("/api/download/sample-csv", methods=["GET"])
def download_sample_csv():
    if os.path.exists(Config.SAMPLE_TEST_CSV):
        return send_file(
            Config.SAMPLE_TEST_CSV,
            mimetype="text/csv",
            as_attachment=True,
            download_name="sample_iot_packets.csv"
        )
    return jsonify({"error": "Sample file not found"}), 404

@app.route("/api/download/prediction-results/<filename>", methods=["GET"])
def download_prediction_results(filename):
    clean_name = secure_filename(filename)
    path = os.path.join(Config.UPLOAD_FOLDER, clean_name)
    if os.path.exists(path):
        return send_file(
            path,
            mimetype="text/csv",
            as_attachment=True,
            download_name=clean_name
        )
    return jsonify({"error": "File not found"}), 404


# --- ALERTS MANAGEMENT APIS ---
@app.route("/api/alerts", methods=["GET"])
def api_get_alerts():
    severity = request.args.get("severity", "All")
    status = request.args.get("status", "All")
    attack_type = request.args.get("attack_type", "All")
    search = request.args.get("search", "")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    data = get_alerts(severity=severity, status=status, attack_type=attack_type, search=search, limit=limit, offset=offset)
    return jsonify({"success": True, "data": data})

@app.route("/api/alerts/<int:alert_id>/status", methods=["POST"])
def api_update_alert_status(alert_id):
    req = request.get_json() or {}
    new_status = req.get("status", "Acknowledged")
    update_alert_status(alert_id, new_status)
    return jsonify({"success": True, "alert_id": alert_id, "new_status": new_status})

@app.route("/api/alerts/batch", methods=["POST"])
def api_batch_alerts():
    req = request.get_json() or {}
    action = req.get("action", "acknowledge_all")
    alert_ids = req.get("alert_ids", [])
    batch_update_alerts(action, alert_ids)
    return jsonify({"success": True, "action": action})

@app.route("/api/alerts/counts", methods=["GET"])
def api_alert_counts():
    counts = get_alert_counts()
    return jsonify({"success": True, "counts": counts})


# --- DETECTION HISTORY APIS ---
@app.route("/api/history", methods=["GET"])
def api_get_history():
    attack_type = request.args.get("attack_type", "All")
    severity = request.args.get("severity", "All")
    search = request.args.get("search", "")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    data = get_detection_history(attack_type=attack_type, severity=severity, search=search, limit=limit, offset=offset)
    return jsonify({"success": True, "data": data})

@app.route("/api/download/history-csv", methods=["GET"])
def download_history_csv():
    csv_str = export_history_as_csv_string()
    return Response(
        csv_str,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=iot_cyberattack_history_export.csv"}
    )


# --- ML MODEL MANAGEMENT APIS ---
@app.route("/api/model/performance", methods=["GET"])
def api_model_performance():
    meta = ml_engine.get_metadata()
    return jsonify({"success": True, "metadata": meta})

@app.route("/api/model/retrain", methods=["POST"])
def api_model_retrain():
    try:
        updated_meta = ml_engine.retrain_model()
        return jsonify({"success": True, "message": "Model retrained successfully!", "metadata": updated_meta})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# --- REPORTS SUMMARY API ---
@app.route("/api/reports/summary", methods=["GET"])
def api_reports_summary():
    stats = get_dashboard_stats()
    dist = get_attack_distribution()
    meta = ml_engine.get_metadata()
    return jsonify({
        "success": True,
        "dashboard_stats": stats,
        "attack_distribution": dist,
        "model_metrics": meta.get("metrics", {}),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


# --- ERROR HANDLERS ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template("base.html", custom_content="""
        <div class="container py-5 text-center">
            <div class="display-1 text-danger font-monospace mb-3">404</div>
            <h2 class="text-light mb-3">CYBER INTRUSION SENSOR: TARGET NOT FOUND</h2>
            <p class="text-muted mb-4">The requested node or page does not exist in the IoT Security Cluster.</p>
            <a href="/dashboard" class="btn btn-primary px-4 py-2"><i class="bi bi-speedometer2 me-2"></i>Return to SOC Dashboard</a>
        </div>
    """), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"success": False, "error": "Internal Cybersecurity SOC Engine Error"}), 500

if __name__ == "__main__":
    print("[*] Starting AI IoT Cyberattack Detection System...")
    print("[*] Web Console: http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
