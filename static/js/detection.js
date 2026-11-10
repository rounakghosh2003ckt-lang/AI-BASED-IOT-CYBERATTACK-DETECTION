/**
 * AI Cyberattack Detection - Single Flow Predictor Script
 */

const PRESETS = {
    ddos: {
        src_ip: "192.168.1.188",
        dst_ip: "10.0.0.1",
        protocol: 6,
        src_port: 52190,
        dst_port: 80,
        flow_duration: 48000,
        flow_bytes_per_sec: 34500,
        flow_packets_per_sec: 68.5,
        total_fwd_packets: 240,
        total_bwd_packets: 4,
        total_fwd_bytes: 142000,
        total_bwd_bytes: 256,
        packet_length_mean: 591.6,
        packet_length_std: 114.2,
        packet_length_max: 1460,
        syn_flag_count: 32,
        ack_flag_count: 1,
        fin_flag_count: 0,
        rst_flag_count: 1,
        header_length: 7680
    },
    dos: {
        src_ip: "192.168.1.173",
        dst_ip: "10.0.0.1",
        protocol: 6,
        src_port: 48102,
        dst_port: 80,
        flow_duration: 68000,
        flow_bytes_per_sec: 1850,
        flow_packets_per_sec: 8.2,
        total_fwd_packets: 52,
        total_bwd_packets: 5,
        total_fwd_bytes: 11200,
        total_bwd_bytes: 320,
        packet_length_mean: 215.4,
        packet_length_std: 42.1,
        packet_length_max: 380,
        syn_flag_count: 16,
        ack_flag_count: 1,
        fin_flag_count: 1,
        rst_flag_count: 2,
        header_length: 1248
    },
    botnet: {
        src_ip: "192.168.1.144",
        dst_ip: "185.190.140.23",
        protocol: 6,
        src_port: 39120,
        dst_port: 6667,
        flow_duration: 16500,
        flow_bytes_per_sec: 1420,
        flow_packets_per_sec: 3.8,
        total_fwd_packets: 32,
        total_bwd_packets: 14,
        total_fwd_bytes: 2432,
        total_bwd_bytes: 840,
        packet_length_mean: 76.0,
        packet_length_std: 21.4,
        packet_length_max: 180,
        syn_flag_count: 5,
        ack_flag_count: 2,
        fin_flag_count: 0,
        rst_flag_count: 1,
        header_length: 768
    },
    bruteforce: {
        src_ip: "192.168.1.202",
        dst_ip: "10.0.0.4",
        protocol: 6,
        src_port: 44210,
        dst_port: 22,
        flow_duration: 9200,
        flow_bytes_per_sec: 2150,
        flow_packets_per_sec: 4.5,
        total_fwd_packets: 22,
        total_bwd_packets: 18,
        total_fwd_bytes: 2090,
        total_bwd_bytes: 1440,
        packet_length_mean: 95.0,
        packet_length_std: 34.0,
        packet_length_max: 320,
        syn_flag_count: 2,
        ack_flag_count: 5,
        fin_flag_count: 2,
        rst_flag_count: 3,
        header_length: 528
    },
    portscan: {
        src_ip: "192.168.1.189",
        dst_ip: "10.0.0.15",
        protocol: 6,
        src_port: 58921,
        dst_port: 443,
        flow_duration: 120,
        flow_bytes_per_sec: 750,
        flow_packets_per_sec: 16.6,
        total_fwd_packets: 2,
        total_bwd_packets: 0,
        total_fwd_bytes: 88,
        total_bwd_bytes: 0,
        packet_length_mean: 44.0,
        packet_length_std: 0.0,
        packet_length_max: 44,
        syn_flag_count: 2,
        ack_flag_count: 0,
        fin_flag_count: 0,
        rst_flag_count: 1,
        header_length: 40
    },
    normal: {
        src_ip: "192.168.1.112",
        dst_ip: "10.0.0.1",
        protocol: 6,
        src_port: 41200,
        dst_port: 1883,
        flow_duration: 11500,
        flow_bytes_per_sec: 180,
        flow_packets_per_sec: 2.1,
        total_fwd_packets: 12,
        total_bwd_packets: 11,
        total_fwd_bytes: 1440,
        total_bwd_bytes: 1210,
        packet_length_mean: 120.0,
        packet_length_std: 24.5,
        packet_length_max: 180,
        syn_flag_count: 1,
        ack_flag_count: 2,
        fin_flag_count: 0,
        rst_flag_count: 0,
        header_length: 460
    }
};

function loadPreset(name) {
    const p = PRESETS[name];
    if (!p) return;

    for (const [key, value] of Object.entries(p)) {
        const input = document.getElementById(key);
        if (input) input.value = value;
    }
    showCyberToast("Preset Loaded", `Loaded ${name.toUpperCase()} network flow preset attributes.`, "info");
}

function resetForm() {
    document.getElementById("detectionForm").reset();
    document.getElementById("resultPlaceholder").style.display = "block";
    document.getElementById("resultContent").style.display = "none";
    document.getElementById("detectionTimeBadge").textContent = "AWAITING INFERENCE";
}

document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("detectionForm");
    if (!form) return;

    form.addEventListener("submit", function (e) {
        e.preventDefault();
        executeDetection();
    });
});

function executeDetection() {
    const btn = document.getElementById("btnPredict");
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Classifying...';

    const getVal = id => {
        const el = document.getElementById(id);
        return el ? el.value : "";
    };

    const payload = {
        source_ip: getVal("src_ip"),
        destination_ip: getVal("dst_ip"),
        save_to_history: document.getElementById("saveToHistory").checked,
        features: {
            flow_duration: getVal("flow_duration"),
            protocol: getVal("protocol"),
            src_port: getVal("src_port"),
            dst_port: getVal("dst_port"),
            total_fwd_packets: getVal("total_fwd_packets"),
            total_bwd_packets: getVal("total_bwd_packets"),
            total_fwd_bytes: getVal("total_fwd_bytes"),
            total_bwd_bytes: getVal("total_bwd_bytes"),
            packet_length_mean: getVal("packet_length_mean"),
            packet_length_std: getVal("packet_length_std"),
            packet_length_max: getVal("packet_length_max"),
            flow_bytes_per_sec: getVal("flow_bytes_per_sec"),
            flow_packets_per_sec: getVal("flow_packets_per_sec"),
            syn_flag_count: getVal("syn_flag_count"),
            ack_flag_count: getVal("ack_flag_count"),
            fin_flag_count: getVal("fin_flag_count"),
            rst_flag_count: getVal("rst_flag_count"),
            header_length: getVal("header_length")
        }
    };

    fetch("/api/predict/single", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    })
    .then(res => res.json())
    .then(data => {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-cpu-fill"></i> <span>Execute AI Detection</span>';

        if (data.success && data.prediction) {
            renderPredictionResult(data.prediction);
            showCyberToast("Analysis Complete", `Classified flow as: ${data.prediction.attack_type}`, data.prediction.severity === "Safe" ? "success" : "error");
        } else {
            showCyberToast("Error", data.error || "Inference failed", "error");
        }
    })
    .catch(err => {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-cpu-fill"></i> <span>Execute AI Detection</span>';
        showCyberToast("Connection Error", "Could not reach detection API", "error");
        console.error(err);
    });
}

function renderPredictionResult(p) {
    document.getElementById("resultPlaceholder").style.display = "none";
    const content = document.getElementById("resultContent");
    content.style.display = "block";

    // Header badge
    document.getElementById("detectionTimeBadge").textContent = `DETECTED: ${p.detection_time}`;

    // Verdict Banner
    const banner = document.getElementById("verdictBanner");
    const atkTitle = document.getElementById("verdictAttackType");
    const sevBadge = document.getElementById("verdictSeverityBadge");

    atkTitle.textContent = p.attack_type;
    atkTitle.style.color = p.color;
    sevBadge.className = `badge-cyber ${p.severity.toLowerCase()}`;
    sevBadge.textContent = p.severity.toUpperCase();

    banner.style.background = `${p.color}18`;
    banner.style.border = `1px solid ${p.color}`;

    // Details
    document.getElementById("verdictConfidence").textContent = `${p.confidence}%`;
    const confBar = document.getElementById("verdictConfidenceBar");
    confBar.style.width = `${p.confidence}%`;
    confBar.style.backgroundColor = p.color;

    document.getElementById("verdictSrcIp").textContent = p.source_ip;
    document.getElementById("verdictDstIp").textContent = p.destination_ip;
    document.getElementById("verdictMitre").textContent = p.mitre_id;
    document.getElementById("verdictRecommendation").textContent = p.recommendation;

    // Multi-class probabilities
    const probList = document.getElementById("probDistributionList");
    probList.innerHTML = "";

    if (p.probabilities) {
        for (const [clsName, prob] of Object.entries(p.probabilities)) {
            const isWinner = clsName === p.attack_type;
            const item = document.createElement("div");
            item.className = "d-flex align-items-center justify-content-between p-1 px-2 rounded";
            item.style.background = isWinner ? "rgba(0, 240, 255, 0.12)" : "rgba(255,255,255,0.02)";
            item.style.border = isWinner ? "1px solid rgba(0,240,255,0.3)" : "1px solid transparent";

            item.innerHTML = `
                <span class="${isWinner ? 'text-info fw-bold' : 'text-muted'}">${clsName}</span>
                <div class="d-flex align-items-center gap-2" style="width: 140px;">
                    <div class="progress flex-grow-1" style="height: 5px; background: rgba(255,255,255,0.1);">
                        <div class="progress-bar ${isWinner ? 'bg-info' : 'bg-secondary'}" style="width: ${prob}%"></div>
                    </div>
                    <span style="width: 45px; text-align: right;" class="${isWinner ? 'text-info fw-bold' : 'text-muted'}">${prob}%</span>
                </div>
            `;
            probList.appendChild(item);
        }
    }
}
