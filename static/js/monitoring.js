/**
 * Live Network Monitoring Console Script
 */

let isStreaming = true;
let streamInterval = null;
let liveChart = null;
let totalInspected = 0;
let normalCount = 0;
let attackCount = 0;
let recentPackets = [];

document.addEventListener("DOMContentLoaded", function () {
    initLiveChart();
    startStream();

    const btnToggle = document.getElementById("btnToggleStream");
    if (btnToggle) {
        btnToggle.addEventListener("click", function () {
            if (isStreaming) {
                pauseStream();
            } else {
                startStream();
            }
        });
    }

    const btnClear = document.getElementById("btnClearStream");
    if (btnClear) {
        btnClear.addEventListener("click", function () {
            document.getElementById("liveStreamTbody").innerHTML = "";
            recentPackets = [];
            showCyberToast("Table Cleared", "Monitoring table buffer cleared.", "info");
        });
    }

    const scenarioSelect = document.getElementById("scenarioSelect");
    if (scenarioSelect) {
        scenarioSelect.addEventListener("change", function () {
            const sc = this.value;
            fetch("/api/monitoring/scenario", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ scenario: sc })
            })
            .then(res => res.json())
            .then(data => {
                showCyberToast("Scenario Injected", `Simulator switched to: ${sc}`, sc === "Normal Traffic" ? "info" : "warning");
            });
        });
    }
});

function initLiveChart() {
    const ctx = document.getElementById("liveMonitoringChart");
    if (!ctx) return;

    const initialLabels = Array.from({ length: 15 }, (_, i) => `${15 - i}s ago`);
    const initialPackets = Array(15).fill(0);
    const initialThreats = Array(15).fill(0);

    liveChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: initialLabels,
            datasets: [
                {
                    label: "Packets Ingress / Sec",
                    data: initialPackets,
                    borderColor: "#00f0ff",
                    backgroundColor: "rgba(0, 240, 255, 0.1)",
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2,
                    pointRadius: 2
                },
                {
                    label: "Attacks Intercepted",
                    data: initialThreats,
                    borderColor: "#ef4444",
                    backgroundColor: "rgba(239, 68, 68, 0.2)",
                    fill: true,
                    tension: 0.3,
                    borderWidth: 2,
                    pointRadius: 3,
                    pointBackgroundColor: "#ef4444"
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 400 },
            plugins: {
                legend: {
                    labels: { color: "#94a3b8", font: { family: "'Inter', sans-serif", size: 11 } }
                }
            },
            scales: {
                x: {
                    grid: { color: "rgba(255, 255, 255, 0.05)" },
                    ticks: { color: "#64748b", font: { family: "'JetBrains Mono', monospace", size: 10 } }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: "rgba(255, 255, 255, 0.05)" },
                    ticks: { color: "#64748b", font: { family: "'JetBrains Mono', monospace", size: 10 } }
                }
            }
        }
    });
}

function startStream() {
    isStreaming = true;
    document.getElementById("streamStatusDot").className = "status-dot green";
    document.getElementById("streamStatusText").textContent = "STREAM: STREAMING LIVE";
    document.getElementById("streamIcon").className = "bi bi-pause-fill";
    document.getElementById("streamBtnText").textContent = "Pause Stream";

    if (streamInterval) clearInterval(streamInterval);
    streamInterval = setInterval(fetchStreamPacket, 1600);
}

function pauseStream() {
    isStreaming = false;
    document.getElementById("streamStatusDot").className = "status-dot yellow";
    document.getElementById("streamStatusText").textContent = "STREAM: PAUSED";
    document.getElementById("streamIcon").className = "bi bi-play-fill";
    document.getElementById("streamBtnText").textContent = "Resume Stream";

    if (streamInterval) {
        clearInterval(streamInterval);
        streamInterval = null;
    }
}

function fetchStreamPacket() {
    const autoRecord = document.getElementById("chkAutoRecord").checked;
    const scenario = document.getElementById("scenarioSelect").value;

    fetch(`/api/monitoring/stream?record=${autoRecord}&scenario=${encodeURIComponent(scenario)}`)
        .then(res => res.json())
        .then(data => {
            if (data.success && data.packet) {
                handleNewPacket(data.packet);
            }
        })
        .catch(err => console.error("Stream fetch error:", err));
}

function handleNewPacket(p) {
    totalInspected++;
    recentPackets.unshift(p);
    if (recentPackets.length > 50) recentPackets.pop();

    if (p.predicted_attack === "Normal Traffic") {
        normalCount++;
    } else {
        attackCount++;
    }

    // Update Top Counters
    document.getElementById("streamCounter").textContent = `${totalInspected} FLOWS INSPECTED`;
    document.getElementById("liveNormalTotal").textContent = normalCount.toLocaleString();
    document.getElementById("liveAttackTotal").textContent = attackCount.toLocaleString();
    document.getElementById("livePktRate").innerHTML = `${p.packets} <span class="fs-6 text-muted">pkts/s</span>`;
    document.getElementById("liveByteRate").innerHTML = `${(p.bytes / 1024).toFixed(1)} <span class="fs-6 text-muted">KB/s</span>`;

    // Update Rolling Chart
    if (liveChart) {
        liveChart.data.labels.shift();
        liveChart.data.labels.push(p.timestamp);

        liveChart.data.datasets[0].data.shift();
        liveChart.data.datasets[0].data.push(p.packets);

        liveChart.data.datasets[1].data.shift();
        liveChart.data.datasets[1].data.push(p.predicted_attack === "Normal Traffic" ? 0 : 1);

        liveChart.update("none");
    }

    // Prepend Row to Stream Table
    const tbody = document.getElementById("liveStreamTbody");
    const tr = document.createElement("tr");
    tr.style.animation = "fadeIn 0.3s ease";

    const isMalicious = p.predicted_attack !== "Normal Traffic";
    if (isMalicious) {
        tr.style.background = "rgba(239, 68, 68, 0.05)";
    }

    const packetIndex = recentPackets.length - 1;

    tr.innerHTML = `
        <td class="font-mono text-muted small">${p.timestamp}</td>
        <td>
            <div class="fw-bold text-light small">${p.device_name}</div>
            <div class="text-muted" style="font-size:0.75rem;">${p.device_type}</div>
        </td>
        <td><span class="ip-badge">${p.source_ip}:${p.src_port}</span></td>
        <td><span class="ip-badge">${p.destination_ip}:${p.dst_port}</span></td>
        <td><span class="badge bg-dark font-mono text-info">${p.protocol}</span></td>
        <td class="font-mono text-end">${p.packets}</td>
        <td class="font-mono text-end">${p.bytes} B</td>
        <td>
            <strong style="color: ${p.color};">${p.predicted_attack}</strong>
        </td>
        <td class="font-mono text-info">${p.confidence}%</td>
        <td>
            <span class="badge-cyber ${p.severity.toLowerCase()}">${p.severity}</span>
        </td>
        <td>
            <button class="btn btn-sm btn-outline-info py-0 px-2 font-mono small" onclick="inspectPacket(${0})">
                <i class="bi bi-eye"></i>
            </button>
        </td>
    `;

    tbody.insertBefore(tr, tbody.firstChild);

    // Limit table rows to 40
    while (tbody.children.length > 40) {
        tbody.removeChild(tbody.lastChild);
    }
}

function inspectPacket(idx) {
    const p = recentPackets[idx];
    if (!p) return;

    document.getElementById("packetModalTitle").innerHTML = `
        <i class="bi bi-shield-shaded me-2" style="color: ${p.color};"></i>
        <span>${p.predicted_attack} [${p.confidence}% CONFIDENCE]</span>
    `;

    let html = `
        <div class="row g-3 mb-3">
            <div class="col-md-6">
                <div class="p-2 rounded bg-black border border-secondary border-opacity-25">
                    <span class="text-muted d-block small">ORIGIN DEVICE:</span>
                    <strong class="text-light">${p.device_name} (${p.device_type})</strong>
                    <div class="text-info">${p.source_ip}:${p.src_port}</div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="p-2 rounded bg-black border border-secondary border-opacity-25">
                    <span class="text-muted d-block small">DESTINATION TARGET:</span>
                    <strong class="text-light">Gateway Node</strong>
                    <div class="text-info">${p.destination_ip}:${p.dst_port}</div>
                </div>
            </div>
        </div>

        <div class="p-3 rounded bg-black border border-secondary border-opacity-25 mb-3">
            <div class="d-flex justify-content-between mb-1">
                <span class="text-muted">THREAT SEVERITY:</span>
                <span class="badge-cyber ${p.severity.toLowerCase()}">${p.severity}</span>
            </div>
            <div class="d-flex justify-content-between mb-1">
                <span class="text-muted">MITRE ATT&CK:</span>
                <span class="text-light">${p.mitre_id}</span>
            </div>
            <div class="d-flex justify-content-between">
                <span class="text-muted">SOC MITIGATION:</span>
                <span class="text-warning text-end" style="max-width: 60%;">${p.recommendation}</span>
            </div>
        </div>

        <h6 class="text-info font-mono mt-3 mb-2">RAW 18-FEATURE FLOW ATTRIBUTES</h6>
        <div class="table-responsive">
            <table class="table table-sm table-dark table-bordered font-mono" style="font-size:0.75rem;">
                <tbody>
    `;

    if (p.features) {
        let count = 0;
        let rowHtml = "<tr>";
        for (const [k, v] of Object.entries(p.features)) {
            rowHtml += `<td class="text-muted">${k}:</td><td class="text-info fw-bold">${v}</td>`;
            count++;
            if (count % 2 === 0) {
                rowHtml += "</tr><tr>";
            }
        }
        rowHtml += "</tr>";
        html += rowHtml;
    }

    html += `
                </tbody>
            </table>
        </div>
    `;

    document.getElementById("packetModalBody").innerHTML = html;
    const modal = new bootstrap.Modal(document.getElementById("packetModal"));
    modal.show();
}
