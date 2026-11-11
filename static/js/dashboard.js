/**
 * Dashboard Charts & Live Telemetry Refresh
 */

let trafficTrendChart = null;
let attackDistChart = null;

document.addEventListener("DOMContentLoaded", function () {
    initTrafficTrendChart();
    initAttackDistChart();
    loadDashboardData();

    const refreshBtn = document.getElementById("btnRefreshDashboard");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", function () {
            this.disabled = true;
            this.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Refreshing...';
            loadDashboardData(() => {
                this.disabled = false;
                this.innerHTML = '<i class="bi bi-arrow-clockwise"></i> <span>Refresh Data</span>';
                showCyberToast("Dashboard Refreshed", "Latest SOC metrics synced from backend.", "success");
            });
        });
    }

    const resetBtn = document.getElementById("btnResetTelemetry");
    if (resetBtn) {
        resetBtn.addEventListener("click", function () {
            if (!confirm("Are you sure you want to clear all telemetry & security alerts to start a fresh live session?")) return;
            fetch("/api/telemetry/reset", { method: "POST" })
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        showCyberToast("Session Reset", "All historical records wiped. System is in pristine live state.", "info");
                        loadDashboardData();
                    }
                })
                .catch(err => showCyberToast("Error", "Could not reset telemetry.", "error"));
        });
    }

    // Auto refresh every 20 seconds
    setInterval(loadDashboardData, 20000);
});

function initTrafficTrendChart() {
    const ctx = document.getElementById("trafficTrendChart");
    if (!ctx) return;

    trafficTrendChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: ["--:--", "--:--", "--:--", "--:--", "--:--", "--:--"],
            datasets: [
                {
                    label: "Normal IoT Telemetry",
                    data: [0, 0, 0, 0, 0, 0],
                    borderColor: "#10b981",
                    backgroundColor: "rgba(16, 185, 129, 0.1)",
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2,
                    pointRadius: 3,
                    pointBackgroundColor: "#10b981"
                },
                {
                    label: "Malicious Attack Packets",
                    data: [0, 0, 0, 0, 0, 0],
                    borderColor: "#ef4444",
                    backgroundColor: "rgba(239, 68, 68, 0.15)",
                    fill: true,
                    tension: 0.35,
                    borderWidth: 2,
                    pointRadius: 4,
                    pointBackgroundColor: "#ef4444"
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: "#94a3b8",
                        font: { family: "'Inter', sans-serif", size: 12 }
                    }
                },
                tooltip: {
                    backgroundColor: "#0f172a",
                    titleColor: "#00f0ff",
                    bodyColor: "#f8fafc",
                    borderColor: "rgba(0, 240, 255, 0.3)",
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: { color: "rgba(255, 255, 255, 0.05)" },
                    ticks: { color: "#64748b", font: { family: "'JetBrains Mono', monospace", size: 11 } }
                },
                y: {
                    grid: { color: "rgba(255, 255, 255, 0.05)" },
                    ticks: { color: "#64748b", font: { family: "'JetBrains Mono', monospace", size: 11 } }
                }
            }
        }
    });
}

function initAttackDistChart() {
    const ctx = document.getElementById("attackDistChart");
    if (!ctx) return;

    attackDistChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels: ["Normal Traffic", "DDoS Attack", "DoS Attack", "Port Scanning", "Brute Force", "Botnet"],
            datasets: [{
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: [
                    "#10b981", // Normal
                    "#ef4444", // DDoS
                    "#f59e0b", // DoS
                    "#06b6d4", // Port Scanning
                    "#f97316", // Brute Force
                    "#a855f7"  // Botnet
                ],
                borderColor: "#0f172a",
                borderWidth: 2,
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: "bottom",
                    labels: {
                        color: "#94a3b8",
                        boxWidth: 12,
                        font: { family: "'Inter', sans-serif", size: 11 }
                    }
                },
                tooltip: {
                    backgroundColor: "#0f172a",
                    titleColor: "#00f0ff",
                    bodyColor: "#f8fafc",
                    borderColor: "rgba(0, 240, 255, 0.3)",
                    borderWidth: 1
                }
            },
            cutout: "65%"
        }
    });
}

function loadDashboardData(callback) {
    // 1. Fetch Stats
    fetch("/api/dashboard/stats")
        .then(res => res.json())
        .then(data => {
            if (data.success && data.data) {
                const s = data.data;
                const setEl = (id, val) => {
                    const el = document.getElementById(id);
                    if (el) el.textContent = val;
                };
                setEl("dashTotalPackets", s.total_packets.toLocaleString());
                setEl("dashTrafficBytes", `${s.total_traffic_bytes} KB`);
                setEl("dashNormalCount", s.normal_count.toLocaleString());
                setEl("dashMaliciousCount", s.attack_count.toLocaleString());
                setEl("dashActiveThreats", s.active_threats);
                setEl("dashTotalFlows", s.total_flows.toLocaleString());
            }
        })
        .catch(err => console.error("Error fetching stats:", err));

    // 2. Fetch Trend
    fetch("/api/dashboard/traffic-trend")
        .then(res => res.json())
        .then(data => {
            if (data.success && data.data && trafficTrendChart) {
                trafficTrendChart.data.labels = data.data.labels;
                trafficTrendChart.data.datasets[0].data = data.data.normal;
                trafficTrendChart.data.datasets[1].data = data.data.attacks;
                trafficTrendChart.update();
            }
        })
        .catch(err => console.error("Error fetching trend:", err));

    // 3. Fetch Distribution
    fetch("/api/dashboard/attack-distribution")
        .then(res => res.json())
        .then(data => {
            if (data.success && data.data && attackDistChart) {
                const labels = Object.keys(data.data);
                const values = Object.values(data.data);
                attackDistChart.data.labels = labels;
                attackDistChart.data.datasets[0].data = values;
                attackDistChart.update();
            }
            if (callback) callback();
        })
        .catch(err => {
            console.error("Error fetching distribution:", err);
            if (callback) callback();
        });
}

function quickResolveAlert(alertId) {
    fetch(`/api/alerts/${alertId}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: "Resolved" })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            showCyberToast("Alert Resolved", `Alert #${alertId} status marked as Resolved.`, "success");
            loadDashboardData();
        }
    })
    .catch(err => showCyberToast("Error", "Could not resolve alert.", "error"));
}
