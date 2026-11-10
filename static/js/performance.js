/**
 * ML Model Performance Charts & Heatmap
 */

let featChart = null;

document.addEventListener("DOMContentLoaded", function () {
    loadModelPerformance();

    const btnRetrain = document.getElementById("btnRetrainModel");
    if (btnRetrain) {
        btnRetrain.addEventListener("click", function () {
            if (!confirm("Trigger real-time retraining of the Random Forest Classifier on the IoT dataset?")) return;

            btnRetrain.disabled = true;
            btnRetrain.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Retraining Algorithm...';

            fetch("/api/model/retrain", { method: "POST" })
                .then(res => res.json())
                .then(data => {
                    btnRetrain.disabled = false;
                    btnRetrain.innerHTML = '<i class="bi bi-arrow-repeat"></i> <span>Retrain Model</span>';

                    if (data.success) {
                        showCyberToast("Retraining Complete", "Model retrained and newly serialized to joblib!", "success");
                        loadModelPerformance();
                    } else {
                        showCyberToast("Retrain Failed", data.error || "Training error", "error");
                    }
                })
                .catch(err => {
                    btnRetrain.disabled = false;
                    btnRetrain.innerHTML = '<i class="bi bi-arrow-repeat"></i> <span>Retrain Model</span>';
                    showCyberToast("Error", "Could not trigger model retraining.", "error");
                });
        });
    }
});

function loadModelPerformance() {
    fetch("/api/model/performance")
        .then(res => res.json())
        .then(data => {
            if (data.success && data.metadata) {
                renderPerformanceView(data.metadata);
            }
        })
        .catch(err => console.error("Performance load error:", err));
}

function renderPerformanceView(m) {
    // 1. Metrics Cards
    if (m.metrics) {
        document.getElementById("metricAccuracy").textContent = `${(m.metrics.accuracy * 100).toFixed(2)}%`;
        document.getElementById("metricPrecision").textContent = `${(m.metrics.precision_weighted * 100).toFixed(2)}%`;
        document.getElementById("metricRecall").textContent = `${(m.metrics.recall_weighted * 100).toFixed(2)}%`;
        document.getElementById("metricF1").textContent = `${(m.metrics.f1_weighted * 100).toFixed(2)}%`;
    }

    // 2. Feature Importances Chart
    if (m.feature_importances) {
        renderFeatureChart(m.feature_importances);
    }

    // 3. Confusion Matrix Table
    if (m.confusion_matrix && m.classes) {
        renderConfusionMatrix(m.confusion_matrix, m.classes);
    }

    // 4. Classification Report Table
    if (m.classification_report && m.classes) {
        renderClassificationReport(m.classification_report, m.classes);
    }
}

function renderFeatureChart(feats) {
    const ctx = document.getElementById("featureImportanceChart");
    if (!ctx) return;

    const top8 = feats.slice(0, 8);
    const labels = top8.map(f => f.feature.replace(/_/g, " ").toUpperCase());
    const values = top8.map(f => f.importance);

    if (featChart) featChart.destroy();

    featChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: labels,
            datasets: [{
                label: "Feature Importance (%)",
                data: values,
                backgroundColor: [
                    "rgba(0, 240, 255, 0.7)",
                    "rgba(56, 189, 248, 0.7)",
                    "rgba(0, 255, 136, 0.7)",
                    "rgba(192, 132, 252, 0.7)",
                    "rgba(245, 158, 11, 0.7)",
                    "rgba(239, 68, 68, 0.7)",
                    "rgba(59, 130, 246, 0.7)",
                    "rgba(147, 197, 253, 0.7)"
                ],
                borderColor: "#0f172a",
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: "y",
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
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
                    ticks: { color: "#64748b", font: { family: "'JetBrains Mono', monospace", size: 10 } }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: "#94a3b8", font: { family: "'Inter', sans-serif", size: 10 } }
                }
            }
        }
    });
}

function renderConfusionMatrix(matrix, classes) {
    const table = document.getElementById("confusionMatrixTable");
    table.innerHTML = "";

    // Thead
    let theadHtml = `<thead><tr><th class="text-start">Actual \\ Predicted</th>`;
    classes.forEach(c => theadHtml += `<th>${c}</th>`);
    theadHtml += `</tr></thead>`;

    // Tbody
    let tbodyHtml = `<tbody>`;
    for (let i = 0; i < classes.length; i++) {
        tbodyHtml += `<tr><th class="text-start text-light font-mono" style="background: rgba(10,15,29,0.9); font-size:0.75rem;">${classes[i]}</th>`;
        for (let j = 0; j < classes.length; j++) {
            const val = matrix[i][j];
            const isDiagonal = i === j;
            let bg = "transparent";
            let color = "#94a3b8";

            if (isDiagonal && val > 0) {
                bg = "rgba(0, 255, 136, 0.15)";
                color = "#00ff88";
            } else if (!isDiagonal && val > 0) {
                bg = "rgba(239, 68, 68, 0.2)";
                color = "#f87171";
            }

            tbodyHtml += `<td class="font-mono fw-bold" style="background:${bg}; color:${color}; font-size:0.85rem;">${val}</td>`;
        }
        tbodyHtml += `</tr>`;
    }
    tbodyHtml += `</tbody>`;

    table.innerHTML = theadHtml + tbodyHtml;
}

function renderClassificationReport(report, classes) {
    const tbody = document.getElementById("clfReportTbody");
    tbody.innerHTML = "";

    classes.forEach(c => {
        const row = report[c];
        if (!row) return;

        const prec = (row.precision * 100).toFixed(1);
        const rec = (row.recall * 100).toFixed(1);
        const f1 = (row["f1-score"] * 100).toFixed(1);
        const supp = row.support;

        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><strong class="text-light">${c}</strong></td>
            <td class="font-mono text-info">${prec}%</td>
            <td class="font-mono text-primary">${rec}%</td>
            <td class="font-mono text-warning fw-bold">${f1}%</td>
            <td class="font-mono text-muted">${supp}</td>
            <td style="width: 25%;">
                <div class="progress" style="height: 6px; background: rgba(255,255,255,0.08);">
                    <div class="progress-bar bg-success" style="width: ${f1}%"></div>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
}
