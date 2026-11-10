/**
 * Dataset Upload & Batch Prediction Script
 */

let selectedFile = null;

document.addEventListener("DOMContentLoaded", function () {
    const fileInput = document.getElementById("csvFileInput");
    const dropZone = document.getElementById("dropZone");
    const btnPredict = document.getElementById("btnRunPrediction");
    const btnReset = document.getElementById("btnResetUpload");

    if (fileInput) {
        fileInput.addEventListener("change", function (e) {
            if (this.files && this.files[0]) {
                handleFileSelected(this.files[0]);
            }
        });
    }

    if (dropZone) {
        dropZone.addEventListener("dragover", function (e) {
            e.preventDefault();
            this.style.borderColor = "#00f0ff";
            this.style.background = "rgba(0, 240, 255, 0.08)";
        });

        dropZone.addEventListener("dragleave", function (e) {
            e.preventDefault();
            this.style.borderColor = "rgba(0, 240, 255, 0.3)";
            this.style.background = "rgba(0, 240, 255, 0.02)";
        });

        dropZone.addEventListener("drop", function (e) {
            e.preventDefault();
            this.style.borderColor = "rgba(0, 240, 255, 0.3)";
            this.style.background = "rgba(0, 240, 255, 0.02)";
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                handleFileSelected(e.dataTransfer.files[0]);
            }
        });
    }

    if (btnPredict) {
        btnPredict.addEventListener("click", runBatchPrediction);
    }

    if (btnReset) {
        btnReset.addEventListener("click", resetUploadState);
    }
});

function handleFileSelected(file) {
    if (!file.name.endsWith(".csv")) {
        showCyberToast("Invalid File Type", "Please select a valid CSV dataset file.", "error");
        return;
    }

    selectedFile = file;
    const nameEl = document.getElementById("selectedFileName");
    nameEl.style.display = "block";
    nameEl.innerHTML = `<i class="bi bi-file-earmark-check me-1"></i>Selected: <strong>${file.name}</strong> (${(file.size / 1024).toFixed(1)} KB)`;

    // Upload for preview
    const formData = new FormData();
    formData.append("file", file);

    const schemaBadge = document.getElementById("schemaBadge");
    schemaBadge.textContent = "VALIDATING SCHEMA...";
    schemaBadge.className = "badge bg-warning text-dark font-mono";

    fetch("/api/upload/preview", {
        method: "POST",
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            renderSchemaPreview(data);
            document.getElementById("btnRunPrediction").disabled = false;
            showCyberToast("File Validated", `Loaded ${data.rows} flow records for inspection.`, "success");
        } else {
            showCyberToast("Validation Failed", data.error || "Could not validate dataset", "error");
            schemaBadge.textContent = "INVALID SCHEMA";
            schemaBadge.className = "badge bg-danger font-mono";
        }
    })
    .catch(err => {
        console.error(err);
        showCyberToast("Error", "Could not upload file for preview.", "error");
    });
}

function renderSchemaPreview(data) {
    document.getElementById("schemaPlaceholder").style.display = "none";
    document.getElementById("schemaDetails").style.display = "block";

    const schemaBadge = document.getElementById("schemaBadge");
    schemaBadge.textContent = "VALIDATED COMPATIBLE";
    schemaBadge.className = "badge bg-success font-mono";

    document.getElementById("previewRows").textContent = data.rows.toLocaleString();
    document.getElementById("previewCols").textContent = data.columns;
    document.getElementById("previewMatch").textContent = `${data.matched_features} / ${data.total_required} Expected Model Features Matched`;

    // Render Preview Table
    const table = document.getElementById("previewTable");
    table.innerHTML = "";

    if (data.preview && data.preview.length > 0) {
        const thead = document.createElement("thead");
        const headerCols = Object.keys(data.preview[0]).slice(0, 7);
        let headerHtml = "<tr>";
        headerCols.forEach(col => headerHtml += `<th>${col}</th>`);
        headerHtml += "</tr>";
        thead.innerHTML = headerHtml;
        table.appendChild(thead);

        const tbody = document.createElement("tbody");
        data.preview.slice(0, 5).forEach(row => {
            let rowHtml = "<tr>";
            headerCols.forEach(col => rowHtml += `<td>${row[col] !== undefined ? row[col] : '-'}</td>`);
            rowHtml += "</tr>";
            tbody.innerHTML += rowHtml;
        });
        table.appendChild(tbody);
    }
}

function runBatchPrediction() {
    if (!selectedFile) return;

    const btn = document.getElementById("btnRunPrediction");
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Running Random Forest Inference...';

    const formData = new FormData();
    formData.append("file", selectedFile);

    fetch("/api/upload/predict", {
        method: "POST",
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-play-circle-fill"></i> <span>Run AI Model Prediction</span>';

        if (data.success) {
            renderBatchResults(data);
            showCyberToast("Inference Complete", `Processed ${data.total_samples} packet flows!`, "success");
        } else {
            showCyberToast("Prediction Failed", data.error || "Batch prediction error", "error");
        }
    })
    .catch(err => {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-play-circle-fill"></i> <span>Run AI Model Prediction</span>';
        console.error(err);
        showCyberToast("Error", "Server failed during batch inference.", "error");
    });
}

function renderBatchResults(data) {
    const sec = document.getElementById("resultsSection");
    sec.style.display = "block";
    sec.scrollIntoView({ behavior: "smooth" });

    // Counters
    document.getElementById("resTotal").textContent = data.total_samples.toLocaleString();
    document.getElementById("resNormal").textContent = data.normal_samples.toLocaleString();
    document.getElementById("resMalicious").textContent = data.malicious_samples.toLocaleString();
    const ratio = ((data.malicious_samples / data.total_samples) * 100).toFixed(1);
    document.getElementById("resRatio").textContent = `${ratio}%`;

    // Download Button Link
    const dlBtn = document.getElementById("btnDownloadResults");
    dlBtn.href = `/api/download/prediction-results/${data.download_filename}`;

    // Attack Breakdown List
    const atkList = document.getElementById("attackBreakdownList");
    atkList.innerHTML = "";
    for (const [atk, count] of Object.entries(data.attack_breakdown)) {
        const pct = ((count / data.total_samples) * 100).toFixed(1);
        const item = document.createElement("div");
        item.className = "d-flex justify-content-between align-items-center p-2 rounded bg-black";
        item.innerHTML = `
            <span class="${atk === 'Normal Traffic' ? 'text-success' : 'text-danger'} fw-bold">${atk}</span>
            <div class="d-flex align-items-center gap-2">
                <span class="text-light">${count.toLocaleString()}</span>
                <span class="badge bg-secondary font-mono">${pct}%</span>
            </div>
        `;
        atkList.appendChild(item);
    }

    // Severity Breakdown List
    const sevList = document.getElementById("severityBreakdownList");
    sevList.innerHTML = "";
    for (const [sev, count] of Object.entries(data.severity_breakdown)) {
        const pct = ((count / data.total_samples) * 100).toFixed(1);
        const item = document.createElement("div");
        item.className = "d-flex justify-content-between align-items-center p-2 rounded bg-black";
        item.innerHTML = `
            <span class="badge-cyber ${sev.toLowerCase()}">${sev}</span>
            <div class="d-flex align-items-center gap-2">
                <span class="text-light">${count.toLocaleString()}</span>
                <span class="badge bg-secondary font-mono">${pct}%</span>
            </div>
        `;
        sevList.appendChild(item);
    }

    // Table
    const tbody = document.getElementById("resultsTbody");
    tbody.innerHTML = "";
    if (data.results_preview) {
        data.results_preview.forEach((r, idx) => {
            const tr = document.createElement("tr");
            const isAtk = r.predicted_attack !== "Normal Traffic";
            if (isAtk) tr.style.background = "rgba(239, 68, 68, 0.05)";

            tr.innerHTML = `
                <td class="font-mono text-muted">#${idx + 1}</td>
                <td><strong class="${isAtk ? 'text-danger' : 'text-success'}">${r.predicted_attack}</strong></td>
                <td class="font-mono text-info">${r.confidence_score}%</td>
                <td><span class="badge-cyber ${(r.severity || 'Medium').toLowerCase()}">${r.severity || 'Medium'}</span></td>
                <td class="font-mono">${r.flow_duration || 0} ms</td>
                <td class="font-mono">${r.total_fwd_packets || 0}</td>
                <td class="font-mono">${r.total_bwd_packets || 0}</td>
                <td class="font-mono">${r.total_fwd_bytes || 0} B</td>
                <td class="font-mono">${r.total_bwd_bytes || 0} B</td>
                <td class="font-mono">${r.packet_length_mean || 0}</td>
            `;
            tbody.appendChild(tr);
        });
    }
}

function resetUploadState() {
    selectedFile = null;
    document.getElementById("csvFileInput").value = "";
    document.getElementById("selectedFileName").style.display = "none";
    document.getElementById("schemaPlaceholder").style.display = "block";
    document.getElementById("schemaDetails").style.display = "none";
    document.getElementById("resultsSection").style.display = "none";
    document.getElementById("btnRunPrediction").disabled = true;
    const schemaBadge = document.getElementById("schemaBadge");
    schemaBadge.textContent = "AWAITING FILE";
    schemaBadge.className = "badge bg-info font-mono";
}
