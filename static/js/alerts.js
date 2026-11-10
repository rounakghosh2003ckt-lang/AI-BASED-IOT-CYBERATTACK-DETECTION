/**
 * Security Alerts Management Script
 */

let currentPage = 0;
const pageSize = 20;
let totalAlerts = 0;

document.addEventListener("DOMContentLoaded", function () {
    loadAlerts();

    const btnFilter = document.getElementById("btnFilterAlerts");
    if (btnFilter) {
        btnFilter.addEventListener("click", function () {
            currentPage = 0;
            loadAlerts();
        });
    }

    const searchInput = document.getElementById("searchAlerts");
    if (searchInput) {
        searchInput.addEventListener("keypress", function (e) {
            if (e.key === "Enter") {
                currentPage = 0;
                loadAlerts();
            }
        });
    }

    const btnPrev = document.getElementById("btnPrevPage");
    const btnNext = document.getElementById("btnNextPage");

    if (btnPrev) {
        btnPrev.addEventListener("click", function () {
            if (currentPage > 0) {
                currentPage--;
                loadAlerts();
            }
        });
    }

    if (btnNext) {
        btnNext.addEventListener("click", function () {
            if ((currentPage + 1) * pageSize < totalAlerts) {
                currentPage++;
                loadAlerts();
            }
        });
    }
});

function loadAlerts() {
    const sev = document.getElementById("filterSeverity").value;
    const stat = document.getElementById("filterStatus").value;
    const atk = document.getElementById("filterAttack").value;
    const search = document.getElementById("searchAlerts").value;

    const offset = currentPage * pageSize;
    const url = `/api/alerts?severity=${encodeURIComponent(sev)}&status=${encodeURIComponent(stat)}&attack_type=${encodeURIComponent(atk)}&search=${encodeURIComponent(search)}&limit=${pageSize}&offset=${offset}`;

    fetch(url)
        .then(res => res.json())
        .then(data => {
            if (data.success && data.data) {
                renderAlertsTable(data.data.alerts, data.data.total);
            }
        })
        .catch(err => console.error("Error loading alerts:", err));

    // Refresh counts
    fetch("/api/alerts/counts")
        .then(res => res.json())
        .then(data => {
            if (data.success && data.counts) {
                const c = data.counts;
                const setEl = (id, val) => {
                    const el = document.getElementById(id);
                    if (el) el.textContent = val || 0;
                };
                setEl("countCritical", c.critical_count);
                setEl("countHigh", c.high_count);
                setEl("countMedium", c.medium_count);
                setEl("countNew", c.new_count);
            }
        });
}

function renderAlertsTable(alerts, total) {
    totalAlerts = total;
    document.getElementById("alertsTotalBadge").textContent = `${total} TOTAL ALERTS`;

    const start = total === 0 ? 0 : currentPage * pageSize + 1;
    const end = Math.min((currentPage + 1) * pageSize, total);
    document.getElementById("paginationInfo").textContent = `Showing ${start} to ${end} of ${total} alerts`;

    document.getElementById("btnPrevPage").disabled = currentPage === 0;
    document.getElementById("btnNextPage").disabled = end >= total;

    const tbody = document.getElementById("alertsTbody");
    tbody.innerHTML = "";

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="10" class="text-center text-muted py-4">No matching security alerts found.</td></tr>`;
        return;
    }

    alerts.forEach(a => {
        const tr = document.createElement("tr");

        let statusBadge = "bg-danger";
        if (a.status === "Acknowledged") statusBadge = "bg-warning text-dark";
        if (a.status === "Resolved") statusBadge = "bg-success";

        tr.innerHTML = `
            <td class="font-mono text-muted">#${a.id}</td>
            <td class="font-mono text-muted small">${a.timestamp}</td>
            <td><span class="badge-cyber ${(a.severity || 'medium').toLowerCase()}">${a.severity}</span></td>
            <td>
                <div class="fw-bold text-light">${a.attack_type}</div>
                <div class="text-muted" style="font-size:0.75rem;">${a.details || ''}</div>
            </td>
            <td><span class="ip-badge">${a.source_ip}</span></td>
            <td><span class="ip-badge">${a.destination_ip}</span></td>
            <td class="font-mono text-info">${a.confidence}%</td>
            <td><span class="badge bg-dark font-mono text-secondary">${a.mitre_id || 'N/A'}</span></td>
            <td><span class="badge ${statusBadge} font-mono small">${a.status}</span></td>
            <td>
                <div class="btn-group btn-group-sm">
                    ${a.status === 'New' ? `
                        <button class="btn btn-outline-warning py-0 px-2 font-mono small" onclick="setAlertStatus(${a.id}, 'Acknowledged')">Ack</button>
                    ` : ''}
                    ${a.status !== 'Resolved' ? `
                        <button class="btn btn-outline-success py-0 px-2 font-mono small" onclick="setAlertStatus(${a.id}, 'Resolved')">Resolve</button>
                    ` : `
                        <span class="text-muted small"><i class="bi bi-check2-all text-success"></i> Closed</span>
                    `}
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function setAlertStatus(alertId, newStatus) {
    fetch(`/api/alerts/${alertId}/status`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            showCyberToast("Alert Updated", `Alert #${alertId} marked as ${newStatus}.`, "success");
            loadAlerts();
        }
    });
}

function batchAlertAction(action) {
    if (!confirm(`Are you sure you want to execute '${action.replace('_', ' ').toUpperCase()}' on alerts?`)) {
        return;
    }

    fetch("/api/alerts/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: action })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            showCyberToast("Batch Action Executed", `Alerts updated with action: ${action}`, "success");
            loadAlerts();
        }
    });
}
