const CHECKS_META = [
    { label: "HTTPS Secure Connection" },
    { label: "Known Malicious Domain" },
    { label: "URL Shortener" },
    { label: "Suspicious Keywords" },
    { label: "Suspicious TLD" },
    { label: "IP Address as Host" },
    { label: "Excessive Subdomains" },
    { label: "URL Length" },
    { label: "Encoded / Special Characters" },
    { label: "DNS Resolution" },
    { label: "URLhaus Threat Check" },
    { label: "VirusTotal Reputation Check" },
];

const RECOMMENDATIONS = {
    "Malicious": [
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--error);">report</span>Do NOT visit this URL under any circumstances.`,
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--accent);">shield</span>Block this domain in your firewall/security software.`,
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--info);">campaign</span>Report this URL to your IT security team.`,
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--warning);">lock</span>If you've already visited it, run a full malware scan immediately.`,
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--success);">key</span>Change any passwords that may have been entered on this site.`,
    ],
    "Suspicious": [
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--warning);">warning</span>Exercise extreme caution before visiting this URL.`,
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--accent);">search</span>Verify the domain belongs to a legitimate organization.`,
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--info);">phone</span>Contact the sender through a known, trusted channel to verify.`,
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--text-muted);">laptop_mac</span>Use a sandboxed browser or virtual machine if you must visit.`,
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--success);">key</span>Never enter credentials on this site.`,
    ],
    "Potentially Risky": [
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--warning);">info</span>Proceed with caution — some risk indicators detected.`,
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--success);">check_circle</span>Verify the domain reputation independently.`,
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--accent);">lock</span>Ensure the site uses HTTPS before entering any data.`,
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--info);">visibility</span>Watch for unusual behavior after visiting.`,
    ],
    "Likely Safe": [
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--success);">check_circle</span>No major threats detected — appears safe based on our checks.`,
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--accent);">lock</span>Always verify HTTPS is active before submitting sensitive data.`,
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--info);">lightbulb</span>Remember: no automated tool is 100% accurate.`,
        `<span class="material-symbols-outlined" style="font-size: 1.1rem; vertical-align: -2px; margin-right: 6px; color: var(--success);">shield</span>Stay vigilant even on seemingly safe websites.`,
    ],
};

function setExample(url) {
    document.getElementById("scanUrl").value = url;
    document.getElementById("scanUrl").focus();
}

function clearScan() {
    document.getElementById("scanUrl").value = "";
    document.getElementById("resultsContainer").classList.add("hidden");
    document.getElementById("scanProgress").classList.add("hidden");
    document.getElementById("scannerStatusDot").className = "scanner-status-dot";
    document.getElementById("scannerStatusText").textContent = "Ready to scan";
    document.getElementById("mainScanBtn").disabled = false;
    document.getElementById("scanBtnIcon").textContent = "search";
    document.getElementById("scanBtnText").textContent = "Analyze URL";
}

async function performScan() {
    const urlInput = document.getElementById("scanUrl");
    const url = urlInput.value.trim();
    if (!url) { urlInput.focus(); return; }

    const btn = document.getElementById("mainScanBtn");
    const progressEl = document.getElementById("scanProgress");
    const resultsEl = document.getElementById("resultsContainer");
    const checksList = document.getElementById("checksList");
    const progressBar = document.getElementById("progressBar");

    // Reset
    resultsEl.classList.add("hidden");
    checksList.innerHTML = "";
    progressBar.style.width = "0%";

    // Status
    document.getElementById("scannerStatusDot").className = "scanner-status-dot scanning";
    document.getElementById("scannerStatusText").textContent = "Scanning...";
    btn.disabled = true;
    document.getElementById("scanBtnIcon").textContent = "";
    document.getElementById("scanBtnText").innerHTML = '<span class="spinner"></span> Analyzing...';

    // Animate progress
    progressEl.classList.remove("hidden");
    const checks = [...CHECKS_META];
    for (let i = 0; i < checks.length; i++) {
        const li = document.createElement("div");
        li.className = "check-item scanning";
        li.innerHTML = `<span class="check-spinner">⟳</span> ${checks[i].label}`;
        checksList.appendChild(li);
        progressBar.style.width = `${((i + 1) / checks.length) * 100}%`;
        await sleep(120);
    }

    // Call API
    try {
        const res = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });
        const data = await res.json();
        progressEl.classList.add("hidden");
        renderResults(data);
    } catch (err) {
        progressEl.classList.add("hidden");
        alert("Scan failed. Please check your connection and try again.");
    }

    document.getElementById("scannerStatusDot").className = "scanner-status-dot done";
    document.getElementById("scannerStatusText").textContent = "Scan complete";
    btn.disabled = false;
    document.getElementById("scanBtnIcon").textContent = "search";
    document.getElementById("scanBtnText").textContent = "Analyze URL";
}

let currentScanData = null;

function renderResults(data) {
    currentScanData = data;
    const container = document.getElementById("resultsContainer");

    // Verdict Banner
    const banner = document.getElementById("verdictBanner");
    banner.style.borderColor = data.verdict_color;
    banner.style.boxShadow = `0 0 40px ${data.verdict_color}30`;
    document.getElementById("verdictIcon").textContent = data.verdict_icon;
    document.getElementById("verdictText").textContent = data.verdict;
    document.getElementById("verdictText").style.color = data.verdict_color;
    document.getElementById("verdictUrl").textContent = data.url;

    // Score Ring
    const score = data.risk_percent;
    const circumference = 314;
    const offset = circumference - (score / 100) * circumference;
    const fill = document.getElementById("scoreRingFill");
    fill.style.stroke = data.verdict_color;
    fill.style.strokeDashoffset = offset;
    document.getElementById("scoreNumber").textContent = score;
    document.getElementById("scoreNumber").style.color = data.verdict_color;

    // Checks Grid
    const grid = document.getElementById("checksGrid");
    grid.innerHTML = data.checks.map(c => `
        <div class="check-result-card check-${c.status}">
            <div class="check-result-icon">
                ${c.status === "pass" ? '<span class="material-symbols-outlined" style="color: var(--success);">check_circle</span>' : c.status === "fail" ? '<span class="material-symbols-outlined" style="color: var(--error);">cancel</span>' : c.status === "info" ? '<span class="material-symbols-outlined" style="color: var(--accent);">info</span>' : '<span class="material-symbols-outlined" style="color: var(--warning);">warning</span>'}
            </div>
            <div class="check-result-body">
                <div class="check-result-label">${c.label}</div>
                <div class="check-result-detail">${c.detail}</div>
            </div>
        </div>
    `).join("");

    // Recommendations
    const recs = RECOMMENDATIONS[data.verdict] || RECOMMENDATIONS["Likely Safe"];
    document.getElementById("recommendationsPanel").innerHTML = `
        <h3><span class="material-symbols-outlined" style="font-size: 1.5rem; vertical-align: middle; margin-right: 0.5rem; color: var(--accent);">assignment</span>Recommendations</h3>
        <ul class="rec-list">
            ${recs.map(r => `<li>${r}</li>`).join("")}
        </ul>`;

    container.classList.remove("hidden");
    container.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function downloadScanPdf() {
    if (!currentScanData) return;
    try {
        const btn = document.getElementById("downloadPdfBtn");
        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;margin-right:4px;"></span> Generating...';

        const res = await fetch("/api/report/pdf", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                type: "scan",
                data: currentScanData
            })
        });

        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `cyberdefense_scan_report.pdf`;
            document.body.appendChild(a);
            a.click();
            a.remove();
        } else {
            alert("Failed to generate PDF report.");
        }
        btn.disabled = false;
        btn.innerHTML = originalText;
    } catch (err) {
        alert("Error downloading PDF: " + err.message);
        document.getElementById("downloadPdfBtn").disabled = false;
    }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

document.getElementById("scanUrl")?.addEventListener("keydown", e => {
    if (e.key === "Enter") performScan();
});

// ── TAB SWITCHING ──
function switchTab(tab) {
    const urlCard  = document.getElementById("scannerCard");
    const fileCard = document.getElementById("fileScannerCard");
    const netCard  = document.getElementById("networkScannerCard");
    const tabUrl   = document.getElementById("tabUrl");
    const tabFile  = document.getElementById("tabFile");
    const tabNet   = document.getElementById("tabNetwork");
    const infoCards = document.getElementById("urlInfoCards");

    [urlCard, fileCard, netCard].forEach(c => c?.classList.add("hidden"));
    [tabUrl, tabFile, tabNet].forEach(t => t?.classList.remove("active"));

    if (tab === "url") {
        urlCard.classList.remove("hidden");
        tabUrl.classList.add("active");
        infoCards?.classList.remove("hidden");
    } else if (tab === "file") {
        fileCard.classList.remove("hidden");
        tabFile.classList.add("active");
        infoCards?.classList.add("hidden");
    } else {
        netCard.classList.remove("hidden");
        tabNet.classList.add("active");
        infoCards?.classList.add("hidden");
    }
    document.getElementById("resultsContainer").classList.add("hidden");
    document.getElementById("scanProgress").classList.add("hidden");
    document.getElementById("netResults")?.classList.add("hidden");
}

// ── NETWORK SCANNER ──
const NET_SCAN_LABELS = [
    "Detecting local subnet...",
    "Probing 254 addresses...",
    "Checking active hosts...",
    "Scanning open ports...",
    "Identifying services...",
    "Classifying risk levels...",
    "Finalizing results...",
];

async function performNetworkScan() {
    const depth  = document.getElementById("netScanDepth").value;
    const subnet = document.getElementById("netSubnet").value.trim();

    const btn = document.getElementById("netScanBtn");
    btn.disabled = true;
    document.getElementById("netScanBtnIcon").textContent = "";
    document.getElementById("netScanBtnText").innerHTML = '<span class="spinner"></span> Scanning...';
    document.getElementById("netScannerStatusDot").className = "scanner-status-dot scanning";
    document.getElementById("netResults").classList.add("hidden");

    // Show radar animation with rotating labels
    const anim = document.getElementById("netScanAnimation");
    const label = document.getElementById("netScanLabel");
    anim.classList.remove("hidden");
    let li = 0;
    const labelInterval = setInterval(() => {
        label.textContent = NET_SCAN_LABELS[li % NET_SCAN_LABELS.length];
        document.getElementById("netScannerStatusText").textContent = NET_SCAN_LABELS[li % NET_SCAN_LABELS.length];
        li++;
    }, 2000);

    try {
        const res = await fetch("/api/scan-network", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ scan_depth: depth, subnet })
        });
        clearInterval(labelInterval);
        const data = await res.json();
        if (data.error) {
            anim.classList.add("hidden");
            alert("Network scan error: " + data.error);
        } else {
            renderNetworkResults(data);
        }
    } catch (err) {
        clearInterval(labelInterval);
        anim.classList.add("hidden");
        alert("Network scan failed. Please check your connection.");
    }

    document.getElementById("netScannerStatusDot").className = "scanner-status-dot done";
    document.getElementById("netScannerStatusText").textContent = "Scan complete";
    btn.disabled = false;
    document.getElementById("netScanBtnIcon").textContent = "radar";
    document.getElementById("netScanBtnText").textContent = "Discover Network";
}

function renderNetworkResults(data) {
    document.getElementById("netScanAnimation").classList.add("hidden");
    document.getElementById("netResults").classList.remove("hidden");
    document.getElementById("netResultsTitle").innerHTML = `Discovered Hosts — ${data.subnet} <span style="color:var(--accent); font-size:0.9rem; margin-left:0.5rem; background:rgba(59,130,246,0.1); padding:0.2rem 0.6rem; border-radius:50px;"><span class="material-symbols-outlined" style="font-size:1rem; vertical-align:-2px; margin-right:4px;">wifi</span>${data.ssid}</span>`;

    // Summary strip
    document.getElementById("netSummary").innerHTML = `
        <div class="net-summary-grid">
            <div class="net-stat"><div class="net-stat-val">${data.hosts_scanned}</div><div class="net-stat-lbl">IPs Probed</div></div>
            <div class="net-stat"><div class="net-stat-val" style="color:var(--accent)">${data.active_count}</div><div class="net-stat-lbl">Active Hosts</div></div>
            <div class="net-stat"><div class="net-stat-val" style="color:var(--text-muted); font-size:0.85rem; font-family:monospace;">${data.server_ip || '—'}</div><div class="net-stat-lbl">This Server</div></div>
        </div>`;

    // Host cards grid
    const grid = document.getElementById("netHostsGrid");
    if (data.active_hosts.length === 0) {
        grid.innerHTML = `<div style="text-align:center; color:var(--text-muted); padding:2rem; grid-column:1/-1;">
            <span class="material-symbols-outlined" style="font-size:2.5rem; display:block; margin-bottom:0.5rem; color:var(--success);">wifi_off</span>
            No active hosts found on <strong>${data.subnet}</strong>
        </div>`;
    } else {
        grid.innerHTML = data.active_hosts.map(h => {
            const portBadge = h.open_count > 0
                ? `<span class="host-port-count" style="color:${h.risk_color};">${h.open_count} port${h.open_count > 1 ? 's' : ''} open</span>`
                : `<span class="host-port-count" style="color:var(--success);">No open ports</span>`;
            const riskPill = `<span class="host-risk-pill" style="color:${h.risk_color}; border-color:${h.risk_color}40; background:${h.risk_color}12;">${h.risk}</span>`;
            window.hostOpenPorts = window.hostOpenPorts || {};
            window.hostOpenPorts[h.ip] = h.open_ports;
            return `<div class="net-host-card" onclick="showHostPorts('${h.ip}', '${h.hostname.replace(/'/g, "\\'")}')">
                <div class="host-card-header">
                    <span class="material-symbols-outlined" style="font-size:1.8rem; color:var(--accent);">computer</span>
                    ${riskPill}
                </div>
                <div class="host-ip">${h.ip}</div>
                <div class="host-name" title="${h.hostname}">${h.hostname !== h.ip ? h.hostname : 'Unknown host'}</div>
                <div class="host-mac" style="font-size: 0.65rem; color: var(--text-muted); font-family: monospace; margin-top: -2px;">${h.mac || ''}</div>
                ${portBadge}
                <div class="host-card-footer">
                    <span class="material-symbols-outlined" style="font-size:0.9rem; vertical-align:-2px;">zoom_in</span> View ports
                </div>
            </div>`;
        }).join("");
    }
    document.getElementById("netResults").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function showHostPorts(ip, hostname) {
    const openPorts = window.hostOpenPorts[ip] || [];
    document.getElementById("netPortsPanel").classList.remove("hidden");
    document.getElementById("netPortsTitle").textContent = `${ip} — ${hostname !== ip ? hostname : 'Open Ports'}`;
    const tbody = document.getElementById("netPortsBody");
    if (openPorts.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--success); padding:1rem;">
            <span class="material-symbols-outlined" style="vertical-align:-3px; margin-right:4px;">verified</span>
            No open ports detected — host appears secure.
        </td></tr>`;
    } else {
        tbody.innerHTML = openPorts.map(p => `
            <tr>
                <td style="font-family:monospace; font-weight:700; color:var(--accent);">${p.port}</td>
                <td><span style="color:var(--success); font-weight:600;">● OPEN</span></td>
                <td>${p.service}</td>
                <td><span style="color:${p.risk_color}; font-weight:700; font-size:0.78rem; background:${p.risk_color}15; padding:0.15rem 0.55rem; border-radius:50px; border:1px solid ${p.risk_color}40;">${p.risk}</span></td>
                <td style="font-size: 0.75rem; color: var(--text-secondary); max-width: 250px; line-height: 1.3;">${p.remedy || ''}</td>
            </tr>`).join("");
    }
    document.getElementById("netPortsPanel").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function clearNetworkScan() {
    document.getElementById("netResults").classList.add("hidden");
    document.getElementById("netScanAnimation").classList.add("hidden");
    document.getElementById("netPortsPanel").classList.add("hidden");
    document.getElementById("netScannerStatusDot").className = "scanner-status-dot";
    document.getElementById("netScannerStatusText").textContent = "Ready to discover network";
    document.getElementById("netHostsGrid").innerHTML = "";
}

// ── VIRUSTOTAL API KEY CONFIG ──
function toggleVtConfig() {
    const form = document.getElementById("vtConfigForm");
    form.classList.toggle("hidden");
}

async function saveVtKey() {
    const key = document.getElementById("vtApiKeyInput").value.trim();
    const res = await fetch("/api/config/vt-key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key })
    });
    const data = await res.json();
    if (data.status === "success") {
        document.getElementById("vtConfigStatus").textContent = key
            ? "✓ VirusTotal API key saved — live lookups & file uploads enabled."
            : "API key cleared — falling back to heuristic checks.";
        document.getElementById("vtConfigForm").classList.add("hidden");
        document.getElementById("vtApiKeyInput").value = "";
    }
}

async function clearVtKey() {
    document.getElementById("vtApiKeyInput").value = "";
    await fetch("/api/config/vt-key", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: "" })
    });
    document.getElementById("vtConfigStatus").textContent = "No API key configured — currently using heuristic checks.";
    document.getElementById("vtConfigForm").classList.add("hidden");
}

// ── FILE SCANNER ──
let selectedFile = null;

function handleDragOver(event) {
    event.preventDefault();
    document.getElementById("fileDropZone").classList.add("drag-active");
}

function handleDragLeave(event) {
    document.getElementById("fileDropZone").classList.remove("drag-active");
}

function handleFileDrop(event) {
    event.preventDefault();
    document.getElementById("fileDropZone").classList.remove("drag-active");
    const file = event.dataTransfer.files[0];
    if (file) setSelectedFile(file);
}

function handleFileSelect(event) {
    const file = event.target.files[0];
    if (file) setSelectedFile(file);
}

function setSelectedFile(file) {
    selectedFile = file;
    const sizeKb = (file.size / 1024).toFixed(1);
    const sizeMb = (file.size / (1024 * 1024)).toFixed(2);
    document.getElementById("fileInfoName").textContent = file.name;
    document.getElementById("fileInfoSize").textContent = file.size > 1048576 ? `${sizeMb} MB` : `${sizeKb} KB`;
    document.getElementById("fileDropZone").classList.add("hidden");
    document.getElementById("fileSelectedInfo").classList.remove("hidden");
}

function clearFileScan() {
    selectedFile = null;
    document.getElementById("fileInput").value = "";
    document.getElementById("fileDropZone").classList.remove("hidden");
    document.getElementById("fileSelectedInfo").classList.add("hidden");
    document.getElementById("fileScannerStatusDot").className = "scanner-status-dot";
    document.getElementById("fileScannerStatusText").textContent = "Ready to scan files";
    document.getElementById("resultsContainer").classList.add("hidden");
}

async function performFileScan() {
    if (!selectedFile) { alert("Please select a file first."); return; }

    const btn = document.getElementById("fileScanBtn");
    btn.disabled = true;
    document.getElementById("fileScanBtnIcon").textContent = "";
    document.getElementById("fileScanBtnText").innerHTML = '<span class="spinner"></span> Scanning...';
    document.getElementById("fileScannerStatusDot").className = "scanner-status-dot scanning";
    document.getElementById("fileScannerStatusText").textContent = "Analyzing file...";

    const progressEl = document.getElementById("scanProgress");
    const resultsEl = document.getElementById("resultsContainer");
    const checksList = document.getElementById("checksList");
    const progressBar = document.getElementById("progressBar");

    resultsEl.classList.add("hidden");
    checksList.innerHTML = "";
    progressBar.style.width = "0%";

    const fileChecks = [
        { label: "File Size Verification" },
        { label: "Executable & Extension Analysis" },
        { label: "VirusTotal File Reputation Check" },
    ];

    progressEl.classList.remove("hidden");
    for (let i = 0; i < fileChecks.length; i++) {
        const li = document.createElement("div");
        li.className = "check-item scanning";
        li.innerHTML = `<span class="check-spinner">⟳</span> ${fileChecks[i].label}`;
        checksList.appendChild(li);
        progressBar.style.width = `${((i + 1) / fileChecks.length) * 100}%`;
        await sleep(300);
    }

    try {
        const formData = new FormData();
        formData.append("file", selectedFile);

        const res = await fetch("/api/scan-file", {
            method: "POST",
            body: formData
        });
        const data = await res.json();
        progressEl.classList.add("hidden");
        if (data.error) {
            alert("Error: " + data.error);
        } else {
            renderResults(data);
        }
    } catch (err) {
        progressEl.classList.add("hidden");
        alert("File scan failed. Please check your connection and try again.");
    }

    document.getElementById("fileScannerStatusDot").className = "scanner-status-dot done";
    document.getElementById("fileScannerStatusText").textContent = "Scan complete";
    btn.disabled = false;
    document.getElementById("fileScanBtnIcon").textContent = "security";
    document.getElementById("fileScanBtnText").textContent = "Analyze File";
}
