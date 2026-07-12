let currentEmailData = null;

const SAMPLES = {
    safe: `From: Google Security Team <no-reply@accounts.google.com>
Received-SPF: pass (google.com designates 209.85.220.69 as authorized sender)
Authentication-Results: dkim=pass header.i=@google.com; spf=pass; dmarc=pass header.from=google.com
Return-Path: <no-reply@accounts.google.com>
Reply-To: <no-reply@accounts.google.com>`,

    spoofed: `From: PayPal Billing Service <service@paypal.com>
Received-SPF: pass (company.corp designates 192.168.10.45 as authorized sender)
Authentication-Results: dkim=pass header.i=@mass-mailer-marketing.net; dmarc=fail header.from=paypal.com
Return-Path: <support@mass-mailer-marketing.net>
Reply-To: <paypal-resolutions@mass-mailer-marketing.net>`,

    spf_fail: `From: Netflix Billing Helpdesk <billing-update@netflix.com>
Received-SPF: fail (netflix.com does not designate 88.99.112.5 as authorized sender)
Authentication-Results: dkim=fail header.i=@netflix.com; dmarc=fail header.from=netflix.com
Return-Path: <billing-update@netflix.com>`
};

function loadSample(key) {
    document.getElementById("rawHeaders").value = SAMPLES[key];
}

function clearHeaders() {
    document.getElementById("rawHeaders").value = "";
    document.getElementById("resultsContainer").classList.add("hidden");
}

async function performAnalysis() {
    const textarea = document.getElementById("rawHeaders");
    const headers = textarea.value.trim();
    if (!headers) { textarea.focus(); return; }

    const btn = document.getElementById("analyzeBtn");
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;margin-right:4px;"></span> Analyzing...';

    try {
        const res = await fetch("/email-analyzer", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ headers })
        });
        const data = await res.json();
        renderResults(data);
    } catch (err) {
        alert("Failed to analyze email headers. Please check syntax and try again.");
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}

function renderResults(data) {
    currentEmailData = data;
    const container = document.getElementById("resultsContainer");

    // Verdict Banner
    const banner = document.getElementById("verdictBanner");
    banner.style.borderColor = data.verdict_color;
    banner.style.boxShadow = `0 0 40px ${data.verdict_color}30`;
    document.getElementById("verdictIcon").textContent = data.verdict_icon;
    document.getElementById("verdictText").textContent = data.verdict;
    document.getElementById("verdictText").style.color = data.verdict_color;
    document.getElementById("verdictSubject").textContent = `Subject: ${data.headers.subject}`;

    // Score Ring
    const score = data.score;
    const circumference = 314;
    const offset = circumference - (Math.min(score, 100) / 100) * circumference;
    const fill = document.getElementById("scoreRingFill");
    fill.style.stroke = data.verdict_color;
    fill.style.strokeDashoffset = offset;
    document.getElementById("scoreNumber").textContent = score;
    document.getElementById("scoreNumber").style.color = data.verdict_color;

    // Populate Metadata Table
    document.getElementById("metaFrom").textContent = data.headers.from;
    document.getElementById("metaTo").textContent = data.headers.to;
    document.getElementById("metaDate").textContent = data.headers.date;
    document.getElementById("metaReturnPath").textContent = data.headers.return_path || "None";
    document.getElementById("metaReplyTo").textContent = data.headers.reply_to || "None";

    // Populate Alignments & Security Checks
    const verificationGrid = document.getElementById("verificationGrid");
    verificationGrid.innerHTML = data.findings.map(f => `
        <div class="check-result-card check-${f.status}" style="padding: 0.5rem; margin-bottom: 0.25rem;">
            <div class="check-result-icon" style="margin-right: 6px;">
                ${f.status === 'pass' ? '<span class="material-symbols-outlined" style="color: var(--success); font-size: 1.1rem;">check_circle</span>' : f.status === 'fail' ? '<span class="material-symbols-outlined" style="color: var(--error); font-size: 1.1rem;">cancel</span>' : '<span class="material-symbols-outlined" style="color: var(--warning); font-size: 1.1rem;">warning</span>'}
            </div>
            <div class="check-result-body">
                <div class="check-result-label" style="font-size: 0.8rem; font-weight:600;">${f.label}</div>
            </div>
        </div>
    `).join("");

    // Detailed Findings List
    const findingsList = document.getElementById("findingsList");
    findingsList.innerHTML = data.findings.map(f => `
        <div class="check-item ${f.status}" style="border-left: 3px solid ${f.status === 'pass' ? 'var(--success)' : f.status === 'fail' ? 'var(--error)' : 'var(--warning)'}; margin-bottom: 0.75rem; padding-left: 0.5rem;">
            <strong style="display: block; font-size: 0.9rem; color: #fff;">${f.label}</strong>
            <p style="font-size: 0.85rem; color: var(--text-muted); margin: 0.25rem 0 0 0;">${f.detail}</p>
        </div>
    `).join("");

    container.classList.remove("hidden");
    container.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function downloadEmailPdf() {
    if (!currentEmailData) return;
    try {
        const btn = document.getElementById("downloadPdfBtn");
        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;margin-right:4px;"></span> Generating...';

        const res = await fetch("/api/report/pdf", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                type: "email",
                data: currentEmailData
            })
        });

        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `cyberdefense_email_report.pdf`;
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
