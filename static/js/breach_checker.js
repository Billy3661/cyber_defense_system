let currentBreachData = null;
let currentTargetType = "email";

function switchTab(type) {
    const tabEmail = document.getElementById("tabEmailBtn");
    const tabPassword = document.getElementById("tabPasswordBtn");
    const panelEmail = document.getElementById("emailPanel");
    const panelPassword = document.getElementById("passwordPanel");

    document.getElementById("resultsContainer").classList.add("hidden");

    if (type === "email") {
        tabEmail.classList.add("active");
        tabEmail.style.borderBottomColor = "var(--accent)";
        tabEmail.style.color = "#fff";

        tabPassword.classList.remove("active");
        tabPassword.style.borderBottomColor = "transparent";
        tabPassword.style.color = "var(--text-muted)";

        panelEmail.classList.remove("hidden");
        panelPassword.classList.add("hidden");
    } else {
        tabPassword.classList.add("active");
        tabPassword.style.borderBottomColor = "var(--accent)";
        tabPassword.style.color = "#fff";

        tabEmail.classList.remove("active");
        tabEmail.style.borderBottomColor = "transparent";
        tabEmail.style.color = "var(--text-muted)";

        panelPassword.classList.remove("hidden");
        panelEmail.classList.add("hidden");
    }
}

function setEmailExample(email) {
    document.getElementById("checkEmailInput").value = email;
    document.getElementById("checkEmailInput").focus();
}

function togglePasswordVisibility() {
    const input = document.getElementById("checkPasswordInput");
    if (input.type === "password") {
        input.type = "text";
    } else {
        input.type = "password";
    }
}

async function performEmailCheck() {
    const emailInput = document.getElementById("checkEmailInput");
    const email = emailInput.value.trim();
    if (!email) { emailInput.focus(); return; }

    const btn = document.getElementById("emailCheckBtn");
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;margin-right:4px;"></span> Checking...';

    try {
        const res = await fetch("/api/breach/email", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email })
        });
        const data = await res.json();
        if (data.error) {
            alert(data.error);
            btn.disabled = false;
            btn.innerHTML = originalText;
            return;
        }
        currentTargetType = "email";
        if (data.info) {
            const container = document.getElementById("resultsContainer");
            const banner = document.getElementById("verdictBanner");
            const verdictIcon = document.getElementById("verdictIcon");
            const verdictText = document.getElementById("verdictText");
            const verdictTarget = document.getElementById("verdictTarget");
            const detailsPanel = document.getElementById("detailsPanel");
            document.getElementById("scoreCount").textContent = "&mdash;";
            document.getElementById("scoreLabel").textContent = "N/A";
            verdictTarget.textContent = `Target: ${email}`;
            banner.style.borderColor = "var(--info)";
            banner.style.boxShadow = "0 0 40px rgba(59, 130, 246, 0.15)";
            verdictIcon.textContent = "info";
            verdictIcon.style.color = "var(--info)";
            verdictText.textContent = "API Key Required";
            verdictText.style.color = "var(--info)";
            detailsPanel.innerHTML = `
                <h3><span class="material-symbols-outlined" style="font-size: 1.5rem; vertical-align: middle; margin-right: 0.5rem; color: var(--info);">key</span>Email Breach Checking Requires API Key</h3>
                <p style="font-size: 0.9rem; color: var(--text-muted); line-height: 1.5; margin-top: 0.5rem;">${data.info}</p>
            `;
            container.classList.remove("hidden");
            container.scrollIntoView({ behavior: "smooth", block: "start" });
        } else {
            renderEmailResults(email, data);
        }
    } catch (err) {
        alert("Failed to perform breach lookup.");
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}

function renderEmailResults(email, data) {
    const container = document.getElementById("resultsContainer");

    const count = data.breaches.length;
    const clean = count === 0;

    const banner = document.getElementById("verdictBanner");
    const verdictIcon = document.getElementById("verdictIcon");
    const verdictText = document.getElementById("verdictText");
    const verdictTarget = document.getElementById("verdictTarget");
    const scoreCount = document.getElementById("scoreCount");
    const detailsPanel = document.getElementById("detailsPanel");

    verdictTarget.textContent = `Target: ${email}`;
    scoreCount.textContent = count;
    document.getElementById("scoreLabel").textContent = "Exposure(s)";

    currentBreachData = {
        target: email,
        verdict: clean ? "Clean (No breaches found)" : "Exposed (Breaches detected)",
        verdict_color: clean ? "#2ed573" : "#ff4757",
        count: count,
        checks: clean ? [
            { label: "Email Address Database Check", detail: "No compromised records associated with this address." }
        ] : data.breaches.map(b => ({
            label: b.title,
            detail: `${b.date} - Compromised: ${b.compromised.join(", ")}`
        }))
    };

    if (clean) {
        banner.style.borderColor = "var(--success)";
        banner.style.boxShadow = "0 0 40px rgba(46, 213, 115, 0.15)";
        verdictIcon.textContent = "check_circle";
        verdictIcon.style.color = "var(--success)";
        verdictText.textContent = "Good News: Safe!";
        verdictText.style.color = "var(--success)";

        detailsPanel.innerHTML = `
            <h3><span class="material-symbols-outlined" style="font-size: 1.5rem; vertical-align: middle; margin-right: 0.5rem; color: var(--success);">shield</span>Recommendations</h3>
            <ul class="rec-list">
                <li><span class="material-symbols-outlined" style="color: var(--success); font-size: 1.1rem; vertical-align: -2px; margin-right: 6px;">check_circle</span>No data breaches detected in our databases for this address.</li>
                <li><span class="material-symbols-outlined" style="color: var(--accent); font-size: 1.1rem; vertical-align: -2px; margin-right: 6px;">info</span>Stay vigilant and use unique passwords for every service.</li>
            </ul>
        `;
    } else {
        banner.style.borderColor = "var(--error)";
        banner.style.boxShadow = "0 0 40px rgba(255, 71, 87, 0.15)";
        verdictIcon.textContent = "warning";
        verdictIcon.style.color = "var(--error)";
        verdictText.textContent = "Warning: Exposed in breaches!";
        verdictText.style.color = "var(--error)";

        const listHtml = data.breaches.map(b => `
            <div style="border-left: 3px solid var(--error); padding-left: 0.75rem; margin-bottom: 1rem;">
                <h4 style="color: #fff; margin: 0 0 0.25rem 0;">${b.title} (${b.date})</h4>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin: 0 0 0.25rem 0;">${b.details}</p>
                <div style="font-size: 0.8rem;"><strong style="color: var(--warning);">Compromised:</strong> ${b.compromised.join(", ")}</div>
            </div>
        `).join("");

        detailsPanel.innerHTML = `
            <h3><span class="material-symbols-outlined" style="font-size: 1.5rem; vertical-align: middle; margin-right: 0.5rem; color: var(--error);">report</span>Exposed Data Sources</h3>
            <div style="margin-top: 1rem;">
                ${listHtml}
            </div>
            <div style="margin-top: 1.5rem; border-top: 1px solid var(--border); padding-top: 1rem;">
                <h4 style="color: #fff; margin-bottom: 0.5rem;">&#x26a0;&#xfe0f; Immediate Actions Required:</h4>
                <ul class="rec-list">
                    <li>Change the password of the email account and any sites where you used this same email/password combo.</li>
                    <li>Enable Multi-Factor Authentication (MFA/2FA) on all accounts where available.</li>
                    <li>Use a Password Manager to generate and safely store unique, complex passwords.</li>
                </ul>
            </div>
        `;
    }

    container.classList.remove("hidden");
    container.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function performPasswordCheck() {
    const pwInput = document.getElementById("checkPasswordInput");
    const password = pwInput.value;
    if (!password) { pwInput.focus(); return; }

    const btn = document.getElementById("passwordCheckBtn");
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;margin-right:4px;"></span> Verifying...';

    try {
        const sha1 = await sha1Local(password);
        const prefix = sha1.substring(0, 5);
        const suffix = sha1.substring(5);

        const url = `https://api.pwnedpasswords.com/range/${prefix}`;
        const resp = await fetch(url);

        let count = 0;
        if (resp.status === 200) {
            const bodyText = await resp.text();
            const lines = bodyText.split("\n");
            for (let line of lines) {
                const parts = line.trim().split(":");
                if (parts[0] === suffix) {
                    count = parseInt(parts[1], 10);
                    break;
                }
            }
        }

        currentTargetType = "password";
        renderPasswordResults(password.length, count);
    } catch (err) {
        alert("Failed to check HaveIBeenPwned range API. Checking locally offline...");
        try {
            const res = await fetch("/api/breach/password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password })
            });
            const data = await res.json();
            currentTargetType = "password";
            renderPasswordResults(password.length, data.count);
        } catch (e) {
            alert("Could not complete verification.");
        }
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}

async function sha1Local(str) {
    const buffer = new TextEncoder().encode(str);
    const hashBuffer = await crypto.subtle.digest("SHA-1", buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0").toUpperCase()).join("");
}

function renderPasswordResults(len, count) {
    const container = document.getElementById("resultsContainer");
    const clean = count === 0;

    const banner = document.getElementById("verdictBanner");
    const verdictIcon = document.getElementById("verdictIcon");
    const verdictText = document.getElementById("verdictText");
    const verdictTarget = document.getElementById("verdictTarget");
    const scoreCount = document.getElementById("scoreCount");
    const detailsPanel = document.getElementById("detailsPanel");

    verdictTarget.textContent = `Target: [Password Length: ${len}]`;
    scoreCount.textContent = count.toLocaleString();
    document.getElementById("scoreLabel").textContent = "Breach Matches";

    currentBreachData = {
        target: `[Password Checked - Length ${len}]`,
        verdict: clean ? "Clean (No breaches found)" : "Exposed (Breaches detected)",
        verdict_color: clean ? "#2ed573" : "#ff4757",
        count: count,
        checks: [
            { label: "HaveIBeenPwned Range Search", detail: clean ? "Password was not found in database of leaked passwords." : `Password found ${count.toLocaleString()} times in historical data breaches.` }
        ]
    };

    if (clean) {
        banner.style.borderColor = "var(--success)";
        banner.style.boxShadow = "0 0 40px rgba(46, 213, 115, 0.15)";
        verdictIcon.textContent = "check_circle";
        verdictIcon.style.color = "var(--success)";
        verdictText.textContent = "Safe: Password is Clean!";
        verdictText.style.color = "var(--success)";

        detailsPanel.innerHTML = `
            <h3><span class="material-symbols-outlined" style="font-size: 1.5rem; vertical-align: middle; margin-right: 0.5rem; color: var(--success);">shield</span>Password Analysis</h3>
            <ul class="rec-list">
                <li><span class="material-symbols-outlined" style="color: var(--success); font-size: 1.1rem; vertical-align: -2px; margin-right: 6px;">check_circle</span>This password was not found in any database of known leaked credentials.</li>
                <li><span class="material-symbols-outlined" style="color: var(--accent); font-size: 1.1rem; vertical-align: -2px; margin-right: 6px;">info</span>However, remember to keep your password complex and never reuse it across multiple web sites.</li>
            </ul>
        `;
    } else {
        banner.style.borderColor = "var(--error)";
        banner.style.boxShadow = "0 0 40px rgba(255, 71, 87, 0.15)";
        verdictIcon.textContent = "warning";
        verdictIcon.style.color = "var(--error)";
        verdictText.textContent = "COMPROMISED PASSWORD!";
        verdictText.style.color = "var(--error)";

        detailsPanel.innerHTML = `
            <h3><span class="material-symbols-outlined" style="font-size: 1.5rem; vertical-align: middle; margin-right: 0.5rem; color: var(--error);">report</span>Exposure Alert</h3>
            <p style="font-size: 0.9rem; color: var(--text-muted); line-height: 1.5;">
                This password has been exposed in public databases at least <strong style="color: var(--error);">${count.toLocaleString()} times</strong>. 
                Hackers use lists of previously exposed passwords in automated "credential stuffing" and brute-force attacks to break into accounts.
            </p>
            <div style="margin-top: 1.5rem; border-top: 1px solid var(--border); padding-top: 1rem;">
                <h4 style="color: #fff; margin-bottom: 0.5rem;">&#x26a0;&#xfe0f; Immediate Actions Required:</h4>
                <ul class="rec-list">
                    <li><strong style="color: var(--error);">Stop using this password immediately</strong> for any accounts.</li>
                    <li>Generate a strong, completely random replacement password.</li>
                    <li>Never reuse passwords on different accounts.</li>
                </ul>
            </div>
        `;
    }

    container.classList.remove("hidden");
    container.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function downloadBreachPdf() {
    if (!currentBreachData) return;
    try {
        const btn = document.getElementById("downloadPdfBtn");
        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;margin-right:4px;"></span> Generating...';

        const res = await fetch("/api/report/pdf", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                type: "breach",
                data: currentBreachData
            })
        });

        if (res.ok) {
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `cyberdefense_breach_report.pdf`;
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
