const TIPS = [
    "Use a password manager to create and store unique, strong passwords for every account.",
    "Enable multi-factor authentication (MFA) on all your critical accounts today.",
    "Never click links in emails — always navigate directly to websites by typing the address.",
    "Keep your operating system and all software up to date to patch security vulnerabilities.",
    "Back up your important data regularly using the 3-2-1 rule: 3 copies, 2 media types, 1 offsite.",
    "Use a VPN when connecting to public WiFi networks to encrypt your traffic.",
    "Be suspicious of urgent requests — attackers create panic to bypass your critical thinking.",
    "Check if your email has been in a data breach at haveibeenpwned.com.",
    "Use HTTPS websites only — look for the padlock icon in your browser address bar.",
    "Regularly review which apps have access to your social media and revoke unused ones.",
];

let tipIndex = 0;
function rotateTip() {
    const el = document.getElementById("tipContent");
    if (!el) return;
    el.style.opacity = "0";
    setTimeout(() => {
        tipIndex = (tipIndex + 1) % TIPS.length;
        el.textContent = TIPS[tipIndex];
        el.style.opacity = "1";
    }, 400);
}
setInterval(rotateTip, 6000);

async function quickScan() {
    const input = document.getElementById("quickScanInput");
    const resultDiv = document.getElementById("quickScanResult");
    const btn = document.getElementById("quickScanBtn");
    const url = input.value.trim();
    if (!url) { input.focus(); return; }

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Scanning...';
    resultDiv.className = "quick-result hidden";

    try {
        const res = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url }),
        });
        const data = await res.json();
        resultDiv.className = "quick-result";
        resultDiv.innerHTML = `
            <div class="quick-verdict" style="border-color: ${data.verdict_color}; color: ${data.verdict_color}; display: flex; align-items: center; gap: 0.5rem;">
                <span class="material-symbols-outlined" style="font-size: 1.5rem;">${data.verdict_icon}</span> <strong>${data.verdict}</strong>
                <span style="color: #8892b0; font-weight: 400; font-size: 0.85rem; margin-left: 1rem;">
                    Risk Score: ${data.risk_percent}/100
                </span>
            </div>
            <a href="/scanner" class="quick-detail-link">View full analysis →</a>`;
    } catch(e) {
        resultDiv.className = "quick-result error";
        resultDiv.textContent = "Scan failed. Please try again.";
    }

    btn.disabled = false;
    btn.innerHTML = '<span class="material-symbols-outlined">search</span> Scan Now';
}

document.getElementById("quickScanInput")?.addEventListener("keydown", e => {
    if (e.key === "Enter") quickScan();
});
