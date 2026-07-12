function switchSection(id, btn) {
    document.querySelectorAll(".awareness-section").forEach(s => s.classList.add("hidden"));
    document.querySelectorAll(".awareness-level-btn").forEach(b => b.classList.remove("active"));
    const target = document.getElementById("section-" + id);
    target.classList.remove("hidden");
    btn.classList.add("active");
    event.preventDefault();
    // Trigger card flip for newly visible cards
    setTimeout(() => {
        target.querySelectorAll('.awareness-card').forEach(c => {
            if (!c.classList.contains('flipped')) {
                c.classList.add('flip-card');
                c.style.transitionDelay = '0s';
                requestAnimationFrame(() => c.classList.add('flipped'));
            }
        });
    }, 50);
}

// Password strength checker
const pwInput = document.getElementById("pwTestInput");
if (pwInput) {
    pwInput.addEventListener("input", () => {
        const pw = pwInput.value;
        const len = pw.length >= 12;
        const upper = /[A-Z]/.test(pw);
        const lower = /[a-z]/.test(pw);
        const num = /[0-9]/.test(pw);
        const sym = /[^a-zA-Z0-9]/.test(pw);
        const score = [len, upper, lower, num, sym].filter(Boolean).length;

        const colors = ["#ff4757", "#ff6348", "#ffa502", "#eccc68", "#2ed573"];
        const labels = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"];
        const widths = ["20%", "40%", "60%", "80%", "100%"];

        const bar = document.getElementById("pwStrengthBar");
        bar.style.width = pw.length ? widths[score - 1] || "10%" : "0%";
        bar.style.background = pw.length ? colors[score - 1] : "transparent";
        document.getElementById("pwStrengthLabel").textContent = pw.length ? labels[score - 1] : "Enter a password above";
        document.getElementById("pwStrengthLabel").style.color = pw.length ? colors[score - 1] : "#8892b0";

        const setCriteria = (id, met) => {
            const el = document.getElementById(id);
            el.textContent = (met ? "✓" : "✗") + " " + el.textContent.slice(2);
            el.className = "criteria-item " + (met ? "met" : "");
        };
        setCriteria("cLen", len);
        setCriteria("cUpper", upper);
        setCriteria("cLower", lower);
        setCriteria("cNum", num);
        setCriteria("cSym", sym);
    });
}

function togglePwVisibility() {
    const inp = document.getElementById("pwTestInput");
    const btn = document.getElementById("visibilityToggleBtn");
    if (inp.type === "password") {
        inp.type = "text";
        btn.textContent = "visibility_off";
    } else {
        inp.type = "password";
        btn.textContent = "visibility";
    }
}

// ── Daily Streak ──
(function() {
    const STREAK_KEY = "securix_daily_streak";
    const today = new Date().toDateString();
    let streakData;
    try { streakData = JSON.parse(localStorage.getItem(STREAK_KEY)) || { count: 0, last: "" }; }
    catch { streakData = { count: 0, last: "" }; }

    if (streakData.last !== today) {
        const yesterday = new Date(Date.now() - 86400000).toDateString();
        if (streakData.last === yesterday) { streakData.count++; }
        else { streakData.count = 1; }
        streakData.last = today;
        localStorage.setItem(STREAK_KEY, JSON.stringify(streakData));
    }

    const el = document.getElementById("dailyStreakDisplay");
    if (el) {
        const c = streakData.count;
        el.textContent = c + " day" + (c !== 1 ? "s" : "");
    }
})();

// ── Daily Security Tip ──
(function() {
    const tips = [
        "Never reuse passwords across multiple sites — use a password manager.",
        "Enable 2FA on every account that supports it.",
        "Phishing emails often create urgency — pause before clicking.",
        "Public WiFi is a hotspot for attackers — always use a VPN.",
        "Lock your screen every time you step away from your desk.",
        "Update your software promptly — patches fix known vulnerabilities.",
        "Backup critical files using the 3-2-1 rule: 3 copies, 2 media, 1 offsite.",
        "Review app permissions regularly — revoke what you don't use.",
        "If a deal sounds too good to be true, it's probably a scam.",
        "Use unique email aliases for different services to reduce tracking.",
        "Don't plug unknown USB drives into your computer.",
        "Verify the sender before acting on unexpected email requests.",
        "Use ad-blockers to reduce the risk of malvertising.",
        "Check for HTTPS before entering sensitive data on any website.",
        "Log out of accounts on shared or public devices.",
    ];
    const dayOfYear = Math.floor((new Date() - new Date(new Date().getFullYear(), 0, 0)) / 86400000);
    const el = document.getElementById("dailyTipDisplay");
    if (el) el.textContent = tips[dayOfYear % tips.length];
})();

// ── Interactive Checklist ──
(function() {
    const CHECKLIST_KEY = "securix_checklist";
    function getChecks() { try { return JSON.parse(localStorage.getItem(CHECKLIST_KEY)) || {}; } catch { return {}; } }
    function saveChecks(checks) { localStorage.setItem(CHECKLIST_KEY, JSON.stringify(checks)); }

    const items = document.querySelectorAll(".check-item-label");
    const total = items.length;
    let checks = getChecks();
    let prevMilestone = -1;

    items.forEach((label, i) => {
        const cb = label.querySelector("input[type=checkbox]");
        const key = label.dataset.key || "item_" + i;
        if (checks[key]) cb.checked = true;
        cb.addEventListener("change", () => {
            checks[key] = cb.checked;
            saveChecks(checks);
            updateProgress();
            if (cb.checked) {
                const done = Object.values(checks).filter(Boolean).length;
                const pct = Math.round((done / total) * 100);
                if (pct > 0 && pct % 25 === 0 && pct !== prevMilestone) {
                    prevMilestone = pct;
                    spawnConfetti(pct);
                }
            }
        });
    });

    function updateProgress() {
        const done = Object.values(checks).filter(Boolean).length;
        const pct = Math.round((done / total) * 100);
        const bar = document.getElementById("checklistBar");
        const txt = document.getElementById("checklistProgressText");
        if (bar) bar.style.width = pct + "%";
        if (txt) txt.textContent = done + " of " + total + " completed";
    }

    function spawnConfetti(milestone) {
        const c = document.getElementById("confettiContainer");
        if (!c) return;
        const colors = ["#f59e0b","#ef4444","#3b82f6","#10b981","#8b5cf6","#ec4899"];
        const count = milestone === 100 ? 80 : 40;
        for (let i = 0; i < count; i++) {
            const p = document.createElement("div");
            p.style.cssText = "position:absolute;width:"+(Math.random()*6+4)+"px;height:"+(Math.random()*6+4)+"px;border-radius:2px;left:"+(Math.random()*100)+"%;top:"+(Math.random()*30+10)+"%;background:"+colors[Math.floor(Math.random()*colors.length)]+";animation:confettiFall "+(Math.random()*1+1)+"s ease-out forwards;animation-delay:"+(Math.random()*0.3)+"s";
            c.appendChild(p);
            setTimeout(() => p.remove(), 2500);
        }
    }

    updateProgress();

    if (!document.getElementById("confettiKeyframes")) {
        const s = document.createElement("style");
        s.id = "confettiKeyframes";
        s.textContent = "@keyframes confettiFall{0%{opacity:1;transform:translateY(0) rotate(0deg) scale(1)}100%{opacity:0;transform:translateY(400px) rotate(720deg) scale(0.3)}}";
        document.head.appendChild(s);
    }
})();
