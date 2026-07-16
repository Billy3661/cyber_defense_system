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

// ── Breach Filters ──
(function() {
    const filters = document.querySelectorAll(".breach-filter-btn");
    const cards = document.querySelectorAll(".breach-card");
    filters.forEach(btn => {
        btn.addEventListener("click", () => {
            filters.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            const f = btn.dataset.filter;
            cards.forEach(card => {
                const type = card.dataset.type;
                const region = card.dataset.region;
                const match = f === "all" || type === f || (f === "kenya" && region === "kenya");
                card.style.display = match ? "" : "none";
            });
        });
    });
})();

// ── Breach Detail Toggle ──
function toggleBreachDetail(btn) {
    const card = btn.closest(".breach-card");
    const detail = card.querySelector(".breach-detail");
    const icon = btn.querySelector(".material-symbols-outlined");
    if (detail.classList.contains("open")) {
        detail.classList.remove("open");
        btn.classList.remove("open");
        icon.textContent = "expand_more";
    } else {
        detail.classList.add("open");
        btn.classList.add("open");
        icon.textContent = "expand_less";
    }
}
