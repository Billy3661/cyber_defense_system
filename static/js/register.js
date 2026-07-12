const regPwInput = document.getElementById("regPassword");
const regConfirmInput = document.getElementById("regConfirmPassword");
const strengthBar = document.getElementById("regPwStrengthBar");
const strengthLabel = document.getElementById("regPwStrengthLabel");
const strengthContainer = document.getElementById("pwStrengthContainer");

regPwInput?.addEventListener("input", () => {
    const val = regPwInput.value;
    if (!val) {
        strengthContainer.style.display = "none";
        return;
    }
    strengthContainer.style.display = "block";

    const len = val.length >= 8;
    const upper = /[A-Z]/.test(val);
    const lower = /[a-z]/.test(val);
    const num = /[0-9]/.test(val);
    const sym = /[^a-zA-Z0-9]/.test(val);
    const score = [len, upper, lower, num, sym].filter(Boolean).length;

    const colors = ["#ff4757", "#ff6348", "#ffa502", "#eccc68", "#2ed573"];
    const labels = ["Weak", "Fair", "Medium", "Strong", "Very Strong"];
    const widths = ["20%", "40%", "60%", "80%", "100%"];

    strengthBar.style.width = widths[score - 1] || "10%";
    strengthBar.style.background = colors[score - 1];
    strengthLabel.textContent = "Strength: " + labels[score - 1];
    strengthLabel.style.color = colors[score - 1];
});

function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    const icon = btn.querySelector(".material-symbols-outlined");
    if (input.type === "password") {
        input.type = "text";
        icon.textContent = "visibility_off";
    } else {
        input.type = "password";
        icon.textContent = "visibility";
    }
}

function validateRegisterForm() {
    const pw = regPwInput.value;
    const confirmPw = regConfirmInput.value;
    if (pw !== confirmPw) {
        alert("Passwords do not match!");
        return false;
    }
    if (pw.length < 8) {
        alert("Password must be at least 8 characters long!");
        return false;
    }
    return true;
}
