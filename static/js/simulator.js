let emails = [];
let currentIndex = -1;
let score = 0;
let answeredCount = 0;
const answeredIds = new Set();
let decisionTimestamps = {};
let sessionId = 'session_' + Date.now();
let useAIEmails = false;

// Streak tracking
let currentStreak = 0;
let bestStreak = 0;

// Timed mode
let timedMode = false;
let timerInterval = null;
let timeRemaining = 0;
const TIMER_SECONDS = 20;

document.addEventListener("DOMContentLoaded", () => {
    loadStaticEmails();
    loadMyStats();
});

function toggleTimedMode() {
    timedMode = !timedMode;
    const btn = document.getElementById("timedModeBtn");
    const timerDisplay = document.getElementById("timerDisplay");
    const sidebarTimer = document.getElementById("sidebarTimer");
    if (timedMode) {
        btn.style.borderColor = "var(--warning)";
        btn.style.color = "var(--warning)";
        timerDisplay.style.display = "inline";
        sidebarTimer.style.display = "block";
        if (currentIndex >= 0 && !answeredIds.has(emails[currentIndex].id)) {
            startTimer();
        }
    } else {
        btn.style.borderColor = "";
        btn.style.color = "";
        timerDisplay.style.display = "none";
        sidebarTimer.style.display = "none";
        if (timerInterval) {
            clearInterval(timerInterval);
            timerInterval = null;
        }
    }
}

function startTimer() {
    if (!timedMode) return;
    stopTimer();
    timeRemaining = TIMER_SECONDS;
    updateTimerDisplay();
    timerInterval = setInterval(() => {
        timeRemaining--;
        updateTimerDisplay();
        if (timeRemaining <= 0) {
            stopTimer();
            if (!answeredIds.has(emails[currentIndex].id)) {
                makeDecision(null);
            }
        }
    }, 1000);
}

function stopTimer() {
    if (timerInterval) {
        clearInterval(timerInterval);
        timerInterval = null;
    }
}

function updateTimerDisplay() {
    const display = document.getElementById("timerDisplay");
    const bar = document.getElementById("sidebarTimerBar");
    display.textContent = "\u23F1 " + timeRemaining + "s";
    if (timeRemaining <= 5) {
        display.style.color = "var(--error)";
    } else {
        display.style.color = "var(--warning)";
    }
    if (bar) {
        bar.style.width = (timeRemaining / TIMER_SECONDS * 100) + "%";
        if (timeRemaining <= 5) {
            bar.style.background = "var(--error)";
        } else {
            bar.style.background = "var(--warning)";
        }
    }
}

async function loadStaticEmails() {
    document.getElementById("generationStatus").textContent = "Loading built-in emails...";
    useAIEmails = false;
    try {
        const res = await fetch("/api/simulator/emails");
        emails = await res.json();
        resetSession();
        document.getElementById("generationStatus").textContent = "Built-in set loaded (" + emails.length + " emails)";
    } catch (err) {
        console.error("Failed to load emails:", err);
        document.getElementById("generationStatus").textContent = "Failed to load emails";
    }
}

async function generateNewSession() {
    const difficulty = document.getElementById("difficultySelect").value;
    const count = parseInt(document.getElementById("countSelect").value);
    const status = document.getElementById("generationStatus");
    status.textContent = "Generating " + count + " " + difficulty + " emails with AI...";
    useAIEmails = true;

    try {
        const res = await fetch("/api/simulator/generate", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({count, difficulty})
        });
        const data = await res.json();

        if (data.error) {
            status.textContent = "AI generation failed: " + data.error;
            if (data.raw) console.error("Raw AI output:", data.raw);
            return;
        }

        if (data.emails && data.emails.length > 0) {
            emails = data.emails.map((e, i) => ({...e, id: e.id || (i + 1)}));
            resetSession();
            status.textContent = "AI generated " + emails.length + " emails (" + difficulty + ")";
        } else {
            status.textContent = "AI returned no emails. Try again.";
        }
    } catch (err) {
        status.textContent = "Network error during generation.";
        console.error(err);
    }
}

function resetSession() {
    currentIndex = -1;
    score = 0;
    answeredCount = 0;
    answeredIds.clear();
    decisionTimestamps = {};
    sessionId = 'session_' + Date.now();
    currentStreak = 0;
    bestStreak = 0;
    stopTimer();
    updateStreakDisplay();
    document.getElementById("currentScore").textContent = "0";
    document.getElementById("inboxCount").textContent = emails.length;
    document.getElementById("totalQuestions").textContent = emails.length;
    document.getElementById("emptyState").classList.remove("hidden");
    document.getElementById("emailView").classList.add("hidden");
    document.getElementById("feedbackPanel").classList.add("hidden");
    renderEmailList();
    if (emails.length > 0) selectEmail(0);
}

function renderEmailList() {
    const list = document.getElementById("emailList");
    list.innerHTML = emails.map((email, idx) => {
        const isAnswered = answeredIds.has(email.id);
        const activeClass = idx === currentIndex ? "active" : "";
        const answeredIcon = isAnswered
            ? `<span class="material-symbols-outlined mail-status" style="color: var(--success);">done</span>`
            : `<span class="material-symbols-outlined mail-status" style="color: var(--text-muted);">mail</span>`;
        return `
            <div class="email-item ${activeClass} ${isAnswered ? 'answered' : ''}" onclick="selectEmail(${idx})">
                ${answeredIcon}
                <div class="email-item-content">
                    <div class="email-item-sender">${escapeHTML(email.sender_name)}</div>
                    <div class="email-item-subject">${escapeHTML(email.subject)}</div>
                    <div class="email-item-date">${email.date || ''}</div>
                </div>
            </div>
        `;
    }).join("");
}

function selectEmail(idx) {
    if (idx < 0 || idx >= emails.length) return;
    currentIndex = idx;
    const items = document.querySelectorAll(".email-item");
    items.forEach((item, i) => item.classList.toggle("active", i === idx));

    const email = emails[idx];
    document.getElementById("emptyState").classList.add("hidden");
    document.getElementById("emailView").classList.remove("hidden");

    document.getElementById("viewSubject").textContent = email.subject;
    document.getElementById("viewSenderName").textContent = email.sender_name;
    document.getElementById("viewSenderEmail").textContent = email.sender_email;
    document.getElementById("viewDate").textContent = email.date || '';
    document.getElementById("viewBody").innerHTML = email.body_html;

    if (!decisionTimestamps[email.id]) {
        decisionTimestamps[email.id] = { viewedAt: Date.now() };
    }

    const isAnswered = answeredIds.has(email.id);
    if (isAnswered) {
        showFeedback(email, false);
        stopTimer();
    } else {
        document.getElementById("decisionPanel").classList.remove("hidden");
        document.getElementById("feedbackPanel").classList.add("hidden");
        startTimer();
    }
}

function makeDecision(selectedPhishing) {
    const email = emails[currentIndex];
    if (answeredIds.has(email.id)) return;

    answeredIds.add(email.id);
    answeredCount++;
    stopTimer();

    if (selectedPhishing === null) {
        currentStreak = 0;
        updateStreakDisplay();
        document.getElementById("currentScore").textContent = score;
        const timing = decisionTimestamps[email.id] || {};
        const responseTime = timing.viewedAt ? Date.now() - timing.viewedAt : TIMER_SECONDS * 1000;
        renderEmailList();
        showFeedback(email, true, false);
        fetch("/api/phishing/stats", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                email_id: String(email.id),
                campaign_id: 0,
                is_phishing: email.is_phishing,
                identified_correctly: false,
                response_time_ms: responseTime,
                red_flags_identified: 0,
                total_red_flags: (email.red_flags && email.red_flags.length) || 0,
                session_id: sessionId
            })
        }).then(() => loadMyStats()).catch(() => {});
        fetchDebrief(email, false, false);
        return;
    }

    const correct = email.is_phishing === selectedPhishing;

    if (correct) {
        currentStreak++;
        if (currentStreak > bestStreak) bestStreak = currentStreak;
        score += Math.min(currentStreak, 5);
        document.getElementById("currentScore").textContent = score;
        spawnConfetti();
        updateStreakDisplay();
    } else {
        currentStreak = 0;
        updateStreakDisplay();
        const pane = document.getElementById("emailPane");
        pane.classList.remove("shake");
        void pane.offsetWidth;
        pane.classList.add("shake");
    }

    const timing = decisionTimestamps[email.id] || {};
    const responseTime = timing.viewedAt ? Date.now() - timing.viewedAt : 0;
    const totalFlags = (email.red_flags && email.red_flags.length) || 0;
    const flagsIdentified = correct ? totalFlags : 0;

    renderEmailList();
    showFeedback(email, true, correct);

    fetch("/api/phishing/stats", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            email_id: String(email.id),
            campaign_id: 0,
            is_phishing: email.is_phishing,
            identified_correctly: correct,
            response_time_ms: responseTime,
            red_flags_identified: flagsIdentified,
            total_red_flags: totalFlags,
            session_id: sessionId
        })
    }).then(() => loadMyStats()).catch(() => {});

    fetchDebrief(email, selectedPhishing, correct);
}

function spawnConfetti() {
    const container = document.getElementById("confettiContainer");
    const colors = ["#f59e0b", "#ef4444", "#3b82f6", "#10b981", "#8b5cf6", "#ec4899"];
    for (let i = 0; i < 40; i++) {
        const piece = document.createElement("div");
        piece.className = "confetti-piece";
        piece.style.left = (Math.random() * 100) + "%";
        piece.style.top = (Math.random() * 30 + 10) + "%";
        piece.style.background = colors[Math.floor(Math.random() * colors.length)];
        piece.style.width = (Math.random() * 6 + 4) + "px";
        piece.style.height = (Math.random() * 6 + 4) + "px";
        piece.style.animationDuration = (Math.random() * 1 + 1) + "s";
        piece.style.animationDelay = (Math.random() * 0.3) + "s";
        container.appendChild(piece);
        setTimeout(() => piece.remove(), 2500);
    }
}

function updateStreakDisplay() {
    const el = document.getElementById("streakDisplay");
    const streakCount = document.getElementById("streakCount");
    const multiplier = document.getElementById("comboMultiplier");
    const indicator = document.getElementById("streakIndicator");

    streakCount.textContent = currentStreak;
    const combo = Math.min(currentStreak, 5);
    multiplier.textContent = "x" + Math.max(combo, 1);

    if (currentStreak >= 2) {
        el.style.display = "flex";
        indicator.style.display = "inline";
    } else {
        el.style.display = "none";
        indicator.style.display = "none";
    }
}

async function fetchDebrief(email, userAnsweredPhishing, correct) {
    try {
        const res = await fetch("/api/simulator/debrief", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({
                email: {
                    subject: email.subject,
                    sender_name: email.sender_name,
                    sender_email: email.sender_email,
                    is_phishing: email.is_phishing
                },
                userAnsweredPhishing,
                correct
            })
        });
        const data = await res.json();
        const debriefContainer = document.getElementById("debriefContainer");
        const debriefText = document.getElementById("debriefText");
        if (data.debrief) {
            debriefText.textContent = data.debrief;
            debriefContainer.classList.remove("hidden");
        }
    } catch (err) {}
}

function showFeedback(email, animate, correct = null) {
    document.getElementById("decisionPanel").classList.add("hidden");
    document.getElementById("debriefContainer").classList.add("hidden");

    const feedbackPanel = document.getElementById("feedbackPanel");
    feedbackPanel.classList.remove("hidden");

    const feedbackIcon = document.getElementById("feedbackIcon");
    const feedbackTitle = document.getElementById("feedbackTitle");
    const feedbackDesc = document.getElementById("feedbackDesc");
    const redFlagsContainer = document.getElementById("redFlagsContainer");
    const redFlagsList = document.getElementById("redFlagsList");

    if (correct !== null) {
        if (correct) {
            feedbackIcon.textContent = "check_circle";
            feedbackIcon.style.color = "var(--success)";
            feedbackTitle.textContent = "Correct! Well spotted.";
            feedbackTitle.style.color = "var(--success)";
            if (currentStreak >= 3) {
                feedbackTitle.textContent = "Correct! \uD83D\uDD25 " + currentStreak + " in a row!";
            } else if (currentStreak >= 2) {
                feedbackTitle.textContent = "Correct! \uD83D\uDD25 Streak continues!";
            }
        } else {
            feedbackIcon.textContent = "cancel";
            feedbackIcon.style.color = "var(--error)";
            feedbackTitle.textContent = "Incorrect. You fell for the bait!";
            feedbackTitle.style.color = "var(--error)";
        }
    } else {
        feedbackIcon.textContent = "info";
        feedbackIcon.style.color = "var(--info)";
        feedbackTitle.textContent = "Reviewing Email Analysis";
        feedbackTitle.style.color = "var(--text)";
    }

    feedbackDesc.textContent = email.explanation || '';

    if (email.is_phishing && email.red_flags && email.red_flags.length > 0) {
        redFlagsContainer.classList.remove("hidden");
        redFlagsList.innerHTML = email.red_flags.map(f => `
            <li>
                <strong>Target:</strong> <code class="highlight-warn">${escapeHTML(f.target)}</code>
                <div style="margin-top: 0.25rem;">${escapeHTML(f.reason)}</div>
            </li>
        `).join("");
    } else {
        redFlagsContainer.classList.add("hidden");
    }

    if (animate) {
        feedbackPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
}

function nextEmail() {
    if (currentIndex < emails.length - 1) {
        selectEmail(currentIndex + 1);
    } else {
        showSummary();
    }
}

function showSummary() {
    const total = emails.length;
    const accuracy = total > 0 ? Math.round((score / total) * 100) : 0;
    const avgTime = calculateAvgTime();

    document.getElementById("summaryScore").textContent = score + "/" + total;
    document.getElementById("summaryAccuracy").textContent = accuracy + "%";
    document.getElementById("summaryStreak").textContent = bestStreak;
    document.getElementById("summaryAvgTime").textContent = avgTime + "s";

    let msg = "";
    if (accuracy >= 90) {
        msg = "Outstanding! You're a phishing detection expert. \uD83C\uDFC6 Keep training to maintain your edge!";
    } else if (accuracy >= 70) {
        msg = "Great job! You have a solid eye for threats. A bit more practice and you'll be elite.";
    } else if (accuracy >= 50) {
        msg = "Good effort! You're catching some threats but there's room to improve. Focus on sender addresses and urgency cues.";
    } else {
        msg = "Keep practicing! Phishing detection is a skill that improves with time. Pay attention to red flags like mismatched domains and urgent language.";
    }
    if (bestStreak >= 5) {
        msg += " And that " + bestStreak + "-email streak was impressive! \uD83D\uDD25";
    }
    document.getElementById("summaryMessage").textContent = msg;

    if (accuracy >= 90) {
        spawnConfetti();
        setTimeout(spawnConfetti, 500);
    }

    document.getElementById("summaryModal").classList.remove("hidden");
}

function closeSummary() {
    document.getElementById("summaryModal").classList.add("hidden");
}

function calculateAvgTime() {
    const times = Object.values(decisionTimestamps).filter(t => t.viewedAt);
    if (times.length === 0) return "0";
    const total = times.reduce((sum, t, i) => {
        if (i === 0) return 0;
        return sum + (t.viewedAt - times[i - 1].viewedAt);
    }, 0);
    return Math.round(total / Math.max(times.length - 1, 1) / 1000);
}

// ── Stats & Leaderboard ──

async function loadMyStats() {
    try {
        const res = await fetch("/api/phishing/my-stats");
        const data = await res.json();
        if (data.error) return;

        document.getElementById("statTotal").textContent = data.total;
        document.getElementById("statCorrect").textContent = data.correct;
        document.getElementById("statAccuracy").textContent = data.accuracy + "%";
        document.getElementById("statBadges").textContent = data.badges ? data.badges.length : 0;
        document.getElementById("statsBar").style.display = "flex";

        updateLiveRank();
    } catch (err) {}
}

async function updateLiveRank() {
    try {
        const res = await fetch("/api/phishing/leaderboard");
        const lb = await res.json();
        const leaderboard = lb.leaderboard || [];
        const username = (typeof SIMULATOR_USERNAME !== 'undefined') ? SIMULATOR_USERNAME : '';
        const idx = leaderboard.findIndex(u => u.username === username);
        document.getElementById("liveRank").textContent = idx >= 0 ? "#" + (idx + 1) : "-";
    } catch (err) {}
}

async function toggleLeaderboard() {
    const modal = document.getElementById("leaderboardModal");
    if (modal.classList.contains("hidden")) {
        modal.classList.remove("hidden");
        await loadLeaderboard();
    } else {
        modal.classList.add("hidden");
    }
}

async function loadLeaderboard() {
    const content = document.getElementById("leaderboardContent");
    const badgeDisplay = document.getElementById("badgeDisplay");
    try {
        const [lbRes, statsRes, badgesRes] = await Promise.all([
            fetch("/api/phishing/leaderboard"),
            fetch("/api/phishing/my-stats"),
            fetch("/api/badges")
        ]);
        const lb = await lbRes.json();
        const stats = await statsRes.json();
        const badgeDefs = await badgesRes.json();

        const username = (typeof SIMULATOR_USERNAME !== 'undefined') ? SIMULATOR_USERNAME : '';

        let html = '<h3 style="font-size: 0.95rem; margin-bottom: 0.75rem;">Accuracy Rankings</h3>';
        html += '<table style="width:100%; border-collapse:collapse; font-size:0.85rem;">';
        html += '<thead><tr style="border-bottom:1px solid rgba(255,255,255,0.05);"><th style="padding:0.4rem 0.5rem;text-align:left;color:var(--text-muted);">#</th><th style="padding:0.4rem 0.5rem;text-align:left;color:var(--text-muted);">User</th><th style="padding:0.4rem 0.5rem;text-align:right;color:var(--text-muted);">Accuracy</th><th style="padding:0.4rem 0.5rem;text-align:right;color:var(--text-muted);">Attempts</th></tr></thead><tbody>';
        (lb.leaderboard || []).forEach((u, i) => {
            const isMe = u.username === username;
            html += `<tr style="border-bottom:1px solid rgba(255,255,255,0.03);${isMe ? 'background:rgba(59,130,246,0.08);' : ''}">
                <td style="padding:0.4rem 0.5rem;">${i + 1}</td>
                <td style="padding:0.4rem 0.5rem;font-weight:500;">${escapeHTML(u.username)}${isMe ? ' (you)' : ''}</td>
                <td style="padding:0.4rem 0.5rem;text-align:right;color:${u.accuracy >= 90 ? 'var(--success)' : u.accuracy >= 70 ? 'var(--warning)' : 'var(--text-secondary)'};">${u.accuracy}%</td>
                <td style="padding:0.4rem 0.5rem;text-align:right;color:var(--text-muted);">${u.total_attempts}</td>
            </tr>`;
        });
        html += '</tbody></table>';

        html += '<h3 style="font-size:0.95rem; margin:1.25rem 0 0.75rem;">Badge Rankings</h3>';
        html += '<table style="width:100%; border-collapse:collapse; font-size:0.85rem;">';
        html += '<thead><tr style="border-bottom:1px solid rgba(255,255,255,0.05);"><th style="padding:0.4rem 0.5rem;text-align:left;color:var(--text-muted);">#</th><th style="padding:0.4rem 0.5rem;text-align:left;color:var(--text-muted);">User</th><th style="padding:0.4rem 0.5rem;text-align:right;color:var(--text-muted);">Badges</th><th style="padding:0.4rem 0.5rem;text-align:right;color:var(--text-muted);">Accuracy</th></tr></thead><tbody>';
        (lb.badge_leaderboard || []).forEach((u, i) => {
            html += `<tr style="border-bottom:1px solid rgba(255,255,255,0.03);">
                <td style="padding:0.4rem 0.5rem;">${i + 1}</td>
                <td style="padding:0.4rem 0.5rem;font-weight:500;">${escapeHTML(u.username)}</td>
                <td style="padding:0.4rem 0.5rem;text-align:right;color:var(--warning);">${u.badge_count}</td>
                <td style="padding:0.4rem 0.5rem;text-align:right;color:var(--text-muted);">${u.accuracy}%</td>
            </tr>`;
        });
        html += '</tbody></table>';
        content.innerHTML = html;

        if (stats.badges && stats.badges.length > 0) {
            badgeDisplay.innerHTML = stats.badges.map(b => {
                const label = badgeDefs[b.badge_id] || b.badge_id;
                return `<span style="padding:0.3rem 0.6rem;border-radius:20px;background:rgba(245,158,11,0.12);border:1px solid rgba(245,158,11,0.2);color:var(--warning);font-size:0.8rem;" title="${escapeHTML(label)}">
                    <span class="material-symbols-outlined" style="font-size:0.85rem;vertical-align:middle;">military_tech</span> ${escapeHTML(label)}
                </span>`;
            }).join('');
        } else {
            badgeDisplay.innerHTML = '<span style="color:var(--text-muted);font-size:0.85rem;">No badges yet. Keep analyzing emails!</span>';
        }
    } catch (err) {
        content.innerHTML = '<p style="color:var(--error);">Failed to load leaderboard.</p>';
    }
}

function escapeHTML(str) {
    if (!str) return '';
    return String(str).replace(/[&<>'"]/g,
        tag => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;',
            "'": '&#39;', '"': '&quot;'
        }[tag] || tag)
    );
}
