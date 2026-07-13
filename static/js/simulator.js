/* ══════════════════════════════════════════════════════════════════
   Securix Phishing Lab — Campaign, Boss Battle, XP & AAR
   ══════════════════════════════════════════════════════════════════ */

let mode = 'campaign';
let emails = [];
let currentIndex = -1;
let score = 0;
let answeredCount = 0;
const answeredIds = new Set();
let decisionTimestamps = {};
let sessionId = 'session_' + Date.now();
let currentStreak = 0;
let bestStreak = 0;
let xpThisRound = 0;

// Campaign state
let currentCampaignId = null;
let campaignData = null;
let roundResults = [];

// Boss state
let bossEmail = null;
let bossDefeated = false;

// XP system
let userXP = 0;
let userRank = { name: 'Intern', icon: 'school', color: '#94a3b8' };

document.addEventListener("DOMContentLoaded", () => {
    loadXPData();
    switchMode('campaign');
});

// ─── Mode Switching ───

function switchMode(m) {
    mode = m;
    document.querySelectorAll('.mode-tab').forEach(t => t.classList.remove('active'));
    document.getElementById('campaignView').style.display = m === 'campaign' ? '' : 'none';
    document.getElementById('practiceView').style.display = m === 'practice' ? '' : 'none';
    document.getElementById('bossView').style.display = m === 'boss' ? '' : 'none';

    if (m === 'campaign') {
        document.getElementById('tabCampaign').classList.add('active');
        loadCampaigns();
    } else if (m === 'practice') {
        document.getElementById('tabPractice').classList.add('active');
        loadStaticEmails();
    } else if (m === 'boss') {
        document.getElementById('tabBoss').classList.add('active');
        loadBossState();
    }
}

// ─── XP & Rank ───

async function loadXPData() {
    try {
        const res = await fetch('/api/simulator/xp');
        const data = await res.json();
        userXP = data.xp;
        userRank = data.rank;
        updateXPBar();
    } catch (e) {}
}

function updateXPBar() {
    const rank = userRank;
    const badge = document.getElementById('rankBadge');
    const icon = document.getElementById('rankIcon');
    const name = document.getElementById('rankName');
    const current = document.getElementById('xpCurrent');
    const fill = document.getElementById('xpFill');
    const nextLabel = document.getElementById('xpNextLabel');
    const certMini = document.getElementById('certBadgeMini');

    badge.style.background = rank.color + '18';
    badge.style.borderColor = rank.color + '40';
    badge.style.color = rank.color;
    icon.textContent = rank.icon;
    name.textContent = rank.name;
    current.textContent = userXP;

    // Calculate fill percentage
    const ranks = [0, 100, 300, 600, 1000];
    const rankNames = ['Intern', 'Analyst', 'Threat Hunter', 'CISO', 'SOC Legend'];
    let currentIdx = 0;
    for (let i = ranks.length - 1; i >= 0; i--) {
        if (userXP >= ranks[i]) { currentIdx = i; break; }
    }
    if (currentIdx < ranks.length - 1) {
        const range = ranks[currentIdx + 1] - ranks[currentIdx];
        const progress = userXP - ranks[currentIdx];
        fill.style.width = (progress / range * 100) + '%';
        nextLabel.textContent = 'Next: ' + rankNames[currentIdx + 1] + ' (' + ranks[currentIdx + 1] + ' XP)';
    } else {
        fill.style.width = '100%';
        nextLabel.textContent = 'Max rank!';
    }
}

// ─── Campaign Mode ───

async function loadCampaigns() {
    try {
        const res = await fetch('/api/simulator/campaigns');
        const data = await res.json();
        renderCampaignGrid(data);
    } catch (e) {}
}

function renderCampaignGrid(data) {
    const grid = document.getElementById('campaignGrid');
    const campaigns = data.campaigns;
    const completedCount = data.completed_count;
    const total = data.total;

    let html = campaigns.map((c, i) => {
        const diffColor = c.difficulty.includes('Easy') ? '#10b981' : c.difficulty.includes('Medium') ? '#f59e0b' : '#ef4444';
        return `
            <div class="campaign-card ${c.completed ? 'completed' : ''}" onclick="startCampaign('${c.id}')">
                <div class="cc-difficulty" style="background: ${diffColor}15; color: ${diffColor}; border: 1px solid ${diffColor}30;">
                    Mission ${i + 1} — ${c.difficulty}
                </div>
                <div class="cc-title">${escapeHTML(c.title)}</div>
                <div class="cc-narrative">${escapeHTML(c.narrative)}</div>
                <div class="cc-meta">
                    <span><span class="material-symbols-outlined" style="font-size: 0.9rem; vertical-align: middle;">mail</span> ${c.email_count} emails</span>
                    <span><span class="material-symbols-outlined" style="font-size: 0.9rem; vertical-align: middle;">bolt</span> +${c.xp_reward} XP</span>
                    <span style="color: var(--text-muted);">${escapeHTML(c.threat_type)}</span>
                </div>
            </div>
        `;
    }).join('');

    html += `<div style="grid-column: 1 / -1; text-align: center; padding: 1.5rem; color: var(--text-muted); font-size: 0.85rem;">
        ${completedCount}/${total} campaigns completed
    </div>`;

    grid.innerHTML = html;
}

async function startCampaign(campaignId) {
    currentCampaignId = campaignId;
    roundResults = [];
    score = 0;
    answeredCount = 0;
    answeredIds.clear();
    decisionTimestamps = {};
    currentStreak = 0;
    bestStreak = 0;
    xpThisRound = 0;
    sessionId = 'session_' + Date.now();

    try {
        const res = await fetch('/api/simulator/campaign/' + campaignId);
        const data = await res.json();
        if (data.error) return;
        campaignData = data;
        emails = data.emails;

        document.getElementById('campaignSelect').style.display = 'none';
        document.getElementById('campaignActive').style.display = '';
        document.getElementById('campaignNarrative').innerHTML = `
            <strong style="color: var(--accent);">${escapeHTML(data.title)}</strong> — ${escapeHTML(data.threat_type)}<br>
            <em>${escapeHTML(data.narrative)}</em>
        `;
        resetSessionCampaign();
    } catch (e) {}
}

function resetSessionCampaign() {
    currentIndex = -1;
    score = 0;
    answeredCount = 0;
    answeredIds.clear();
    decisionTimestamps = {};
    currentStreak = 0;
    bestStreak = 0;
    xpThisRound = 0;
    updateStreakDisplayCampaign();
    document.getElementById('currentScore').textContent = '0';
    document.getElementById('inboxCount').textContent = emails.length;
    document.getElementById('totalQuestions').textContent = emails.length;
    document.getElementById('emptyState').classList.remove('hidden');
    document.getElementById('emailView').classList.add('hidden');
    document.getElementById('feedbackPanel').classList.add('hidden');
    renderEmailListCampaign();
    if (emails.length > 0) selectEmailCampaign(0);
}

function renderEmailListCampaign() {
    const list = document.getElementById('emailList');
    list.innerHTML = emails.map((email, idx) => {
        const isAnswered = answeredIds.has(email.id);
        const activeClass = idx === currentIndex ? 'active' : '';
        const icon = isAnswered
            ? `<span class="material-symbols-outlined mail-status" style="color: var(--success);">done</span>`
            : `<span class="material-symbols-outlined mail-status" style="color: var(--text-muted);">mail</span>`;
        return `<div class="email-item ${activeClass} ${isAnswered ? 'answered' : ''}" onclick="selectEmailCampaign(${idx})">
            ${icon}
            <div class="email-item-content">
                <div class="email-item-sender">${escapeHTML(email.sender_name)}</div>
                <div class="email-item-subject">${escapeHTML(email.subject)}</div>
                <div class="email-item-date">${email.date || ''}</div>
            </div>
        </div>`;
    }).join('');
}

function selectEmailCampaign(idx) {
    if (idx < 0 || idx >= emails.length) return;
    currentIndex = idx;
    const items = document.querySelectorAll('#emailList .email-item');
    items.forEach((item, i) => item.classList.toggle('active', i === idx));
    const email = emails[idx];
    document.getElementById('emptyState').classList.add('hidden');
    document.getElementById('emailView').classList.remove('hidden');
    document.getElementById('viewSubject').textContent = email.subject;
    document.getElementById('viewSenderName').textContent = email.sender_name;
    document.getElementById('viewSenderEmail').textContent = email.sender_email;
    document.getElementById('viewDate').textContent = email.date || '';
    document.getElementById('viewBody').innerHTML = email.body_html;
    if (!decisionTimestamps[email.id]) decisionTimestamps[email.id] = { viewedAt: Date.now() };
    const isAnswered = answeredIds.has(email.id);
    if (isAnswered) {
        showFeedbackCampaign(email, false);
    } else {
        document.getElementById('decisionPanel').classList.remove('hidden');
        document.getElementById('feedbackPanel').classList.add('hidden');
    }
}

function makeDecision(selectedPhishing) {
    makeDecisionInner(selectedPhishing, 'campaign');
}

function updateStreakDisplayCampaign() {
    const el = document.getElementById('streakDisplay');
    const count = document.getElementById('streakCount');
    const mult = document.getElementById('comboMultiplier');
    count.textContent = currentStreak;
    mult.textContent = 'x' + Math.min(Math.max(currentStreak, 1), 5);
    el.style.display = currentStreak >= 2 ? 'flex' : 'none';
}

function showFeedbackCampaign(email, animate, correct) {
    showFeedbackInner(email, animate, correct, {
        panel: 'feedbackPanel', icon: 'feedbackIcon', title: 'feedbackTitle',
        desc: 'feedbackDesc', flags: 'redFlagsContainer', flagsList: 'redFlagsList',
        debrief: 'debriefContainer', debriefText: 'debriefText'
    });
}

function nextEmail() {
    if (currentIndex < emails.length - 1) {
        selectEmailCampaign(currentIndex + 1);
    } else {
        completeCampaignRound();
    }
}

async function completeCampaignRound() {
    if (!currentCampaignId) return showSummary();
    try {
        const res = await fetch('/api/simulator/campaign/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ campaign_id: currentCampaignId, xp_earned: xpThisRound })
        });
        const data = await res.json();
        if (data.rank) { userRank = data.rank; }
        if (data.total_xp !== undefined) { userXP = data.total_xp; }
        updateXPBar();
        showAfterActionReport();
    } catch (e) { showAfterActionReport(); }
}

// ─── Practice Mode ───

async function loadStaticEmails() {
    document.getElementById('generationStatus').textContent = 'Loading built-in emails...';
    try {
        const res = await fetch('/api/simulator/emails');
        emails = await res.json();
        resetSessionPractice();
        document.getElementById('generationStatus').textContent = 'Built-in set loaded (' + emails.length + ' emails)';
    } catch (e) {
        document.getElementById('generationStatus').textContent = 'Failed to load emails';
    }
}

async function generateNewSession() {
    const difficulty = document.getElementById('difficultySelect').value;
    const count = parseInt(document.getElementById('countSelect').value);
    const status = document.getElementById('generationStatus');
    status.textContent = 'Generating ' + count + ' ' + difficulty + ' emails with AI...';
    try {
        const res = await fetch('/api/simulator/generate', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ count, difficulty })
        });
        const data = await res.json();
        if (data.error) { status.textContent = 'AI generation failed: ' + data.error; return; }
        if (data.emails && data.emails.length > 0) {
            emails = data.emails.map((e, i) => ({ ...e, id: e.id || (i + 1) }));
            resetSessionPractice();
            status.textContent = 'AI generated ' + emails.length + ' emails (' + difficulty + ')';
        }
    } catch (e) { status.textContent = 'Network error during generation.'; }
}

function resetSessionPractice() {
    currentIndex = -1; score = 0; answeredCount = 0; answeredIds.clear();
    decisionTimestamps = {}; sessionId = 'session_' + Date.now();
    currentStreak = 0; bestStreak = 0; xpThisRound = 0;
    updateStreakDisplayPractice();
    document.getElementById('currentScoreP').textContent = '0';
    document.getElementById('inboxCountP').textContent = emails.length;
    document.getElementById('totalQuestionsP').textContent = emails.length;
    document.getElementById('emptyStateP').classList.remove('hidden');
    document.getElementById('emailViewP').classList.add('hidden');
    document.getElementById('feedbackPanelP').classList.add('hidden');
    renderEmailListPractice();
    if (emails.length > 0) selectEmailPractice(0);
}

function renderEmailListPractice() {
    const list = document.getElementById('emailListP');
    list.innerHTML = emails.map((email, idx) => {
        const isAnswered = answeredIds.has(email.id);
        const activeClass = idx === currentIndex ? 'active' : '';
        const icon = isAnswered
            ? `<span class="material-symbols-outlined mail-status" style="color: var(--success);">done</span>`
            : `<span class="material-symbols-outlined mail-status" style="color: var(--text-muted);">mail</span>`;
        return `<div class="email-item ${activeClass} ${isAnswered ? 'answered' : ''}" onclick="selectEmailPractice(${idx})">
            ${icon}
            <div class="email-item-content">
                <div class="email-item-sender">${escapeHTML(email.sender_name)}</div>
                <div class="email-item-subject">${escapeHTML(email.subject)}</div>
                <div class="email-item-date">${email.date || ''}</div>
            </div>
        </div>`;
    }).join('');
}

function selectEmailPractice(idx) {
    if (idx < 0 || idx >= emails.length) return;
    currentIndex = idx;
    const items = document.querySelectorAll('#emailListP .email-item');
    items.forEach((item, i) => item.classList.toggle('active', i === idx));
    const email = emails[idx];
    document.getElementById('emptyStateP').classList.add('hidden');
    document.getElementById('emailViewP').classList.remove('hidden');
    document.getElementById('viewSubjectP').textContent = email.subject;
    document.getElementById('viewSenderNameP').textContent = email.sender_name;
    document.getElementById('viewSenderEmailP').textContent = email.sender_email;
    document.getElementById('viewDateP').textContent = email.date || '';
    document.getElementById('viewBodyP').innerHTML = email.body_html;
    if (!decisionTimestamps[email.id]) decisionTimestamps[email.id] = { viewedAt: Date.now() };
    if (answeredIds.has(email.id)) {
        showFeedbackPractice(email, false);
    } else {
        document.getElementById('decisionPanelP').classList.remove('hidden');
        document.getElementById('feedbackPanelP').classList.add('hidden');
    }
}

function makeDecisionP(selectedPhishing) {
    makeDecisionInner(selectedPhishing, 'practice');
}

function updateStreakDisplayPractice() {
    const el = document.getElementById('streakDisplayP');
    const count = document.getElementById('streakCountP');
    const mult = document.getElementById('comboMultiplierP');
    count.textContent = currentStreak;
    mult.textContent = 'x' + Math.min(Math.max(currentStreak, 1), 5);
    el.style.display = currentStreak >= 2 ? 'flex' : 'none';
}

function showFeedbackPractice(email, animate, correct) {
    showFeedbackInner(email, animate, correct, {
        panel: 'feedbackPanelP', icon: 'feedbackIconP', title: 'feedbackTitleP',
        desc: 'feedbackDescP', flags: 'redFlagsContainerP', flagsList: 'redFlagsListP',
        debrief: null, debriefText: null
    });
}

function nextEmailP() {
    if (currentIndex < emails.length - 1) {
        selectEmailPractice(currentIndex + 1);
    } else {
        showSummaryPractice();
    }
}

function showSummaryPractice() {
    const total = emails.length;
    const accuracy = total > 0 ? Math.round((score / total) * 100) : 0;
    document.getElementById('summaryScore').textContent = score + '/' + total;
    document.getElementById('summaryAccuracy').textContent = accuracy + '%';
    document.getElementById('summaryStreak').textContent = bestStreak;
    document.getElementById('summaryXP').textContent = '+' + xpThisRound;
    let msg = accuracy >= 90 ? 'Outstanding! You\'re a phishing detection expert.' : accuracy >= 70 ? 'Great job! You have a solid eye for threats.' : accuracy >= 50 ? 'Good effort! Focus on sender addresses and urgency cues.' : 'Keep practicing! Pay attention to red flags like mismatched domains.';
    document.getElementById('summaryMessage').textContent = msg;
    if (accuracy >= 90) { spawnConfetti(); setTimeout(spawnConfetti, 500); }
    document.getElementById('summaryModal').classList.remove('hidden');
}

// ─── Shared Decision Logic ───

function makeDecisionInner(selectedPhishing, fromMode) {
    const email = emails[currentIndex];
    if (answeredIds.has(email.id)) return;
    answeredIds.add(email.id);
    answeredCount++;

    const timing = decisionTimestamps[email.id] || {};
    const responseTime = timing.viewedAt ? Date.now() - timing.viewedAt : 0;
    const correct = email.is_phishing === selectedPhishing;

    // XP calculation
    let xp = 0;
    if (correct) {
        currentStreak++;
        if (currentStreak > bestStreak) bestStreak = currentStreak;
        score += Math.min(currentStreak, 5);
        xp = 10;
        if (responseTime < 3000) xp += 10;
        else if (responseTime < 5000) xp += 5;
        xp *= Math.min(currentStreak, 5);
    } else {
        currentStreak = 0;
    }
    xpThisRound += xp;
    userXP += xp;
    updateXPBar();

    // Record round result for AAR
    roundResults.push({
        email: email, correct: correct, selectedPhishing: selectedPhishing,
        responseTime: responseTime, xpEarned: xp,
        flagsFound: correct ? (email.red_flags || []).length : 0
    });

    // Update UI
    if (fromMode === 'campaign') {
        document.getElementById('currentScore').textContent = score;
        updateStreakDisplayCampaign();
        renderEmailListCampaign();
        showFeedbackCampaign(email, true, correct);
    } else {
        document.getElementById('currentScoreP').textContent = score;
        updateStreakDisplayPractice();
        renderEmailListPractice();
        showFeedbackPractice(email, true, correct);
    }

    if (!correct) {
        const pane = document.getElementById(fromMode === 'campaign' ? 'emailPane' : 'emailPaneP');
        pane.classList.remove('shake'); void pane.offsetWidth; pane.classList.add('shake');
    }

    if (correct) spawnConfetti();

    // Record stats
    const totalFlags = (email.red_flags && email.red_flags.length) || 0;
    const flagsIdentified = correct ? totalFlags : 0;
    fetch('/api/phishing/stats', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            email_id: String(email.id), campaign_id: 0,
            is_phishing: email.is_phishing, identified_correctly: correct,
            response_time_ms: responseTime, red_flags_identified: flagsIdentified,
            total_red_flags: totalFlags, session_id: sessionId
        })
    }).catch(() => {});

    // Debrief (campaign mode only)
    if (fromMode === 'campaign') fetchDebrief(email, selectedPhishing, correct);
}

function showFeedbackInner(email, animate, correct, ids) {
    document.getElementById(ids.panel).classList.remove('hidden');
    if (ids.debrief) document.getElementById(ids.debrief).classList.add('hidden');
    const icon = document.getElementById(ids.icon);
    const title = document.getElementById(ids.title);
    const desc = document.getElementById(ids.desc);
    const flags = document.getElementById(ids.flags);
    const flagsList = document.getElementById(ids.flagsList);

    if (correct === true) {
        icon.textContent = 'check_circle'; icon.style.color = 'var(--success)';
        title.textContent = currentStreak >= 3 ? 'Correct! ' + currentStreak + ' in a row!' : 'Correct! Well spotted.';
        title.style.color = 'var(--success)';
    } else if (correct === false) {
        icon.textContent = 'cancel'; icon.style.color = 'var(--error)';
        title.textContent = 'Incorrect. You fell for the bait!';
        title.style.color = 'var(--error)';
    } else {
        icon.textContent = 'info'; icon.style.color = 'var(--info)';
        title.textContent = 'Reviewing Email Analysis';
        title.style.color = 'var(--text)';
    }
    desc.textContent = email.explanation || '';
    if (email.is_phishing && email.red_flags && email.red_flags.length > 0) {
        flags.classList.remove('hidden');
        flagsList.innerHTML = email.red_flags.map(f => `<li><strong>Target:</strong> <code class="highlight-warn">${escapeHTML(f.target)}</code><div style="margin-top: 0.25rem;">${escapeHTML(f.reason)}</div></li>`).join('');
    } else {
        flags.classList.add('hidden');
    }
    if (animate) document.getElementById(ids.panel).scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ─── Debrief ───

async function fetchDebrief(email, userAnsweredPhishing, correct) {
    try {
        const res = await fetch('/api/simulator/debrief', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: { subject: email.subject, sender_name: email.sender_name, sender_email: email.sender_email, is_phishing: email.is_phishing },
                userAnsweredPhishing, correct
            })
        });
        const data = await res.json();
        if (data.debrief) {
            document.getElementById('debriefText').textContent = data.debrief;
            document.getElementById('debriefContainer').classList.remove('hidden');
        }
    } catch (e) {}
}

// ─── Boss Battle ───

async function loadBossState() {
    try {
        const res = await fetch('/api/simulator/xp');
        const data = await res.json();
        const allDone = data.campaigns_completed.length >= 5;
        bossDefeated = data.boss_defeated;

        if (bossDefeated) {
            document.getElementById('bossLocked').style.display = 'none';
            document.getElementById('bossReady').style.display = 'none';
            document.getElementById('bossDefeated').style.display = '';
            document.getElementById('bossCertMsg').style.display = data.certified ? '' : 'none';
        } else if (allDone) {
            document.getElementById('bossLocked').style.display = 'none';
            document.getElementById('bossReady').style.display = '';
        } else {
            document.getElementById('bossLocked').style.display = '';
            document.getElementById('bossReady').style.display = 'none';
            const prog = document.getElementById('bossProgress');
            prog.innerHTML = `<div style="display: inline-block; padding: 0.5rem 1rem; background: var(--bg-tertiary); border-radius: 8px; font-size: 0.9rem;">
                ${data.campaigns_completed.length}/5 campaigns completed
            </div>`;
        }
    } catch (e) {}
}

async function startBossBattle() {
    try {
        const res = await fetch('/api/simulator/boss-battle');
        const data = await res.json();
        if (data.error) return;
        bossEmail = data.email;
        document.getElementById('bossReady').style.display = 'none';
        document.getElementById('bossActive').style.display = '';
        document.getElementById('bossNarrative').textContent = bossEmail.explanation;
        document.getElementById('bossSubject').textContent = bossEmail.subject;
        document.getElementById('bossSenderName').textContent = bossEmail.sender_name;
        document.getElementById('bossSenderEmail').textContent = bossEmail.sender_email;
        document.getElementById('bossDate').textContent = bossEmail.date;
        document.getElementById('bossBody').innerHTML = bossEmail.body_html;
        document.getElementById('bossEmailItem').innerHTML = `
            <div class="email-item-content">
                <div class="email-item-sender">${escapeHTML(bossEmail.sender_name)}</div>
                <div class="email-item-subject">${escapeHTML(bossEmail.subject)}</div>
                <div class="email-item-date">${bossEmail.date}</div>
            </div>`;
    } catch (e) {}
}

function makeBossDecision(selectedPhishing) {
    if (!bossEmail) return;
    const correct = bossEmail.is_phishing === selectedPhishing;

    document.getElementById('bossDecisionPanel').classList.add('hidden');
    document.getElementById('bossFeedbackPanel').classList.remove('hidden');

    const icon = document.getElementById('bossFeedbackIcon');
    const title = document.getElementById('bossFeedbackTitle');
    const desc = document.getElementById('bossFeedbackDesc');
    const flagsList = document.getElementById('bossRedFlagsList');

    if (correct) {
        icon.textContent = 'emoji_events'; icon.style.color = 'var(--warning)';
        title.textContent = 'Boss Defeated!'; title.style.color = 'var(--warning)';
        desc.textContent = 'You identified this as phishing! +200 XP earned.';
        spawnConfetti(); setTimeout(spawnConfetti, 600);
    } else {
        icon.textContent = 'cancel'; icon.style.color = 'var(--error)';
        title.textContent = 'Boss Wins...'; title.style.color = 'var(--error)';
        desc.textContent = 'This was a sophisticated phishing attack. Review all 7 red flags below.';
    }

    flagsList.innerHTML = bossEmail.red_flags.map(f =>
        `<li><strong>Target:</strong> <code class="highlight-warn">${escapeHTML(f.target)}</code><div style="margin-top: 0.25rem;">${escapeHTML(f.reason)}</div></li>`
    ).join('');

    roundResults.push({ email: bossEmail, correct, selectedPhishing, responseTime: 0, xpEarned: correct ? 200 : 0, flagsFound: correct ? bossEmail.red_flags.length : 0, isBoss: true });
}

async function bossDefeatSequence() {
    try {
        const res = await fetch('/api/simulator/boss/defeat', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
        const data = await res.json();
        if (data.rank) userRank = data.rank;
        if (data.total_xp !== undefined) userXP = data.total_xp;
        updateXPBar();
        document.getElementById('bossActive').style.display = 'none';
        document.getElementById('bossDefeated').style.display = '';
        document.getElementById('bossCertMsg').style.display = data.certified ? '' : 'none';
        if (data.certified) {
            document.getElementById('certUsername').textContent = 'Awarded to: ' + SIMULATOR_USERNAME;
            document.getElementById('certModal').classList.remove('hidden');
            spawnConfetti(); setTimeout(spawnConfetti, 500); setTimeout(spawnConfetti, 1000);
        }
    } catch (e) {
        document.getElementById('bossActive').style.display = 'none';
        document.getElementById('bossDefeated').style.display = '';
    }
}

// ─── After-Action Report ───

function showAfterActionReport() {
    if (roundResults.length === 0) return showSummary();
    const total = roundResults.length;
    const correctCount = roundResults.filter(r => r.correct).length;
    const accuracy = Math.round(correctCount / total * 100);
    const totalXP = roundResults.reduce((s, r) => s + r.xpEarned, 0);

    let html = `
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1.5rem;">
            <div style="text-align: center; padding: 1rem; background: var(--bg-tertiary); border-radius: 8px;">
                <div style="font-size: 1.5rem; font-weight: 800; color: var(--accent);">${correctCount}/${total}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">Score</div>
            </div>
            <div style="text-align: center; padding: 1rem; background: var(--bg-tertiary); border-radius: 8px;">
                <div style="font-size: 1.5rem; font-weight: 800; color: ${accuracy >= 80 ? 'var(--success)' : 'var(--warning)'};">${accuracy}%</div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">Accuracy</div>
            </div>
            <div style="text-align: center; padding: 1rem; background: var(--bg-tertiary); border-radius: 8px;">
                <div style="font-size: 1.5rem; font-weight: 800; color: var(--warning);">${bestStreak}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">Best Streak</div>
            </div>
            <div style="text-align: center; padding: 1rem; background: var(--bg-tertiary); border-radius: 8px;">
                <div style="font-size: 1.5rem; font-weight: 800; color: var(--info);">+${totalXP}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted);">XP Earned</div>
            </div>
        </div>
        <h3 style="font-size: 0.95rem; margin-bottom: 0.75rem;">Email-by-Email Breakdown</h3>
    `;

    roundResults.forEach((r, i) => {
        const e = r.email;
        const statusColor = r.correct ? 'var(--success)' : 'var(--error)';
        const statusIcon = r.correct ? 'check_circle' : 'cancel';
        const timeStr = r.responseTime > 0 ? (r.responseTime / 1000).toFixed(1) + 's' : '—';

        html += `
            <div style="padding: 0.75rem 1rem; margin-bottom: 0.5rem; background: var(--bg-tertiary); border-radius: 8px; border-left: 3px solid ${statusColor};">
                <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.3rem;">
                    <span class="material-symbols-outlined" style="color: ${statusColor}; font-size: 1.1rem;">${statusIcon}</span>
                    <strong style="font-size: 0.85rem;">${escapeHTML(e.subject)}</strong>
                    <span style="margin-left: auto; font-size: 0.75rem; color: var(--text-muted);">${timeStr}</span>
                </div>
                <div style="font-size: 0.8rem; color: var(--text-secondary);">
                    From: ${escapeHTML(e.sender_email)} — ${e.is_phishing ? 'Phishing' : 'Legitimate'}
                    ${r.correct ? '' : ' — <span style="color: var(--error);">You said ' + (r.selectedPhishing ? 'Phishing' : 'Safe') + '</span>'}
                </div>
                <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.3rem;">
                    ${escapeHTML((e.explanation || '').substring(0, 150))}${(e.explanation || '').length > 150 ? '...' : ''}
                </div>
                ${r.xpEarned > 0 ? `<div style="font-size: 0.75rem; color: var(--accent); margin-top: 0.25rem;">+${r.xpEarned} XP</div>` : ''}
            </div>`;
    });

    document.getElementById('aarContent').innerHTML = html;
    document.getElementById('aarModal').classList.remove('hidden');
}

function closeAAR() {
    document.getElementById('aarModal').classList.add('hidden');
    document.getElementById('campaignSelect').style.display = '';
    document.getElementById('campaignActive').style.display = 'none';
    loadCampaigns();
    loadXPData();
}

// ─── Summary ───

function closeSummary() { document.getElementById('summaryModal').classList.add('hidden'); }

// ─── Confetti ───

function spawnConfetti() {
    const container = document.getElementById('confettiContainer');
    const colors = ['#f59e0b', '#ef4444', '#3b82f6', '#10b981', '#8b5cf6', '#ec4899'];
    for (let i = 0; i < 40; i++) {
        const piece = document.createElement('div');
        piece.className = 'confetti-piece';
        piece.style.left = (Math.random() * 100) + '%';
        piece.style.top = (Math.random() * 30 + 10) + '%';
        piece.style.background = colors[Math.floor(Math.random() * colors.length)];
        piece.style.width = (Math.random() * 6 + 4) + 'px';
        piece.style.height = (Math.random() * 6 + 4) + 'px';
        piece.style.animationDuration = (Math.random() * 1 + 1) + 's';
        piece.style.animationDelay = (Math.random() * 0.3) + 's';
        container.appendChild(piece);
        setTimeout(() => piece.remove(), 2500);
    }
}

// ─── Escape ───

function escapeHTML(str) {
    if (!str) return '';
    return String(str).replace(/[&<>'"]/g, tag => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[tag] || tag));
}
