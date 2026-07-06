# AGENTS.md — Session Checkpoint

## Project
**Securix** — Cyber Defense System (Flask web app)
- IP/domain/URL/email threat analysis
- VirusTotal, WHOIS, DNS, SSL OSINT enrichment
- AI chat via Groq API
- User auth with Flask sessions
- SQLite (dev) / PostgreSQL (prod)

## Current State
- Round 6 complete (IP Intelligence OSINT Enhancement — WHOIS, DNS, SSL)
- Removed campaign management and phishing kit features
- Enhanced phishing simulator with gamification

## Key Files
- `app.py` (~2885 lines) — main application
- `database.py` — DB layer (SQLite + PostgreSQL)
- `templates/simulator.html` — Phishing Lab with gamification
- `static/` — CSS, JS assets

## Last Session (Round 7)
1. **Removed Campaign Management** — deleted routes, templates, DB tables, nav links
2. **Removed Phishing Kit** — deleted routes, templates, DB tables, nav links
3. **Enhanced Phishing Simulator**:
   - Streak counter with combo multiplier (up to x5 points)
   - Timed mode (20s countdown per email)
   - Visual celebrations (confetti on correct, shake on wrong)
   - End-of-session summary modal (score, accuracy, best streak, avg time)
   - Live rank display in stats bar
   - Streak fire indicator in sidebar

## Where to Pick Up
Possible next areas:
- Additional OSINT integrations
- UI polish / mobile responsiveness
- Testing improvements
- Deployment config tweaks
