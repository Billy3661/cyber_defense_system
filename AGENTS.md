# AGENTS.md — Session Checkpoint

## Project
**Securix** — Cyber Defense System (Flask web app)
- IP/domain/URL/email threat analysis
- VirusTotal, WHOIS, DNS, SSL OSINT enrichment
- AI chat via Groq API
- User auth with Flask sessions
- SQLite (dev) / PostgreSQL (prod)

## Current State
- Round 8 complete — Admin Panel added
- 8 blueprints: main, auth, scanner, simulator, breach, chat, admin
- 53 routes total, 69 automated tests passing
- Admin panel at `/admin/` with user/signature/badge/stats/conversation management

## Key Files
- `app.py` (140 lines) — Flask init, config, OAuth, CSRF, blueprint registration
- `helpers.py` (1954 lines) — All shared logic, constants, middleware, API helpers
- `database.py` (318 lines) — DB layer (SQLite + PostgreSQL)
- `blueprints/admin.py` — Admin panel (dashboard, CRUD for all tables)
- `templates/admin/` — Admin templates (base_admin, dashboard, users, signatures, badges, stats, conversations)
- `static/js/*.js` — 10 extracted JS files
- `tests/test_app.py` — 69 automated tests

## Previous Rounds
- **Round 7**: Removed campaign management + phishing kit, enhanced simulator (streaks, timed mode, confetti, summary modal)
- **Round 6**: IP Intelligence OSINT Enhancement (WHOIS, DNS, SSL)

## Round 8 — Admin Panel
1. Installed Flask-Admin 2.2.0 (used for layout, not ModelView since no SQLAlchemy)
2. Created `blueprints/admin.py` with `admin_required` decorator (checks `ADMIN_USERNAME` env var)
3. Created 6 admin views: dashboard, users, signatures, badges, phishing_stats, conversations
4. Created 7 admin templates with sidebar navigation, search, pagination, modals
5. Added CRUD: delete users (cascading), add/delete signatures, remove badges, delete conversations
6. Registered admin blueprint in `app.py`, added to context processor
7. Added "Admin Panel" link to user dropdown in `base.html` (visible only to admin)
8. Updated `.env.example` with `ADMIN_USERNAME`
9. Added 6 admin tests, updated 2 existing tests for new route/blueprint counts
10. All 69 tests pass

## Where to Pick Up
Possible next areas:
- Additional OSINT integrations
- UI polish / mobile responsiveness
- Testing improvements
- Deployment config tweaks
