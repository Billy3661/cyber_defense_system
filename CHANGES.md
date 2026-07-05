# Securix — Amendments Log

> Tracking all improvements made to the Cyber Defense System.
> Each entry is tied to a commit for full traceability.

---

## Round 0 — Project Setup

- [x] Created `CHANGES.md` to track all amendments
- [x] Created `.github/workflows/deploy.yml` — auto-deploy to Render on push to `main`

---

## Instructions

Each round corresponds to a group of related fixes.
Rounds are applied incrementally on your command.

---

## Round 1 — Bug Fixes

- [x] Removed duplicate `database.init_db()` call (was called at both module level and again before `app = Flask(__name__)`)
- [x] Fixed overly permissive DKIM parsing — the old logic marked *any* email with a DKIM header as "pass" unless "dkim=fail" was explicitly found. Now only explicit "dkim=pass" results count.
- [x] Removed duplicate `user_id = session.get("user_id")` assignment in `edit_profile()` — was assigned twice in the same function
- [x] Added current password verification before allowing a password change in profile editing. New `current_password` field in the edit profile form. Prevents session hijackers from changing password without knowing the current one.

---

## Round 2 — Security Fixes

- [x] Added full CSRF (Cross-Site Request Forgery) protection:
  - `generate_csrf_token()` — generates a session-bound random token via `secrets.token_hex(32)`
  - `validate_csrf()` — validates the token on every form `POST`
  - Hidden `csrf_token` field injected into `login.html`, `register.html`, `edit_profile.html`
  - All three form POST routes (`/login`, `/register`, `/edit-profile`) now reject requests without a valid CSRF token
- [x] Replaced hardcoded fallback `SECRET_KEY` with a secure generated key:
  - If `SECRET_KEY` env var is missing, generates a random 32-byte hex key using `secrets.token_hex(32)`
  - Logs a warning so the operator knows sessions will be invalidated on restart
- [x] VirusTotal API key validation:
  - `/api/config/vt-key` now rejects keys shorter than 20 chars or containing non-alphanumeric characters
- [x] Upload hardening (`/edit-profile`):
  - Added 5 MB file size limit for profile images
  - Restricted allowed file extensions to `png`, `jpg`, `jpeg`, `gif`
  - Replaced `uuid.uuid4().hex[:8]` with cryptographically secure `secrets.token_hex(8)` for filenames
  - Removed redundant `import os` / `from werkzeug.utils import secure_filename` inside the request handler (were already imported at module top-level)

---

## Round 3 — Code Quality

- [x] Removed dead imports: `from groq import Groq`, `import markdown`, `g`, `Response`, `stream_with_context` from Flask
- [x] Made Groq AI configuration dynamic:
  - `GROQ_API_BASE` env var (default: `https://api.groq.com/openai/v1/chat/completions`)
  - `GROQ_MODEL` env var (default: `llama-3.1-8b-instant`)
- [x] Added reusable CSS utility classes to `style.css`: `.form-stack`, `.field-group`, `.form-label`, `.btn-block`, `.flash-msg`, `.flash-success`, `.flash-error`, `.avatar-wrap`, `.avatar-img`, `.avatar-placeholder-icon`
- [x] Migrated inline styles to CSS classes in `login.html`, `register.html`, `edit_profile.html`:
  - Forms now use `.form-stack`
  - Field groups use `.field-group`
  - Labels use `.form-label`
  - Full-width buttons use `.btn-block`
  - Avatar section uses `.avatar-wrap` / `.avatar-img` / `.avatar-placeholder-icon`
  - Edit profile flash messages use `.flash-msg` + `.flash-success`/`.flash-error`
- [x] Added light mode counterpart for `.avatar-wrap` background
