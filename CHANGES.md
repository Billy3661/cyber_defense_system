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
