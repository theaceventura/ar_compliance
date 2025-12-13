# Compliance App (Tailwind)

Lightweight Flask app for risk and threat dashboards.

## Setup
1. Use Python 3.11.
2. Create venv: `python3.11 -m venv .venv && source .venv/bin/activate`.
3. Install deps: `pip install -r compliance_app/requirements.txt`.
4. Run: `FLASK_APP=compliance_app_tailwind/app.py flask run` (from `compliance_app` directory) or `python compliance_app_tailwind/app.py` if it contains an entrypoint.

## Notes
- SQLite DB file lives at `compliance.db` in the project root by default.
- Repo ignores pycache, .DS_Store, zips, and db/log artifacts via `.gitignore`.
