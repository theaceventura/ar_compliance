# Compliance App (Tailwind)

Lightweight Flask app for risk and threat dashboards.

## Setup
1. Use Python 3.11.
2. Create venv: `python3.11 -m venv .venv && source .venv/bin/activate`.
3. Install deps: `pip install -r compliance_app/requirements.txt`.
4. Run (from `compliance_app` directory):
   - `PYTHONPATH=$PWD/src python -m compliance_app.app`
   - or `FLASK_APP=compliance_app/app.py PYTHONPATH=$PWD/src flask run`

## Notes
- SQLite DB file lives at `compliance.db` in the project root by default.
- Repo ignores pycache, .DS_Store, zips, and db/log artifacts via `.gitignore`.
- Code now lives under `compliance_app/src/compliance_app/` with threat modules in `compliance_app/threat/`.
