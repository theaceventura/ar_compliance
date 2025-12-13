# Cybersecurity Awareness Compliance Tracker

## Running
- Core (meets uni scope): `APP_ENABLE_THREAT_MODULE=0 APP_ENABLE_RISK_MODULE=0 flask run`
- Core + risk: `APP_ENABLE_RISK_MODULE=1 flask run`
- Core + all extras: `APP_ENABLE_THREAT_MODULE=1 APP_ENABLE_RISK_MODULE=1 flask run`
- Nav links/routes for risk/threats appear only when enabled.

## Structure
- `compliance_app_tailwind/core_routes.py`: login/logout, dashboard dispatcher, task detail.
- `compliance_app_tailwind/admin_routes.py`: admin/company-admin dashboards, tasks/users/companies, reports/CSV, settings.
- `compliance_app_tailwind/threat_routes.py`: optional threat ingestion/admin (toggle `APP_ENABLE_THREAT_MODULE`).
- `compliance_app_tailwind/risk_routes.py`: optional risk matrix admin (toggle `APP_ENABLE_RISK_MODULE`).
- Shared helpers: `auth_helpers.py` (decorators/current_user), `core_utils.py` (formatters/tally), `risk_utils.py` (matrix builder), `db.py` (data access).
- `app.py`: app setup, toggles, blueprint registration, context processor.

## Submission note
Run with threats/risk disabled to show the core uni scope; enable them to demonstrate extra work. The core satisfies login/logout, role-based access, task completion with verification Q/A, overdue/compliance metrics, admin task/user management, reports, CSV export, and SQLite persistence with a Flask GUI.
