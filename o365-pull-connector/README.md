# o365-pull-connector

Standalone Microsoft 365 pull connector that collects selected datasets from Microsoft Graph, normalizes them, and exposes them over a REST API.

## Features
- Flask API with health/version, tenants CRUD, run trigger, datasets, events (raw/normalized), export summary, metrics, and readiness checks.
- APScheduler for periodic pulls per tenant.
- Dataset support: signins, role assignments, conditional access policies, MFA coverage. Defender alerts are stubbed behind `DEFENDER_ENABLED`.
- Storage via SQLAlchemy with SQLite (default) or Postgres via `DATABASE_URL`.
- Mapping-driven export JSON with stable `export_version: 1`.
- Correlation produces `IncidentCandidate` events.
- JSON logging with `request_id` support.

## Setup
1. Install Python 3.11.
2. `python -m venv .venv && source .venv/bin/activate`
3. `pip install -r requirements.txt`
4. Copy `config/example.env` to `.env` (or export env vars) and set your database URL.
5. Bootstrap database: `python -m o365_connector` (runs once and starts the app) or `python scripts/bootstrap_db.py`.
6. Start API: `python -m o365_connector` (dev) or `gunicorn -c gunicorn.conf.py "o365_connector.app:create_app()"`.

### Docker
`docker-compose up --build` launches the app and Postgres with a healthcheck.

### Make targets
- `make run`
- `make test`
- `make lint`
- `make docker-up`

## Entra ID app registration (per tenant)
1. In Azure Portal, go to **Entra ID → App registrations → New registration**. Name it and set single-tenant.
2. Note the **Application (client) ID** and **Directory (tenant) ID**.
3. Under **API permissions → Add a permission → Microsoft Graph → Application permissions**, add:
   - `AuditLog.Read.All` (signins)
   - `Directory.Read.All` (role assignments)
   - `Policy.Read.All` (conditional access)
   - `Reports.Read.All` (MFA coverage)
4. Click **Grant admin consent** for the tenant.
5. Under **Certificates & secrets → New client secret**, create a secret and copy its value immediately.
6. Store the secret safely; do not write it to the database. The connector only stores a secret reference.

## Secrets handling
- Implemented `SecretsProvider` with default `EnvSecretsProvider`.
- Env var naming helper: `O365_SECRET_<TENANT_ID_SANITIZED>` where the tenant ID is uppercased and non-alphanumeric chars become `_`.
- Example: tenant `1234-5678-90ab` → env var `O365_SECRET_1234_5678_90AB`.
- `get_client_secret(tenant_id)` returns the secret string, looked up from environment.

## API
- `GET /health`
- `GET /version`
- `GET/POST /tenants`
- `GET/PUT/DELETE /tenants/<tenant_id>`
- `POST /run/<tenant_id>/?dataset=<optional>`
- `GET /datasets`
- `GET /events/raw?tenant_id=&dataset=&since=&limit=`
- `GET /events/normalized?tenant_id=&type=&since=&limit=`
- `GET /export/summary?tenant_id=&since=`
- `GET /metrics`
- `GET /tenants/<tenant_id>/readiness`

## Data minimisation
- No mailbox content is pulled.
- Only security and audit metadata is collected.

## Configuration
- `config/example.env` documents environment variables.
- `config/mapping.yml` maps normalized types to domains/controls/metrics.
- `config/correlation.yml` defines correlation windows and descriptions.

## Notes
- Defender alerts are intentionally disabled; `src/o365_connector/clients/defender_client.py` is a stub. Enable later with `DEFENDER_ENABLED=true`.
- Exports are deterministic JSON with `export_version` for compatibility.
