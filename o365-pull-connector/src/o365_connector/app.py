import json
import logging
from datetime import datetime
from typing import Optional

from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, jsonify, request
from sqlalchemy import select

from o365_connector import __version__
from o365_connector.config import AppConfig
from o365_connector.models import NormalizedEvent, RawEvent, Tenant
from o365_connector.services.dataset_runner import DatasetRunner
from o365_connector.services.exporter import export_summary
from o365_connector.services.readiness import readiness_for_tenant
from o365_connector.utils.constants import SUPPORTED_DATASETS
from o365_connector.utils.db import init_db, session_scope
from o365_connector.utils.logging_config import configure_logging, ensure_request_id
from o365_connector.utils.secrets import EnvSecretsProvider
from o365_connector.ui import ui_bp

logger = logging.getLogger(__name__)


def parse_datetime_param(name: str, default: Optional[datetime] = None) -> Optional[datetime]:
    value = request.args.get(name)
    if not value:
        return default
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return default


def create_app(config: Optional[AppConfig] = None) -> Flask:
    config = config or AppConfig.from_env()
    configure_logging(config.log_level)
    app = Flask(__name__)
    Session = init_db(config)
    secrets_provider = EnvSecretsProvider()
    runner = DatasetRunner(config, secrets_provider)
    scheduler = BackgroundScheduler()
    app.register_blueprint(ui_bp)

    @app.before_request
    def before_request():
        ensure_request_id()

    @app.route("/health")
    def health():
        return jsonify({"status": "ok"})

    @app.route("/version")
    def version():
        return jsonify({"version": __version__})

    @app.route("/datasets")
    def datasets():
        enabled = SUPPORTED_DATASETS.copy()
        if not config.defender_enabled and "defender_alerts" in enabled:
            enabled.remove("defender_alerts")
        return jsonify({"datasets": enabled})

    @app.route("/metrics")
    def metrics():
        return jsonify(runner.metrics)

    @app.route("/tenants", methods=["GET"])
    def list_tenants():
        with session_scope(Session) as session:
            tenants = session.execute(select(Tenant)).scalars().all()
            return jsonify([t.to_dict() for t in tenants])

    @app.route("/tenants", methods=["POST"])
    def create_tenant():
        data = request.get_json(force=True)
        with session_scope(Session) as session:
            tenant = Tenant(
                tenant_id=data["tenant_id"],
                tenant_name=data["tenant_name"],
                client_id=data["client_id"],
                client_secret_ref=data["client_secret_ref"],
                is_enabled=data.get("is_enabled", True),
            )
            session.add(tenant)
            session.flush()
            return jsonify(tenant.to_dict()), 201

    @app.route("/tenants/<tenant_id>", methods=["GET"])
    def get_tenant(tenant_id: str):
        with session_scope(Session) as session:
            tenant = session.get(Tenant, tenant_id)
            if not tenant:
                return jsonify({"error": "not found"}), 404
            return jsonify(tenant.to_dict())

    @app.route("/tenants/<tenant_id>", methods=["PUT"])
    def update_tenant(tenant_id: str):
        data = request.get_json(force=True)
        with session_scope(Session) as session:
            tenant = session.get(Tenant, tenant_id)
            if not tenant:
                return jsonify({"error": "not found"}), 404
            for field in ["tenant_name", "client_id", "client_secret_ref", "is_enabled"]:
                if field in data:
                    setattr(tenant, field, data[field])
            session.flush()
            return jsonify(tenant.to_dict())

    @app.route("/tenants/<tenant_id>", methods=["DELETE"])
    def delete_tenant(tenant_id: str):
        with session_scope(Session) as session:
            tenant = session.get(Tenant, tenant_id)
            if not tenant:
                return jsonify({"error": "not found"}), 404
            session.delete(tenant)
            return jsonify({"status": "deleted"})

    @app.route("/run/<tenant_id>/", methods=["POST"])
    def run_now(tenant_id: str):
        dataset = request.args.get("dataset")
        with session_scope(Session) as session:
            tenant = session.get(Tenant, tenant_id)
            if not tenant:
                return jsonify({"error": "not found"}), 404
            result = runner.run_for_tenant(session, tenant, dataset)
            return jsonify(result)

    @app.route("/events/raw")
    def raw_events():
        tenant_id = request.args.get("tenant_id")
        dataset = request.args.get("dataset")
        since = parse_datetime_param("since")
        limit = int(request.args.get("limit", "100"))
        stmt = select(RawEvent)
        if tenant_id:
            stmt = stmt.where(RawEvent.tenant_id == tenant_id)
        if dataset:
            stmt = stmt.where(RawEvent.dataset == dataset)
        if since:
            stmt = stmt.where(RawEvent.occurred_at >= since)
        stmt = stmt.order_by(RawEvent.received_at.desc()).limit(limit)
        with session_scope(Session) as session:
            events = session.execute(stmt).scalars().all()
            return jsonify(
                [
                    {
                        "id": e.id,
                        "tenant_id": e.tenant_id,
                        "dataset": e.dataset,
                        "event_id": e.event_id,
                        "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
                        "received_at": e.received_at.isoformat() if e.received_at else None,
                        "payload_json": json.loads(e.payload_json or "{}"),
                    }
                    for e in events
                ]
            )

    @app.route("/events/normalized")
    def normalized_events():
        tenant_id = request.args.get("tenant_id")
        event_type = request.args.get("type")
        since = parse_datetime_param("since")
        limit = int(request.args.get("limit", "100"))
        stmt = select(NormalizedEvent)
        if tenant_id:
            stmt = stmt.where(NormalizedEvent.tenant_id == tenant_id)
        if event_type:
            stmt = stmt.where(NormalizedEvent.type == event_type)
        if since:
            stmt = stmt.where(NormalizedEvent.occurred_at >= since)
        stmt = stmt.order_by(NormalizedEvent.occurred_at.desc()).limit(limit)
        with session_scope(Session) as session:
            events = session.execute(stmt).scalars().all()
            return jsonify(
                [
                    {
                        "id": e.id,
                        "tenant_id": e.tenant_id,
                        "type": e.type,
                        "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
                        "actor": json.loads(e.actor_json or "{}"),
                        "target": json.loads(e.target_json or "{}"),
                        "severity": e.severity,
                        "confidence": e.confidence,
                        "summary": e.summary,
                        "json": json.loads(e.json or "{}"),
                    }
                    for e in events
                ]
            )

    @app.route("/actors")
    def actors():
        tenant_id = request.args.get("tenant_id")
        event_type = request.args.get("type")
        if not tenant_id:
            return jsonify({"error": "tenant_id required"}), 400
        stmt = select(NormalizedEvent.actor_json).where(NormalizedEvent.tenant_id == tenant_id)
        if event_type:
            stmt = stmt.where(NormalizedEvent.type == event_type)
        with session_scope(Session) as session:
            actors = []
            for row in session.execute(stmt).scalars().all():
                data = json.loads(row or "{}")
                uid = data.get("userId") or data.get("userPrincipalName")
                if uid:
                    actors.append(uid)
            return jsonify({"tenant_id": tenant_id, "actors": sorted(list(set(actors)))})

    @app.route("/tenants/<tenant_id>/readiness")
    def readiness(tenant_id: str):
        with session_scope(Session) as session:
            tenant = session.get(Tenant, tenant_id)
            if not tenant:
                return jsonify({"error": "not found"}), 404
            checks = readiness_for_tenant(session, tenant, config, secrets_provider)
            return jsonify(checks)

    @app.route("/export/summary")
    def export_endpoint():
        tenant_id = request.args.get("tenant_id")
        if not tenant_id:
            return jsonify({"error": "tenant_id required"}), 400
        since = parse_datetime_param("since")
        with session_scope(Session) as session:
            payload = export_summary(session, tenant_id, since, config)
            return jsonify(payload)

    def scheduled_job():
        with session_scope(Session) as session:
            tenants = session.execute(select(Tenant).where(Tenant.is_enabled == True)).scalars().all()  # noqa: E712
            for tenant in tenants:
                try:
                    runner.run_for_tenant(session, tenant)
                except Exception as exc:  # noqa: BLE001
                    logger.error("Scheduled run failed", extra={"tenant_id": tenant.tenant_id, "error": str(exc)})

    if config.scheduler_enabled:
        scheduler.add_job(scheduled_job, "interval", seconds=config.scheduler_interval, id="dataset_runner")
        scheduler.start()

    return app
