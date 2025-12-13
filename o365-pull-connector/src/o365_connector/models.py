from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.sqlite import JSON as SqliteJSON
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


def utcnow() -> datetime:
    return datetime.utcnow()


class Tenant(Base):
    __tablename__ = "tenants"

    tenant_id = Column(String, primary_key=True)
    tenant_name = Column(String, nullable=False)
    client_id = Column(String, nullable=False)
    client_secret_ref = Column(String, nullable=False)
    is_enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "tenant_name": self.tenant_name,
            "client_id": self.client_id,
            "client_secret_ref": self.client_secret_ref,
            "is_enabled": self.is_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class DatasetState(Base):
    __tablename__ = "dataset_state"
    __table_args__ = (UniqueConstraint("tenant_id", "dataset", name="uq_dataset_state"),)

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False)
    dataset = Column(String, nullable=False)
    last_run_at = Column(DateTime)
    cursor_json = Column(Text)
    delta_token = Column(String)


class RawEvent(Base):
    __tablename__ = "raw_events"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False)
    source = Column(String, nullable=False)
    dataset = Column(String, nullable=False)
    event_id = Column(String, nullable=False)
    occurred_at = Column(DateTime)
    received_at = Column(DateTime, default=utcnow, nullable=False)
    payload_json = Column(Text, nullable=False)
    payload_hash = Column(String, nullable=False)


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False)
    type = Column(String, nullable=False)
    occurred_at = Column(DateTime, nullable=False)
    actor_json = Column(Text)
    target_json = Column(Text)
    severity = Column(String, nullable=False)
    confidence = Column(String, nullable=False)
    summary = Column(Text)
    json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class RunHistory(Base):
    __tablename__ = "run_history"

    id = Column(Integer, primary_key=True)
    tenant_id = Column(String, ForeignKey("tenants.tenant_id", ondelete="CASCADE"), nullable=False)
    dataset = Column(String, nullable=False)
    started_at = Column(DateTime, default=utcnow, nullable=False)
    finished_at = Column(DateTime)
    status = Column(String, nullable=False)
    pulled_count = Column(Integer, default=0, nullable=False)
    normalized_count = Column(Integer, default=0, nullable=False)
    error_text = Column(Text)
    stats_json = Column(Text)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "dataset": self.dataset,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "status": self.status,
            "pulled_count": self.pulled_count,
            "normalized_count": self.normalized_count,
            "error_text": self.error_text,
            "stats_json": self.stats_json,
        }
