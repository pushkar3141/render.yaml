"""Database models (SQLite locally, PostgreSQL on Supabase in production)."""
from __future__ import annotations

import datetime as dt
import json
import os

from sqlalchemy import (JSON, Column, DateTime, Float, ForeignKey, Integer, String, Text,
                        create_engine)
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()


def _utcnow():
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class Upload(Base):
    __tablename__ = "uploads"
    id = Column(Integer, primary_key=True)
    filename = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=_utcnow)
    flows = Column(Integer)
    flagged_flows = Column(Integer)
    labelled_attacks = Column(Integer)
    seconds = Column(Float)
    raw_path = Column(String(500))         # object key in storage (raw upload)
    processed_path = Column(String(500))   # object key of processed Parquet
    summary = Column(JSON)                 # pre-computed chart data


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    upload_id = Column(Integer, ForeignKey("uploads.id", ondelete="CASCADE"), index=True)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    rule = Column(String(8), index=True)
    name = Column(String(80))
    severity = Column(String(10), index=True)
    src_ip = Column(String(64))
    dst_ip = Column(String(64))
    dst_port = Column(Integer, nullable=True)
    minutes = Column(Integer)
    flows = Column(Integer)
    evidence = Column(Text)
    action = Column(Text)


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    upload_id = Column(Integer, ForeignKey("uploads.id", ondelete="CASCADE"), index=True)
    created_at = Column(DateTime, default=_utcnow)
    kind = Column(String(8))               # pdf or csv
    path = Column(String(500))


class Setting(Base):
    __tablename__ = "settings"
    key = Column(String(64), primary_key=True)
    value = Column(Text)


def make_session(base_dir: str):
    url = os.environ.get("DATABASE_URL") or f"sqlite:///{os.path.join(base_dir, 'data', 'netmon.db')}"
    if url.startswith("postgres://"):                 # Render/Supabase style URL
        url = url.replace("postgres://", "postgresql://", 1)
    engine = create_engine(url, pool_pre_ping=True, json_serializer=lambda o: json.dumps(o, default=str))
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)
