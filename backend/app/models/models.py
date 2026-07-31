"""
models.py — full ORM schema for the Secure USB Device Access Management System.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, Text, BigInteger, Float
)
from sqlalchemy.orm import relationship

from app.core.database import Base


def now_utc():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default="viewer")  # admin | operator | viewer
    created_at = Column(DateTime, default=now_utc)
    last_login = Column(DateTime, nullable=True)


class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    permissions = Column(Text, nullable=True)
    created_at = Column(DateTime, default=now_utc)


class Setting(Base):
    __tablename__ = "settings"
    id = Column(Integer, primary_key=True)
    key = Column(String(128), unique=True, nullable=False)
    value = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=now_utc)


class Device(Base):
    __tablename__ = "devices"
    fingerprint = Column(String(64), primary_key=True)  # sha256 identity hash
    vendor_id = Column(String(16))
    product_id = Column(String(16))
    serial_number = Column(String(128))
    manufacturer = Column(String(255))
    device_name = Column(String(255))
    filesystem = Column(String(32))
    capacity_bytes = Column(BigInteger, nullable=True)
    usb_version = Column(String(16), nullable=True)
    status = Column(String(32), nullable=False, default="unknown")
    # unknown | whitelisted | blacklisted | temp_allowed | temp_blocked
    risk_score = Column(Float, default=0.0)
    first_seen = Column(DateTime, default=now_utc)
    last_seen = Column(DateTime, default=now_utc)

    events = relationship("USBEvent", back_populates="device")


class USBEvent(Base):
    __tablename__ = "usb_events"
    id = Column(Integer, primary_key=True)
    device_fingerprint = Column(String(64), ForeignKey("devices.fingerprint"))
    action = Column(String(32), nullable=False)  # plugged|removed|mounted|unmounted|blocked
    device_node = Column(String(64))
    mount_path = Column(String(255), nullable=True)
    bus_number = Column(String(64), nullable=True)
    timestamp = Column(DateTime, default=now_utc)

    device = relationship("Device", back_populates="events")


class Policy(Base):
    __tablename__ = "policies"
    id = Column(Integer, primary_key=True)
    device_fingerprint = Column(String(64), ForeignKey("devices.fingerprint"), nullable=True)
    rule_type = Column(String(32))  # whitelist|blacklist|temp_allow|temp_block
    expires_at = Column(DateTime, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=now_utc)
    reason = Column(Text, nullable=True)


class FileTransfer(Base):
    __tablename__ = "file_transfers"
    id = Column(Integer, primary_key=True)
    device_fingerprint = Column(String(64), ForeignKey("devices.fingerprint"))
    file_name = Column(String(512))
    path = Column(Text, nullable=True)
    extension = Column(String(32))
    mime_type = Column(String(128))
    size_bytes = Column(BigInteger)
    sha256 = Column(String(64))
    direction = Column(String(16))  # to_usb | from_usb
    decision = Column(String(16), nullable=True)
    source_path = Column(Text)
    destination_path = Column(Text)
    blocked = Column(Boolean, default=False)
    reason = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=now_utc)


class MalwareLog(Base):
    __tablename__ = "malware_logs"
    id = Column(Integer, primary_key=True)
    file_transfer_id = Column(Integer, ForeignKey("file_transfers.id"), nullable=True)
    file_name = Column(String(512))
    sha256 = Column(String(64))
    detection_engine = Column(String(32))  # yara|clamav|hash|entropy|heuristic
    threat_name = Column(String(255), nullable=True)
    risk_score = Column(Float, default=0.0)
    action_taken = Column(String(32))  # blocked|quarantined|allowed
    timestamp = Column(DateTime, default=now_utc)


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    severity = Column(String(16))  # info|warning|critical
    category = Column(String(32))  # device|malware|dlp|system
    message = Column(Text)
    acknowledged = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=now_utc)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(128))
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=now_utc)


class OfflineQueue(Base):
    """Rows written locally while MySQL is unreachable; drained on reconnect."""
    __tablename__ = "offline_queue"
    id = Column(Integer, primary_key=True)
    table_name = Column(String(64))
    payload_json = Column(Text)
    created_at = Column(DateTime, default=now_utc)
    synced = Column(Boolean, default=False)
    attempts = Column(Integer, default=0)


class SyncLog(Base):
    __tablename__ = "sync_logs"
    id = Column(Integer, primary_key=True)
    status = Column(String(16))  # started|completed|failed
    records_synced = Column(Integer, default=0)
    error = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=now_utc)


class SystemLog(Base):
    __tablename__ = "system_logs"
    id = Column(Integer, primary_key=True)
    level = Column(String(16))
    message = Column(Text)
    timestamp = Column(DateTime, default=now_utc)
