from sqlalchemy import Column, Integer, String, Boolean, DateTime, JSON, ForeignKey, Text
from sqlalchemy.orm import relationship
from .database import Base
from datetime import datetime

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)  # admin, auditor, dev, ops
    description = Column(String, nullable=True)

    users = relationship("User", back_populates="role")

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    
    # MFA and security
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String, nullable=True)
    last_login = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    account_locked_until = Column(DateTime, nullable=True)
    department = Column(String, nullable=True)
    job_title = Column(String, nullable=True)
    access_level = Column(Integer, default=0)
    session_timeout = Column(Integer, default=30)
    must_change_password = Column(Boolean, default=True)
    
    # Role relationship
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=True)
    role = relationship("Role", back_populates="users")
    
    # Relationships
    access_requests = relationship("AccessRequest", back_populates="user", foreign_keys="AccessRequest.user_id")
    approved_requests = relationship("AccessRequest", back_populates="approver", foreign_keys="AccessRequest.approved_by")
    sessions = relationship("UserSession", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")
    rotation_history = relationship("RotationHistory", back_populates="user")

class UserSession(Base):
    __tablename__ = "user_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    session_token = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    ip_address = Column(String)
    user_agent = Column(String)
    is_revoked = Column(Boolean, default=False)
    
    user = relationship("User", back_populates="sessions")

class Resource(Base):
    __tablename__ = "resources"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)  # ssh, db, api, etc.
    hostname = Column(String, nullable=False)
    port = Column(Integer, nullable=True)
    description = Column(String, nullable=True)
    criticality = Column(String, default="medium")  # low, medium, high
    
    access_requests = relationship("AccessRequest", back_populates="resource")
    credentials = relationship("Credential", back_populates="resource")
    recorded_sessions = relationship("RecordedSession", back_populates="resource")

class Credential(Base):
    __tablename__ = "credentials"

    id = Column(Integer, primary_key=True, index=True)
    resource_id = Column(Integer, ForeignKey("resources.id"), nullable=False)
    vault_path = Column(String, nullable=False)  # reference to Vault secret
    type = Column(String, nullable=False)  # password, ssh_key, api_key
    last_rotated_at = Column(DateTime, default=datetime.utcnow)
    rotation_interval_days = Column(Integer, default=7)

    resource = relationship("Resource", back_populates="credentials")
    rotation_history = relationship("RotationHistory", back_populates="credential")

class AccessRequest(Base):
    __tablename__ = "access_requests"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    resource_id = Column(Integer, ForeignKey("resources.id"))
    reason = Column(String)
    status = Column(String, default="pending")  # pending, approved, rejected
    requested_at = Column(DateTime, default=datetime.utcnow)
    approved_at = Column(DateTime, nullable=True)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    expires_at = Column(DateTime)
    
    user = relationship("User", back_populates="access_requests", foreign_keys=[user_id])
    approver = relationship("User", back_populates="approved_requests", foreign_keys=[approved_by])
    resource = relationship("Resource", back_populates="access_requests")
    recorded_sessions = relationship("RecordedSession", back_populates="access_request")
    audit_logs = relationship("AuditLog", back_populates="access_request")

class RecordedSession(Base):
    __tablename__ = "recorded_sessions"

    id = Column(Integer, primary_key=True, index=True)
    access_request_id = Column(Integer, ForeignKey("access_requests.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    resource_id = Column(Integer, ForeignKey("resources.id"))
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    recording_path = Column(String, nullable=True)  # path to ttyrec/asciinema file
    suspicious_detected = Column(Boolean, default=False)

    user = relationship("User")
    resource = relationship("Resource")
    access_request = relationship("AccessRequest", back_populates="recorded_sessions")
    suspicious_commands = relationship("SuspiciousCommand", back_populates="session")

class SuspiciousCommand(Base):
    __tablename__ = "suspicious_commands"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("recorded_sessions.id"))
    command = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    severity = Column(String, default="medium")  # low, medium, high

    session = relationship("RecordedSession", back_populates="suspicious_commands")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String, nullable=False)  # "login", "create_request", "approve_request", "rotate_credential"
    details = Column(JSON, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    access_request_id = Column(Integer, ForeignKey("access_requests.id"), nullable=True)

    user = relationship("User", back_populates="audit_logs")
    access_request = relationship("AccessRequest", back_populates="audit_logs")

class RotationHistory(Base):
    __tablename__ = "rotation_history"

    id = Column(Integer, primary_key=True, index=True)
    credential_id = Column(Integer, ForeignKey("credentials.id"))
    rotated_at = Column(DateTime, default=datetime.utcnow)
    rotated_by = Column(Integer, ForeignKey("users.id"), nullable=True)  # system or admin
    status = Column(String, default="success")  # success, failed
    details = Column(String, nullable=True)

    credential = relationship("Credential", back_populates="rotation_history")
    user = relationship("User", back_populates="rotation_history")