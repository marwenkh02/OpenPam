from sqlalchemy import Column, Integer, String, Boolean, DateTime, JSON, ForeignKey, Text, Enum as SQLEnum
from sqlalchemy.orm import relationship
from .database import Base
from datetime import datetime
import enum

class AuditActionType(enum.Enum):
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    CREATE_REQUEST = "create_request"
    APPROVE_REQUEST = "approve_request"
    REJECT_REQUEST = "reject_request"
    REQUEST_EXPIRED = "request_expired"
    PASSWORD_CHANGE = "password_change"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    PROFILE_UPDATE = "profile_update"
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    ACCESS_GRANTED = "access_granted"
    ACCESS_REVOKED = "access_revoked"
    RESOURCE_CREATE = "resource_create"
    RESOURCE_UPDATE = "resource_update"
    RESOURCE_DELETE = "resource_delete"
    HEALTH_CHECK = "health_check"

class ResourceType(enum.Enum):
    SSH = "ssh"
    DB = "db"
    API = "api"
    WEB = "web"
    RDP = "rdp"
    SERVICE = "service"

class CriticalityLevel(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

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
    audit_logs = relationship("AuditLog", back_populates="user", foreign_keys="AuditLog.user_id")
    admin_audit_logs = relationship("AuditLog", back_populates="admin_user", foreign_keys="AuditLog.admin_user_id")
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
    name = Column(String, nullable=False, unique=True)
    type = Column(String, nullable=False)  # ssh, db, api, etc.
    hostname = Column(String, nullable=False)
    port = Column(Integer, nullable=True)
    description = Column(String, nullable=True)
    criticality = Column(String, default="medium")  # low, medium, high
    is_active = Column(Boolean, default=True)
    
    # New health monitoring fields
    is_online = Column(Boolean, default=False)
    last_checked_at = Column(DateTime, nullable=True)
    check_interval = Column(Integer, default=300)  # 5 minutes in seconds
    
    access_requests = relationship("AccessRequest", back_populates="resource")
    credentials = relationship("Credential", back_populates="resource")
    recorded_sessions = relationship("RecordedSession", back_populates="resource")
    resource_checks = relationship("ResourceCheck", back_populates="resource")

class ResourceCheck(Base):
    __tablename__ = "resource_checks"
    
    id = Column(Integer, primary_key=True, index=True)
    resource_id = Column(Integer, ForeignKey("resources.id"))
    checked_at = Column(DateTime, default=datetime.utcnow)
    is_online = Column(Boolean, default=False)
    response_time = Column(Integer, nullable=True)  # milliseconds
    error_message = Column(String, nullable=True)
    
    resource = relationship("Resource", back_populates="resource_checks")

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
    reason = Column(Text, nullable=True)
    status = Column(String, default="pending")  # pending, approved, rejected, expired
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
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # User who performed the action
    admin_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Admin who performed admin action
    action = Column(String, nullable=False)  # "login", "create_request", "approve_request", etc.
    action_type = Column(String, nullable=False)  # From AuditActionType enum
    details = Column(JSON, nullable=True)
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    access_request_id = Column(Integer, ForeignKey("access_requests.id"), nullable=True)
    resource_id = Column(Integer, ForeignKey("resources.id"), nullable=True)
    severity = Column(String, default="info")  # info, warning, critical

    user = relationship("User", back_populates="audit_logs", foreign_keys=[user_id])
    admin_user = relationship("User", back_populates="admin_audit_logs", foreign_keys=[admin_user_id])
    access_request = relationship("AccessRequest", back_populates="audit_logs")
    resource = relationship("Resource")

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