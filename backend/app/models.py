from sqlalchemy import Column, Integer, String, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    
    # New columns for PAM context
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
    
    # Relationships - specify foreign_keys to resolve ambiguity
    access_requests = relationship("AccessRequest", back_populates="user", foreign_keys="AccessRequest.user_id")
    approved_requests = relationship("AccessRequest", back_populates="approver", foreign_keys="AccessRequest.approved_by")
    sessions = relationship("UserSession", back_populates="user")
    
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