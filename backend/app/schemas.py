from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=12)
    department: Optional[str] = None
    job_title: Optional[str] = None

    @validator('password')
    def validate_password_complexity(cls, v):
        errors = []
        if len(v) < 12:
            errors.append("Password must be at least 12 characters long")
        if not any(c.isupper() for c in v):
            errors.append("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            errors.append("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            errors.append("Password must contain at least one digit")
        special_chars = "!@#$%^&*(),.?:{}|<>"
        if not any(c in special_chars for c in v):
            errors.append("Password must contain at least one special character")
        
        if errors:
            raise ValueError("; ".join(errors))
        return v

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool
    is_admin: bool
    mfa_enabled: bool
    last_login: Optional[datetime]
    department: Optional[str]
    job_title: Optional[str]
    access_level: int
    must_change_password: bool
    role_id: Optional[int]

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    mfa_required: bool = False

class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: Optional[str] = None

class MFAEnableRequest(BaseModel):
    mfa_code: str

class MFAResponse(BaseModel):
    mfa_uri: str
    mfa_secret: str

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=12)

    @validator('new_password')
    def validate_password_complexity(cls, v):
        errors = []
        if len(v) < 12:
            errors.append("Password must be at least 12 characters long")
        if not any(c.isupper() for c in v):
            errors.append("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            errors.append("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            errors.append("Password must contain at least one digit")
        special_chars = "!@#$%^&*(),.?:{}|<>"
        if not any(c in special_chars for c in v):
            errors.append("Password must contain at least one special character")
        
        if errors:
            raise ValueError("; ".join(errors))
        return v

# Access Request Schemas
class AccessRequestStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"

class AccessRequestCreate(BaseModel):
    resource_id: int
    reason: Optional[str] = None
    expires_at: datetime = Field(..., description="Requested expiry time")

class AccessRequestResponse(BaseModel):
    id: int
    user_id: int
    resource_id: int
    reason: Optional[str]
    status: str
    requested_at: datetime
    approved_at: Optional[datetime]
    approved_by: Optional[int]
    expires_at: datetime
    user: Optional["UserResponse"] = None
    resource: Optional["ResourceResponse"] = None
    approver: Optional["UserResponse"] = None

    class Config:
        from_attributes = True

class AccessRequestUpdate(BaseModel):
    status: AccessRequestStatus

# Resource Schemas
class ResourceType(str, Enum):
    SSH = "ssh"
    DB = "db"
    API = "api"
    WEB = "web"
    RDP = "rdp"
    SERVICE = "service"

class CriticalityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class ResourceCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=100)
    type: ResourceType
    hostname: str = Field(..., min_length=1)
    port: Optional[int] = Field(None, ge=1, le=65535)
    description: Optional[str] = None
    criticality: CriticalityLevel = CriticalityLevel.MEDIUM
    check_interval: Optional[int] = Field(300, ge=60, description="Health check interval in seconds (minimum 60)")

    @validator('hostname')
    def validate_hostname(cls, v):
        # Basic hostname/IP validation
        if not v or len(v.strip()) == 0:
            raise ValueError('hostname cannot be empty')
        return v

class ResourceUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=100)
    type: Optional[ResourceType] = None
    hostname: Optional[str] = Field(None, min_length=1)
    port: Optional[int] = Field(None, ge=1, le=65535)
    description: Optional[str] = None
    criticality: Optional[CriticalityLevel] = None
    check_interval: Optional[int] = Field(None, ge=60, description="Health check interval in seconds (minimum 60)")

class ResourceResponse(BaseModel):
    id: int
    name: str
    type: str
    hostname: str
    port: Optional[int]
    description: Optional[str]
    criticality: str
    is_active: bool
    is_online: bool
    last_checked_at: Optional[datetime]
    check_interval: int

    class Config:
        from_attributes = True

class ResourceListResponse(BaseModel):
    items: List[ResourceResponse]
    meta: Dict[str, Any]

class DeleteResourceResponse(BaseModel):
    message: str
    details: Optional[Dict[str, Any]] = None

# Health Check Schemas
class ResourceCheckResponse(BaseModel):
    id: int
    resource_id: int
    checked_at: datetime
    is_online: bool
    response_time: Optional[int]
    error_message: Optional[str]
    resource: Optional["ResourceResponse"] = None

    class Config:
        from_attributes = True

class HealthCheckResponse(BaseModel):
    resource_id: int
    is_online: bool
    response_time: Optional[int]
    error_message: Optional[str]
    checked_at: datetime

class BulkHealthCheckResponse(BaseModel):
    results: List[HealthCheckResponse]
    total_checked: int
    online_count: int
    offline_count: int

class HealthCheckRequest(BaseModel):
    resource_ids: Optional[List[int]] = None
    force_check: bool = False

# Role Schemas
class RoleCreate(BaseModel):
    name: str
    description: Optional[str] = None

class RoleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]

    class Config:
        from_attributes = True

# Audit Log Schemas
class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    admin_user_id: Optional[int]
    action: str
    action_type: str
    details: Optional[Dict[str, Any]]
    ip_address: Optional[str]
    user_agent: Optional[str]
    timestamp: datetime
    access_request_id: Optional[int]
    resource_id: Optional[int]
    severity: str
    user: Optional["UserResponse"] = None
    admin_user: Optional["UserResponse"] = None
    access_request: Optional["AccessRequestResponse"] = None
    resource: Optional["ResourceResponse"] = None

    class Config:
        from_attributes = True

class AuditLogFilter(BaseModel):
    user_id: Optional[int] = None
    action_type: Optional[str] = None
    severity: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    resource_id: Optional[int] = None
    limit: int = 100
    offset: int = 0

# Update forward references
AccessRequestResponse.update_forward_refs()
ResourceResponse.update_forward_refs()
UserResponse.update_forward_refs()
AuditLogResponse.update_forward_refs()
ResourceCheckResponse.update_forward_refs()