from pydantic import BaseModel, EmailStr, validator, Field
from typing import Optional, List
from datetime import datetime

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

# Basic schemas for new entities (will be extended as needed)
class RoleCreate(BaseModel):
    name: str
    description: Optional[str] = None

class RoleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]

    class Config:
        from_attributes = True

class ResourceCreate(BaseModel):
    name: str
    type: str
    hostname: str
    port: Optional[int] = None
    description: Optional[str] = None
    criticality: str = "medium"

class ResourceResponse(BaseModel):
    id: int
    name: str
    type: str
    hostname: str
    port: Optional[int]
    description: Optional[str]
    criticality: str

    class Config:
        from_attributes = True