from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session, joinedload
from datetime import datetime, timedelta
import logging
from jose import JWTError, jwt
from typing import List, Optional
from fastapi import Query
from sqlalchemy import or_, and_

from .database import SessionLocal, engine, get_db
from .models import User, Base, AccessRequest, Resource, AuditLog, AuditActionType, Credential, ResourceCheck
from .schemas import (
    UserCreate, UserResponse, Token, LoginRequest, 
    MFAEnableRequest, MFAResponse, PasswordChangeRequest,
    AccessRequestCreate, AccessRequestResponse, AccessRequestUpdate,
    ResourceCreate, ResourceResponse, ResourceUpdate, ResourceListResponse, 
    AuditLogResponse, AuditLogFilter, HealthCheckResponse, BulkHealthCheckResponse, 
    ResourceCheckResponse, HealthCheckRequest
)
from .auth import (
    get_password_hash, authenticate_user, 
    create_access_token, create_refresh_token,
    get_current_user, get_current_admin_user, verify_password,
    verify_totp_code, generate_mfa_secret, generate_mfa_uri,
    create_user_session, ACCESS_TOKEN_EXPIRE_MINUTES,
    SECRET_KEY, ALGORITHM
)

# Import health check service (you'll need to create this)
try:
    from .health_check import health_check_service
except ImportError:
    # Fallback mock service if health_check module doesn't exist yet
    class MockHealthCheckService:
        async def check_resource_health(self, resource):
            # Mock implementation - replace with actual health checks
            return {
                "is_online": True,
                "response_time": 100,
                "error_message": None
            }
    
    health_check_service = MockHealthCheckService()

# Import background tasks (you'll need to create these)
try:
    from .tasks import check_single_resource, check_all_resources
except ImportError:
    # Mock tasks if not implemented yet
    def check_single_resource(resource_id):
        print(f"Mock: Checking resource {resource_id}")
    
    def check_all_resources():
        print("Mock: Checking all resources")

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="OpenPAM Backend", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create database tables
Base.metadata.create_all(bind=engine)

# Audit logging utility functions
def create_audit_log(
    db: Session,
    user_id: Optional[int] = None,
    admin_user_id: Optional[int] = None,
    action: str = "",
    action_type: str = "",
    details: Optional[dict] = None,
    request: Optional[Request] = None,
    access_request_id: Optional[int] = None,
    resource_id: Optional[int] = None,
    severity: str = "info"
):
    """Create an audit log entry"""
    audit_log = AuditLog(
        user_id=user_id,
        admin_user_id=admin_user_id,
        action=action,
        action_type=action_type,
        details=details,
        ip_address=request.client.host if request and request.client else None,
        user_agent=request.headers.get("user-agent") if request else None,
        access_request_id=access_request_id,
        resource_id=resource_id,
        severity=severity
    )
    db.add(audit_log)
    db.commit()
    return audit_log

@app.get("/")
async def root():
    return {"message": "OpenPAM API is running"}

# User Management Endpoints
@app.post("/users/", response_model=UserResponse)
def create_user(
    user_data: UserCreate, 
    request: Request,
    db: Session = Depends(get_db)
):
    # Check if user already exists
    existing_user = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    
    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username or email already exists"
        )
    
    hashed = get_password_hash(user_data.password)
    user = User(
        username=user_data.username, 
        email=user_data.email, 
        hashed_password=hashed,
        department=user_data.department,
        job_title=user_data.job_title
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    # Log user creation
    create_audit_log(
        db=db,
        user_id=user.id,
        action="User created",
        action_type=AuditActionType.PROFILE_UPDATE.value,
        details={
            "username": user.username,
            "email": user.email,
            "department": user.department,
            "job_title": user.job_title
        },
        request=request
    )
    
    return user

@app.get("/users/", response_model=list[UserResponse])
def get_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    users = db.query(User).all()
    return users

# Authentication Endpoints
@app.post("/token", response_model=Token)
def login_for_access_token(
    request: Request,
    form_data: LoginRequest, 
    db: Session = Depends(get_db)
):
    try:
        user = authenticate_user(db, form_data.username, form_data.password, request)
        
        # Check if MFA is required
        if user.mfa_enabled:
            if not form_data.mfa_code:
                return {
                    "access_token": "",
                    "refresh_token": "",
                    "token_type": "bearer",
                    "mfa_required": True
                }
            
            if not verify_totp_code(user.mfa_secret, form_data.mfa_code):
                # Log failed MFA attempt
                create_audit_log(
                    db=db,
                    user_id=user.id,
                    action="Failed MFA authentication",
                    action_type=AuditActionType.LOGIN_FAILED.value,
                    details={"reason": "Invalid MFA code"},
                    request=request,
                    severity="warning"
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid MFA code",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        
        # Create tokens
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, 
            expires_delta=access_token_expires
        )
        refresh_token = create_refresh_token(data={"sub": user.username})
        
        # Create session
        session_token = create_user_session(
            db, user.id, user, request, access_token_expires
        )
        
        # Log successful login
        create_audit_log(
            db=db,
            user_id=user.id,
            action="User logged in",
            action_type=AuditActionType.LOGIN.value,
            details={"mfa_used": user.mfa_enabled},
            request=request
        )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "mfa_required": False
        }
    
    except HTTPException as e:
        # Log failed login attempt
        if e.status_code == status.HTTP_401_UNAUTHORIZED:
            user = db.query(User).filter(User.username == form_data.username).first()
            if user:
                create_audit_log(
                    db=db,
                    user_id=user.id,
                    action="Failed login attempt",
                    action_type=AuditActionType.LOGIN_FAILED.value,
                    details={"reason": "Invalid credentials"},
                    request=request,
                    severity="warning"
                )
        raise e

@app.post("/token/refresh")
def refresh_token(
    refresh_token: str,
    db: Session = Depends(get_db)
):
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")
        
        if username is None or token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    user = db.query(User).filter(User.username == username).first()
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    # Create new access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, 
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=UserResponse)
def read_users_me(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return current_user

# MFA Endpoints
@app.post("/users/me/mfa/enable", response_model=MFAResponse)
def enable_mfa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None
):
    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled"
        )
    
    # Generate new MFA secret
    mfa_secret = generate_mfa_secret()
    current_user.mfa_secret = mfa_secret
    db.commit()
    
    # Generate MFA URI for QR code
    mfa_uri = generate_mfa_uri(current_user.username, mfa_secret)
    
    return {"mfa_uri": mfa_uri, "mfa_secret": mfa_secret}

@app.post("/users/me/mfa/verify")
def verify_mfa(
    mfa_data: MFAEnableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None
):
    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA secret not generated"
        )
    
    if verify_totp_code(current_user.mfa_secret, mfa_data.mfa_code):
        current_user.mfa_enabled = True
        db.commit()
        
        # Log MFA enablement
        create_audit_log(
            db=db,
            user_id=current_user.id,
            action="MFA enabled",
            action_type=AuditActionType.MFA_ENABLED.value,
            request=request
        )
        
        return {"message": "MFA enabled successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA code"
        )

@app.post("/users/me/mfa/disable")
def disable_mfa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None
):
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled"
        )
    
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    db.commit()
    
    # Log MFA disablement
    create_audit_log(
        db=db,
        user_id=current_user.id,
        action="MFA disabled",
        action_type=AuditActionType.MFA_DISABLED.value,
        request=request
    )
    
    return {"message": "MFA disabled successfully"}

@app.post("/users/me/change-password")
def change_password(
    password_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None
):
    # Verify current password
    if not verify_password(password_data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Set new password
    current_user.hashed_password = get_password_hash(password_data.new_password)
    current_user.must_change_password = False
    db.commit()
    
    # Log password change
    create_audit_log(
        db=db,
        user_id=current_user.id,
        action="Password changed",
        action_type=AuditActionType.PASSWORD_CHANGE.value,
        request=request
    )
    
    return {"message": "Password changed successfully"}

# Enhanced Resource Management Endpoints
@app.post("/api/resources", response_model=ResourceResponse)
def create_resource(
    resource_data: ResourceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
    request: Request = None
):
    # Check for duplicate name
    existing_resource = db.query(Resource).filter(
        Resource.name == resource_data.name
    ).first()
    if existing_resource:
        raise HTTPException(
            status_code=409,
            detail="Resource name already exists"
        )
    
    # Check for duplicate hostname:port combination
    existing_hostname = db.query(Resource).filter(
        and_(
            Resource.hostname == resource_data.hostname,
            Resource.port == resource_data.port,
            Resource.is_active == True
        )
    ).first()
    if existing_hostname:
        raise HTTPException(
            status_code=409,
            detail="Resource with this hostname and port already exists"
        )

    resource = Resource(**resource_data.dict())
    db.add(resource)
    db.commit()
    db.refresh(resource)
    
    # Log resource creation
    create_audit_log(
        db=db,
        admin_user_id=current_user.id,
        action="create_resource",
        action_type="resource_create",
        details={
            "resource_id": resource.id,
            "name": resource.name,
            "type": resource.type,
            "hostname": resource.hostname,
            "port": resource.port,
            "criticality": resource.criticality
        },
        request=request,
        resource_id=resource.id,
        severity="info"
    )
    
    return resource

@app.get("/api/resources", response_model=ResourceListResponse)
def list_resources(
    q: Optional[str] = Query(None, description="Search by name or hostname"),
    type: Optional[str] = Query(None, description="Filter by resource type"),
    criticality: Optional[str] = Query(None, description="Filter by criticality"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(25, ge=1, le=100, description="Items per page"),
    sort_by: str = Query("name", description="Sort by field"),
    order: str = Query("asc", description="Sort order"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Start with base query
    query = db.query(Resource).filter(Resource.is_active == True)
    
    # Apply search filter
    if q:
        query = query.filter(
            or_(
                Resource.name.ilike(f"%{q}%"),
                Resource.hostname.ilike(f"%{q}%")
            )
        )
    
    # Apply type filter
    if type:
        query = query.filter(Resource.type == type)
    
    # Apply criticality filter
    if criticality:
        query = query.filter(Resource.criticality == criticality)
    
    # Apply sorting
    sort_column = getattr(Resource, sort_by, Resource.name)
    if order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())
    
    # Get total count
    total = query.count()
    
    # Apply pagination
    offset = (page - 1) * limit
    resources = query.offset(offset).limit(limit).all()
    
    return {
        "items": resources,
        "meta": {
            "page": page,
            "limit": limit,
            "total": total,
            "pages": (total + limit - 1) // limit
        }
    }

@app.get("/api/resources/{resource_id}", response_model=ResourceResponse)
def get_resource(
    resource_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    resource = db.query(Resource).filter(
        Resource.id == resource_id,
        Resource.is_active == True
    ).first()
    
    if not resource:
        raise HTTPException(
            status_code=404,
            detail="Resource not found"
        )
    
    return resource

@app.put("/api/resources/{resource_id}", response_model=ResourceResponse)
def update_resource(
    resource_id: int,
    resource_data: ResourceUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
    request: Request = None
):
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    
    if not resource:
        raise HTTPException(
            status_code=404,
            detail="Resource not found"
        )
    
    # Store before state for audit
    before_state = {
        "name": resource.name,
        "type": resource.type,
        "hostname": resource.hostname,
        "port": resource.port,
        "description": resource.description,
        "criticality": resource.criticality,
        "check_interval": resource.check_interval
    }
    
    # Check for duplicate name if name is being updated
    if resource_data.name and resource_data.name != resource.name:
        existing_resource = db.query(Resource).filter(
            Resource.name == resource_data.name,
            Resource.id != resource_id
        ).first()
        if existing_resource:
            raise HTTPException(
                status_code=409,
                detail="Resource name already exists"
            )
    
    # Check for duplicate hostname:port combination
    if resource_data.hostname or resource_data.port is not None:
        hostname = resource_data.hostname or resource.hostname
        port = resource_data.port if resource_data.port is not None else resource.port
        existing_hostname = db.query(Resource).filter(
            and_(
                Resource.hostname == hostname,
                Resource.port == port,
                Resource.id != resource_id,
                Resource.is_active == True
            )
        ).first()
        if existing_hostname:
            raise HTTPException(
                status_code=409,
                detail="Resource with this hostname and port already exists"
            )
    
    # Update fields
    update_data = resource_data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(resource, field, value)
    
    db.commit()
    db.refresh(resource)
    
    # Log resource update
    create_audit_log(
        db=db,
        admin_user_id=current_user.id,
        action="update_resource",
        action_type="resource_update",
        details={
            "resource_id": resource.id,
            "before": before_state,
            "after": {
                "name": resource.name,
                "type": resource.type,
                "hostname": resource.hostname,
                "port": resource.port,
                "description": resource.description,
                "criticality": resource.criticality,
                "check_interval": resource.check_interval
            }
        },
        request=request,
        resource_id=resource.id,
        severity="info"
    )
    
    return resource

@app.delete("/api/resources/{resource_id}")
def delete_resource(
    resource_id: int,
    force: bool = Query(False, description="Force deletion despite dependencies"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
    request: Request = None
):
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    
    if not resource:
        raise HTTPException(
            status_code=404,
            detail="Resource not found"
        )
    
    # Check for active access requests
    active_requests_count = db.query(AccessRequest).filter(
        AccessRequest.resource_id == resource_id,
        AccessRequest.status.in_(["pending", "approved"])
    ).count()
    
    # Check for credentials
    credentials_count = db.query(Credential).filter(
        Credential.resource_id == resource_id
    ).count()
    
    dependencies = {
        "active_access_requests": active_requests_count,
        "credentials": credentials_count
    }
    
    # Block deletion if dependencies exist and force is not True
    if not force and (active_requests_count > 0 or credentials_count > 0):
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Resource cannot be deleted due to existing dependencies",
                "dependencies": dependencies,
                "force_required": True
            }
        )
    
    # For force deletion or no dependencies, use soft delete
    resource.is_active = False
    db.commit()
    
    # Log resource deletion
    severity = "warning" if force else "info"
    create_audit_log(
        db=db,
        admin_user_id=current_user.id,
        action="delete_resource",
        action_type="resource_delete",
        details={
            "resource_id": resource.id,
            "name": resource.name,
            "force_deletion": force,
            "dependencies": dependencies
        },
        request=request,
        resource_id=resource.id,
        severity=severity
    )
    
    return {
        "message": "Resource deleted successfully",
        "details": dependencies if force else None
    }

# Health Check Endpoints
@app.post("/api/resources/{resource_id}/check", response_model=HealthCheckResponse)
async def check_resource_health(
    resource_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None
):
    """Check health of a specific resource"""
    resource = db.query(Resource).filter(
        Resource.id == resource_id,
        Resource.is_active == True
    ).first()
    
    if not resource:
        raise HTTPException(
            status_code=404,
            detail="Resource not found"
        )
    
    # Perform health check
    result = await health_check_service.check_resource_health(resource)
    
    # Update resource status
    resource.is_online = result["is_online"]
    resource.last_checked_at = datetime.utcnow()
    
    # Create check record
    check = ResourceCheck(
        resource_id=resource.id,
        is_online=result["is_online"],
        response_time=result["response_time"],
        error_message=result["error_message"]
    )
    db.add(check)
    db.commit()
    
    # Log health check
    create_audit_log(
        db=db,
        admin_user_id=current_user.id if current_user.is_admin else None,
        user_id=current_user.id if not current_user.is_admin else None,
        action="Resource health check",
        action_type="health_check",
        details={
            "resource_id": resource.id,
            "resource_name": resource.name,
            "is_online": result["is_online"],
            "response_time": result["response_time"]
        },
        request=request,
        resource_id=resource.id,
        severity="info" if result["is_online"] else "warning"
    )
    
    return {
        "resource_id": resource.id,
        "is_online": result["is_online"],
        "response_time": result["response_time"],
        "error_message": result["error_message"],
        "checked_at": datetime.utcnow()
    }

@app.post("/api/resources/check-all", response_model=BulkHealthCheckResponse)
async def check_all_resources_health(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
    request: Request = None
):
    """Check health of all resources (admin only)"""
    resources = db.query(Resource).filter(Resource.is_active == True).all()
    
    results = []
    for resource in resources:
        try:
            result = await health_check_service.check_resource_health(resource)
            
            # Update resource status
            resource.is_online = result["is_online"]
            resource.last_checked_at = datetime.utcnow()
            
            # Create check record
            check = ResourceCheck(
                resource_id=resource.id,
                is_online=result["is_online"],
                response_time=result["response_time"],
                error_message=result["error_message"]
            )
            db.add(check)
            
            results.append({
                "resource_id": resource.id,
                "is_online": result["is_online"],
                "response_time": result["response_time"],
                "error_message": result["error_message"],
                "checked_at": datetime.utcnow()
            })
            
        except Exception as e:
            results.append({
                "resource_id": resource.id,
                "is_online": False,
                "response_time": None,
                "error_message": str(e),
                "checked_at": datetime.utcnow()
            })
    
    db.commit()
    
    # Log bulk health check
    create_audit_log(
        db=db,
        admin_user_id=current_user.id,
        action="Bulk resource health check",
        action_type="bulk_health_check",
        details={
            "total_checked": len(resources),
            "online_count": len([r for r in results if r["is_online"]]),
            "offline_count": len([r for r in results if not r["is_online"]])
        },
        request=request,
        severity="info"
    )
    
    return {
        "results": results,
        "total_checked": len(resources),
        "online_count": len([r for r in results if r["is_online"]]),
        "offline_count": len([r for r in results if not r["is_online"]])
    }

@app.get("/api/resources/{resource_id}/check-history", response_model=List[ResourceCheckResponse])
def get_resource_check_history(
    resource_id: int,
    limit: int = Query(50, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get health check history for a resource"""
    resource = db.query(Resource).filter(
        Resource.id == resource_id,
        Resource.is_active == True
    ).first()
    
    if not resource:
        raise HTTPException(
            status_code=404,
            detail="Resource not found"
        )
    
    checks = db.query(ResourceCheck).options(
        joinedload(ResourceCheck.resource)
    ).filter(
        ResourceCheck.resource_id == resource_id
    ).order_by(ResourceCheck.checked_at.desc()).limit(limit).all()
    
    return checks

@app.post("/api/resources/{resource_id}/check-background")
def trigger_background_health_check(
    resource_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Trigger background health check for a resource"""
    # This will use Celery to run the check in background
    check_single_resource.delay(resource_id)
    
    return {"message": "Background health check started"}

@app.post("/api/resources/check-all-background")
def trigger_background_health_check_all(
    current_user: User = Depends(get_current_admin_user)
):
    """Trigger background health check for all resources"""
    check_all_resources.delay()
    
    return {"message": "Background health check for all resources started"}

# Legacy resource endpoints (keep for backward compatibility)
@app.post("/resources/", response_model=ResourceResponse)
def create_resource_legacy(
    resource_data: ResourceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
    request: Request = None
):
    resource = Resource(**resource_data.dict())
    db.add(resource)
    db.commit()
    db.refresh(resource)
    
    # Log resource creation
    create_audit_log(
        db=db,
        admin_user_id=current_user.id,
        action=f"Resource created: {resource.name}",
        action_type=AuditActionType.PROFILE_UPDATE.value,
        details=resource_data.dict(),
        request=request,
        resource_id=resource.id
    )
    
    return resource

@app.get("/resources/", response_model=List[ResourceResponse])
def get_resources_legacy(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    resources = db.query(Resource).all()
    return resources

# Access Request Endpoints
@app.post("/access-requests/", response_model=AccessRequestResponse)
def create_access_request(
    request_data: AccessRequestCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request: Request = None
):
    # Validate resource exists
    resource = db.query(Resource).filter(Resource.id == request_data.resource_id).first()
    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found"
        )
    
    # Validate expiry time (max 24 hours)
    max_expiry = datetime.utcnow() + timedelta(hours=24)
    if request_data.expires_at > max_expiry:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Access duration cannot exceed 24 hours"
        )
    
    # Create access request
    access_request = AccessRequest(
        user_id=current_user.id,
        resource_id=request_data.resource_id,
        reason=request_data.reason,
        expires_at=request_data.expires_at,
        status="pending"
    )
    
    db.add(access_request)
    db.commit()
    db.refresh(access_request)
    
    # Log access request creation
    create_audit_log(
        db=db,
        user_id=current_user.id,
        action="Access request created",
        action_type=AuditActionType.CREATE_REQUEST.value,
        details={
            "resource_id": request_data.resource_id,
            "resource_name": resource.name,
            "expires_at": request_data.expires_at.isoformat(),
            "reason": request_data.reason
        },
        request=request,
        access_request_id=access_request.id,
        resource_id=request_data.resource_id
    )
    
    return access_request

@app.get("/access-requests/my-requests", response_model=List[AccessRequestResponse])
def get_my_access_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get only the current user's access requests with resource and user details"""
    requests = db.query(AccessRequest).options(
        joinedload(AccessRequest.resource),
        joinedload(AccessRequest.user)
    ).filter(
        AccessRequest.user_id == current_user.id
    ).order_by(AccessRequest.requested_at.desc()).all()
    
    return requests

@app.get("/access-requests/", response_model=List[AccessRequestResponse])
def get_all_access_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Get all access requests (admin only) with resource and user details"""
    requests = db.query(AccessRequest).options(
        joinedload(AccessRequest.resource),
        joinedload(AccessRequest.user),
        joinedload(AccessRequest.approver)
    ).order_by(AccessRequest.requested_at.desc()).all()
    return requests

@app.get("/access-requests/pending", response_model=List[AccessRequestResponse])
def get_pending_access_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Get pending access requests for admin approval with resource and user details"""
    requests = db.query(AccessRequest).options(
        joinedload(AccessRequest.resource),
        joinedload(AccessRequest.user)
    ).filter(
        AccessRequest.status == "pending"
    ).order_by(AccessRequest.requested_at.desc()).all()
    return requests

@app.post("/access-requests/{request_id}/approve", response_model=AccessRequestResponse)
def approve_access_request(
    request_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
    request: Request = None
):
    access_request = db.query(AccessRequest).options(
        joinedload(AccessRequest.user),
        joinedload(AccessRequest.resource)
    ).filter(AccessRequest.id == request_id).first()
    
    if not access_request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found"
        )
    
    if access_request.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Access request is not pending"
        )
    
    # Update access request
    access_request.status = "approved"
    access_request.approved_at = datetime.utcnow()
    access_request.approved_by = current_user.id
    db.commit()
    db.refresh(access_request)
    
    # Log approval
    create_audit_log(
        db=db,
        user_id=access_request.user_id,
        admin_user_id=current_user.id,
        action="Access request approved",
        action_type=AuditActionType.APPROVE_REQUEST.value,
        details={
            "request_id": request_id,
            "approved_by": current_user.username,
            "resource_name": access_request.resource.name if access_request.resource else "Unknown"
        },
        request=request,
        access_request_id=access_request.id,
        resource_id=access_request.resource_id
    )
    
    return access_request

@app.post("/access-requests/{request_id}/reject", response_model=AccessRequestResponse)
def reject_access_request(
    request_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
    request: Request = None
):
    access_request = db.query(AccessRequest).options(
        joinedload(AccessRequest.user),
        joinedload(AccessRequest.resource)
    ).filter(AccessRequest.id == request_id).first()
    
    if not access_request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Access request not found"
        )
    
    if access_request.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Access request is not pending"
        )
    
    # Update access request
    access_request.status = "rejected"
    access_request.approved_at = datetime.utcnow()
    access_request.approved_by = current_user.id
    db.commit()
    db.refresh(access_request)
    
    # Log rejection
    create_audit_log(
        db=db,
        user_id=access_request.user_id,
        admin_user_id=current_user.id,
        action="Access request rejected",
        action_type=AuditActionType.REJECT_REQUEST.value,
        details={
            "request_id": request_id,
            "rejected_by": current_user.username,
            "resource_name": access_request.resource.name if access_request.resource else "Unknown"
        },
        request=request,
        access_request_id=access_request.id,
        resource_id=access_request.resource_id
    )
    
    return access_request

# Background task to expire access requests
def expire_access_requests(db: Session):
    """Expire access requests that have passed their expiry time"""
    expired_requests = db.query(AccessRequest).filter(
        AccessRequest.status == "approved",
        AccessRequest.expires_at < datetime.utcnow()
    ).all()
    
    for request in expired_requests:
        request.status = "expired"
        # Create audit log for expiration
        create_audit_log(
            db=db,
            user_id=request.user_id,
            action="Access request expired",
            action_type=AuditActionType.REQUEST_EXPIRED.value,
            details={
                "request_id": request.id,
                "expired_at": datetime.utcnow().isoformat()
            },
            access_request_id=request.id,
            resource_id=request.resource_id
        )
    
    db.commit()

@app.post("/access-requests/expire")
def trigger_expire_access_requests(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Manually trigger expiration of access requests (for testing)"""
    background_tasks.add_task(expire_access_requests, db)
    return {"message": "Expiration process started"}

# Audit Log Endpoints
@app.get("/audit-logs/", response_model=List[AuditLogResponse])
def get_audit_logs(
    user_id: Optional[int] = None,
    action_type: Optional[str] = None,
    severity: Optional[str] = None,
    resource_id: Optional[int] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Get audit logs with filtering (admin only)"""
    query = db.query(AuditLog).options(
        joinedload(AuditLog.user),
        joinedload(AuditLog.admin_user),
        joinedload(AuditLog.access_request),
        joinedload(AuditLog.resource)
    )
    
    # Apply filters
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    
    if action_type:
        query = query.filter(AuditLog.action_type == action_type)
    
    if severity:
        query = query.filter(AuditLog.severity == severity)
    
    if resource_id:
        query = query.filter(AuditLog.resource_id == resource_id)
    
    if start_date:
        query = query.filter(AuditLog.timestamp >= start_date)
    
    if end_date:
        query = query.filter(AuditLog.timestamp <= end_date)
    
    # Order by timestamp descending and apply limit/offset
    logs = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()
    
    return logs

@app.get("/audit-logs/stats")
def get_audit_log_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Get audit log statistics (admin only)"""
    # Total logs count
    total_logs = db.query(AuditLog).count()
    
    # Logs by action type
    action_type_stats = db.query(
        AuditLog.action_type,
        db.func.count(AuditLog.id)
    ).group_by(AuditLog.action_type).all()
    
    # Logs by severity
    severity_stats = db.query(
        AuditLog.severity,
        db.func.count(AuditLog.id)
    ).group_by(AuditLog.severity).all()
    
    # Recent activity (last 24 hours)
    last_24h = datetime.utcnow() - timedelta(hours=24)
    recent_activity = db.query(AuditLog).filter(
        AuditLog.timestamp >= last_24h
    ).count()
    
    return {
        "total_logs": total_logs,
        "action_type_stats": dict(action_type_stats),
        "severity_stats": dict(severity_stats),
        "recent_activity_24h": recent_activity
    }

# Health check endpoint
@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}