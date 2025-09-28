from fastapi import FastAPI, Depends, HTTPException, status, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session, joinedload
from datetime import datetime, timedelta
import logging
from jose import JWTError, jwt
from typing import List

from .database import SessionLocal, engine, get_db
from .models import User, Base, AccessRequest, Resource, AuditLog
from .schemas import (
    UserCreate, UserResponse, Token, LoginRequest, 
    MFAEnableRequest, MFAResponse, PasswordChangeRequest,
    AccessRequestCreate, AccessRequestResponse, AccessRequestUpdate,
    ResourceCreate, ResourceResponse
)
from .auth import (
    get_password_hash, authenticate_user, 
    create_access_token, create_refresh_token,
    get_current_user, get_current_admin_user, verify_password,
    verify_totp_code, generate_mfa_secret, generate_mfa_uri,
    create_user_session, ACCESS_TOKEN_EXPIRE_MINUTES,
    SECRET_KEY, ALGORITHM
)

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

@app.get("/")
async def root():
    return {"message": "OpenPAM API is running"}

# User Management Endpoints
@app.post("/users/", response_model=UserResponse)
def create_user(user_data: UserCreate, db: Session = Depends(get_db)):
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
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "mfa_required": False
    }

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
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# MFA Endpoints
@app.post("/users/me/mfa/enable", response_model=MFAResponse)
def enable_mfa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
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
    db: Session = Depends(get_db)
):
    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA secret not generated"
        )
    
    if verify_totp_code(current_user.mfa_secret, mfa_data.mfa_code):
        current_user.mfa_enabled = True
        db.commit()
        return {"message": "MFA enabled successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA code"
        )

@app.post("/users/me/mfa/disable")
def disable_mfa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled"
        )
    
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    db.commit()
    
    return {"message": "MFA disabled successfully"}

@app.post("/users/me/change-password")
def change_password(
    password_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
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
    
    return {"message": "Password changed successfully"}

# Resource Management Endpoints
@app.post("/resources/", response_model=ResourceResponse)
def create_resource(
    resource_data: ResourceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    resource = Resource(**resource_data.dict())
    db.add(resource)
    db.commit()
    db.refresh(resource)
    return resource

@app.get("/resources/", response_model=List[ResourceResponse])
def get_resources(
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
    current_user: User = Depends(get_current_user)
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
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        action="create_request",
        details={
            "resource_id": request_data.resource_id,
            "resource_name": resource.name,
            "expires_at": request_data.expires_at.isoformat()
        },
        access_request_id=access_request.id
    )
    db.add(audit_log)
    db.commit()
    
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
    current_user: User = Depends(get_current_admin_user)
):
    access_request = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
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
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        action="approve_request",
        details={
            "request_id": request_id,
            "approved_by": current_user.username
        },
        access_request_id=access_request.id
    )
    db.add(audit_log)
    db.commit()
    
    return access_request

@app.post("/access-requests/{request_id}/reject", response_model=AccessRequestResponse)
def reject_access_request(
    request_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    access_request = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
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
    
    # Create audit log
    audit_log = AuditLog(
        user_id=current_user.id,
        action="reject_request",
        details={
            "request_id": request_id,
            "rejected_by": current_user.username
        },
        access_request_id=access_request.id
    )
    db.add(audit_log)
    db.commit()
    
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
        audit_log = AuditLog(
            user_id=request.user_id,
            action="request_expired",
            details={
                "request_id": request.id,
                "expired_at": datetime.utcnow().isoformat()
            },
            access_request_id=request.id
        )
        db.add(audit_log)
    
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

# Health check endpoint
@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}