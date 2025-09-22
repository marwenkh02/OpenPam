from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import logging
from jose import JWTError, jwt

from .database import SessionLocal, engine, get_db
from .models import User, Base, AccessRequest, Resource
from .schemas import (
    UserCreate, UserResponse, Token, LoginRequest, 
    MFAEnableRequest, MFAResponse, PasswordChangeRequest,
    AccessRequestCreate, AccessRequestResponse
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

@app.post("/access-requests/", response_model=AccessRequestResponse)
def create_access_request(
    request_data: AccessRequestCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check if resource exists
    resource = db.query(Resource).filter(Resource.id == request_data.resource_id).first()
    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found"
        )
    
    # Create access request
    access_request = AccessRequest(
        user_id=current_user.id,
        resource_id=request_data.resource_id,
        reason=request_data.reason,
        expires_at=datetime.utcnow() + timedelta(minutes=request_data.duration_minutes)
    )
    
    db.add(access_request)
    db.commit()
    db.refresh(access_request)
    
    return access_request

@app.get("/access-requests/", response_model=list[AccessRequestResponse])
def get_access_requests(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.is_admin:
        access_requests = db.query(AccessRequest).all()
    else:
        access_requests = db.query(AccessRequest).filter(
            AccessRequest.user_id == current_user.id
        ).all()
    
    return access_requests