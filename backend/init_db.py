# init_db.py
from app.database import engine, Base
from app.models import User, Role, Resource, AccessRequest, AuditLog, Credential, RecordedSession, SuspiciousCommand, RotationHistory, UserSession

def init_db():
    # Drop all tables
    Base.metadata.drop_all(bind=engine)
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    print("Database tables recreated successfully!")

if __name__ == "__main__":
    init_db()