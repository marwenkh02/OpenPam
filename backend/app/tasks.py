import asyncio
import datetime
from celery import Celery
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import Resource, ResourceCheck
from .health_check import health_check_service

# Celery configuration
celery_app = Celery('openpam_tasks')
celery_app.conf.broker_url = 'redis://localhost:6379/0'
celery_app.conf.result_backend = 'redis://localhost:6379/0'

@celery_app.task
def check_single_resource(resource_id: int):
    """Check health of a single resource"""
    db = SessionLocal()
    try:
        resource = db.query(Resource).filter(Resource.id == resource_id).first()
        if resource and resource.is_active:
            asyncio.run(perform_health_check(db, resource))
    finally:
        db.close()

@celery_app.task
def check_all_resources():
    """Check health of all active resources"""
    db = SessionLocal()
    try:
        resources = db.query(Resource).filter(Resource.is_active == True).all()
        for resource in resources:
            asyncio.run(perform_health_check(db, resource))
    finally:
        db.close()

async def perform_health_check(db: Session, resource: Resource):
    """Perform health check and update database"""
    try:
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
        
    except Exception as e:
        print(f"Health check failed for resource {resource.id}: {str(e)}")