import os
import json
import asyncio
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from typing import Dict, List, Optional
import uuid

from .models import RecordedSession, SessionEvent, SuspiciousCommand
from .schemas import SessionEventCreate

logger = logging.getLogger(__name__)

class SessionRecordingService:
    def __init__(self):
        self.active_sessions: Dict[str, RecordedSession] = {}
        self.suspicious_patterns = [
            "rm -rf /", 
            "passwd", 
            "chmod 777", 
            "dd if=",
            "mkfs",
            "> /dev/sda",
            ":(){ :|:& };:",
            "wget http",
            "curl http",
            "nc -l",
            "ssh-keygen",
            "cat /etc/shadow"
        ]

    async def start_session_recording(
        self, 
        db: Session, 
        user_id: int, 
        resource_id: int, 
        access_request_id: int
    ) -> RecordedSession:
        """Start recording a new session"""
        try:
            session_id = str(uuid.uuid4())
            
            recorded_session = RecordedSession(
                access_request_id=access_request_id,
                user_id=user_id,
                resource_id=resource_id,
                session_id=session_id,
                status="recording",
                started_at=datetime.utcnow()
            )
            
            db.add(recorded_session)
            db.commit()
            db.refresh(recorded_session)
            
            self.active_sessions[session_id] = recorded_session
            
            logger.info(f"Started session recording: {session_id}")
            return recorded_session
            
        except Exception as e:
            logger.error(f"Failed to start session recording: {str(e)}")
            raise

    async def record_session_event(
        self, 
        db: Session, 
        session_id: str, 
        event_type: str, 
        data: str,
        sequence: int
    ) -> SessionEvent:
        """Record a session event (command, output, etc.)"""
        try:
            # Find the session
            session = db.query(RecordedSession).filter(
                RecordedSession.session_id == session_id
            ).first()
            
            if not session:
                raise ValueError(f"Session not found: {session_id}")
            
            # Create session event
            event = SessionEvent(
                session_id=session.id,
                event_type=event_type,
                data=data,
                sequence=sequence,
                timestamp=datetime.utcnow()
            )
            
            db.add(event)
            
            # Check for suspicious commands
            if event_type == "command":
                await self._check_suspicious_command(db, session.id, data)
            
            db.commit()
            db.refresh(event)
            
            return event
            
        except Exception as e:
            logger.error(f"Failed to record session event: {str(e)}")
            raise

    async def _check_suspicious_command(self, db: Session, session_id: int, command: str):
        """Check if a command matches suspicious patterns"""
        try:
            command_lower = command.lower().strip()
            
            for pattern in self.suspicious_patterns:
                if pattern in command_lower:
                    # Found suspicious command
                    suspicious_cmd = SuspiciousCommand(
                        session_id=session_id,
                        command=command,
                        severity="high" if pattern in ["rm -rf /", "> /dev/sda"] else "medium"
                    )
                    
                    db.add(suspicious_cmd)
                    
                    # Mark session as having suspicious activity
                    session = db.query(RecordedSession).filter(RecordedSession.id == session_id).first()
                    if session:
                        session.suspicious_detected = True
                    
                    logger.warning(f"Suspicious command detected in session {session_id}: {command}")
                    break
                    
        except Exception as e:
            logger.error(f"Error checking suspicious command: {str(e)}")

    async def stop_session_recording(
        self, 
        db: Session, 
        session_id: str
    ) -> RecordedSession:
        """Stop recording a session"""
        try:
            session = db.query(RecordedSession).filter(
                RecordedSession.session_id == session_id
            ).first()
            
            if not session:
                raise ValueError(f"Session not found: {session_id}")
            
            session.ended_at = datetime.utcnow()
            session.status = "completed"
            
            # Calculate duration
            if session.started_at and session.ended_at:
                duration = (session.ended_at - session.started_at).total_seconds()
                session.duration = int(duration)
            
            db.commit()
            db.refresh(session)
            
            # Remove from active sessions
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
            
            logger.info(f"Stopped session recording: {session_id}, duration: {session.duration}s")
            return session
            
        except Exception as e:
            logger.error(f"Failed to stop session recording: {str(e)}")
            raise

    async def get_session_playback_data(
        self, 
        db: Session, 
        session_id: str
    ) -> Dict:
        """Get session data for playback"""
        try:
            session = db.query(RecordedSession).filter(
                RecordedSession.session_id == session_id
            ).first()
            
            if not session:
                raise ValueError(f"Session not found: {session_id}")
            
            # Get all events for this session, ordered by sequence
            events = db.query(SessionEvent).filter(
                SessionEvent.session_id == session.id
            ).order_by(SessionEvent.sequence).all()
            
            # Get suspicious commands
            suspicious_commands = db.query(SuspiciousCommand).filter(
                SuspiciousCommand.session_id == session.id
            ).all()
            
            return {
                "session": session,
                "events": events,
                "suspicious_commands": suspicious_commands
            }
            
        except Exception as e:
            logger.error(f"Failed to get session playback data: {str(e)}")
            raise

    async def get_user_sessions(
        self, 
        db: Session, 
        user_id: int, 
        limit: int = 50, 
        offset: int = 0
    ) -> List[RecordedSession]:
        """Get sessions for a specific user"""
        try:
            sessions = db.query(RecordedSession).filter(
                RecordedSession.user_id == user_id
            ).order_by(RecordedSession.started_at.desc()).offset(offset).limit(limit).all()
            
            return sessions
            
        except Exception as e:
            logger.error(f"Failed to get user sessions: {str(e)}")
            raise

    async def get_all_sessions(
        self, 
        db: Session, 
        limit: int = 50, 
        offset: int = 0
    ) -> List[RecordedSession]:
        """Get all sessions (admin only)"""
        try:
            sessions = db.query(RecordedSession).order_by(
                RecordedSession.started_at.desc()
            ).offset(offset).limit(limit).all()
            
            return sessions
            
        except Exception as e:
            logger.error(f"Failed to get all sessions: {str(e)}")
            raise

# Global instance
session_recording_service = SessionRecordingService()