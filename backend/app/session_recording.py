import os
import json
import asyncio
import logging
from datetime import datetime
from sqlalchemy.orm import Session
from typing import Dict, List, Optional, Set
import uuid
import re

from .models import RecordedSession, SessionEvent, SuspiciousCommand
from .schemas import SessionEventCreate

logger = logging.getLogger(__name__)

class SessionRecordingService:
    def __init__(self):
        self.active_sessions: Dict[str, RecordedSession] = {}
        self.suspicious_patterns = [
            r'rm\s+-rf\s+/\s*$',
            r'rm\s+-rf\s+/.*',
            r'passwd\s*$',
            r'chmod\s+777\s+.*',
            r'dd\s+if=.*',
            r'mkfs\s+.*',
            r'>\s+/dev/sda',
            r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:',
            r'wget\s+http.*',
            r'curl\s+http.*',
            r'nc\s+-l.*',
            r'ssh-keygen\s*$',
            r'cat\s+/etc/shadow\s*$',
            r'chmod\s+777\s*$',
            r'chown\s+.*\s+/.*',
            r'>\s+/etc/passwd',
            r'>\s+/etc/shadow',
            r'echo\s+.*\s+>\s+/etc/.*',
            r'mount\s+.*',
            r'umount\s+.*',
            r'fdisk\s+.*',
            r'mkfs\.\w+\s+.*',
            r'dd\s+.*=/dev/.*'
        ]
        
        # Compile regex patterns for better performance
        self.suspicious_regex = [re.compile(pattern, re.IGNORECASE) for pattern in self.suspicious_patterns]
        
        # Track suspicious command attempts per session
        self.suspicious_attempts: Dict[str, Dict[str, int]] = {}  # session_id -> {command_pattern: attempt_count}
        
        # Track current command input per session
        self.current_command_input: Dict[str, str] = {}  # session_id -> current_input

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
            self.suspicious_attempts[session_id] = {}
            self.current_command_input[session_id] = ""
            
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
            
            # Handle different event types
            if event_type == "command_input":
                # Track current command input for real-time detection
                await self._handle_command_input(session_id, data)
            elif event_type == "command_executed":
                # Command was executed - check for suspicious patterns
                await self._check_suspicious_command(db, session.id, data)
            elif event_type == "warning_triggered":
                # Record warning events
                await self._record_warning_event(db, session.id, data)
            elif event_type == "session_terminated":
                # Record session termination due to security violation
                await self._record_security_violation(db, session.id, data)
            
            db.commit()
            db.refresh(event)
            
            return event
            
        except Exception as e:
            logger.error(f"Failed to record session event: {str(e)}")
            raise

    async def _handle_command_input(self, session_id: str, input_data: str):
        """Handle real-time command input for suspicious pattern detection"""
        if session_id not in self.current_command_input:
            self.current_command_input[session_id] = ""
        
        # Update current input
        self.current_command_input[session_id] = input_data
        
        # Check for suspicious patterns in current input
        suspicious_detected = await self._check_real_time_suspicious(input_data)
        
        if suspicious_detected:
            # Return warning information that can be sent to the frontend
            return {
                "warning": True,
                "message": "Suspicious command detected. Please remove this command to continue.",
                "block_execution": True
            }
        
        return {"warning": False}

    async def _check_real_time_suspicious(self, command_input: str) -> bool:
        """Check if current command input matches suspicious patterns"""
        command_clean = command_input.strip()
        
        for pattern in self.suspicious_regex:
            if pattern.search(command_clean):
                logger.warning(f"Real-time suspicious command detected: {command_clean}")
                return True
        
        return False

    async def _check_suspicious_command(self, db: Session, session_id: int, command: str):
        """Check if an executed command matches suspicious patterns"""
        try:
            command_clean = command.strip().lower()
            session = db.query(RecordedSession).filter(RecordedSession.id == session_id).first()
            
            if not session:
                return

            suspicious_detected = False
            matched_pattern = None
            
            for pattern in self.suspicious_regex:
                if pattern.search(command_clean):
                    suspicious_detected = True
                    matched_pattern = pattern.pattern
                    break
            
            if suspicious_detected:
                # Track attempt count for this pattern
                pattern_key = matched_pattern or command_clean
                if session.session_id not in self.suspicious_attempts:
                    self.suspicious_attempts[session.session_id] = {}
                
                self.suspicious_attempts[session.session_id][pattern_key] = \
                    self.suspicious_attempts[session.session_id].get(pattern_key, 0) + 1
                
                # Record suspicious command
                suspicious_cmd = SuspiciousCommand(
                    session_id=session_id,
                    command=command,
                    severity="high",
                    attempt_count=self.suspicious_attempts[session.session_id][pattern_key]
                )
                
                db.add(suspicious_cmd)
                
                # Mark session as having suspicious activity
                session.suspicious_detected = True
                
                # Check if we should terminate the session (3+ attempts)
                attempt_count = self.suspicious_attempts[session.session_id][pattern_key]
                if attempt_count >= 3:
                    await self._terminate_session_for_security(db, session, command, attempt_count)
                
                logger.warning(f"Suspicious command detected in session {session.session_id}: {command} (attempt {attempt_count})")
                    
        except Exception as e:
            logger.error(f"Error checking suspicious command: {str(e)}")

    async def _terminate_session_for_security(self, db: Session, session: RecordedSession, command: str, attempt_count: int):
        """Terminate session due to security violation"""
        try:
            # Record security violation event
            security_event = SessionEvent(
                session_id=session.id,
                event_type="security_violation",
                data=json.dumps({
                    "command": command,
                    "attempt_count": attempt_count,
                    "action": "session_terminated",
                    "reason": "Multiple suspicious command attempts"
                }),
                sequence=await self._get_next_sequence(db, session.id),
                timestamp=datetime.utcnow()
            )
            db.add(security_event)
            
            # Update session status
            session.status = "terminated_security"
            session.ended_at = datetime.utcnow()
            
            # Calculate duration
            if session.started_at and session.ended_at:
                duration = (session.ended_at - session.started_at).total_seconds()
                session.duration = int(duration)
            
            logger.warning(f"Session {session.session_id} terminated due to security violation: {command}")
            
        except Exception as e:
            logger.error(f"Error terminating session for security: {str(e)}")

    async def _record_warning_event(self, db: Session, session_id: int, warning_data: str):
        """Record a warning event"""
        try:
            warning_event = SessionEvent(
                session_id=session_id,
                event_type="warning",
                data=warning_data,
                sequence=await self._get_next_sequence(db, session_id),
                timestamp=datetime.utcnow()
            )
            db.add(warning_event)
        except Exception as e:
            logger.error(f"Error recording warning event: {str(e)}")

    async def _record_security_violation(self, db: Session, session_id: int, violation_data: str):
        """Record a security violation event"""
        try:
            violation_event = SessionEvent(
                session_id=session_id,
                event_type="security_violation",
                data=violation_data,
                sequence=await self._get_next_sequence(db, session_id),
                timestamp=datetime.utcnow()
            )
            db.add(violation_event)
        except Exception as e:
            logger.error(f"Error recording security violation: {str(e)}")

    async def _get_next_sequence(self, db: Session, session_id: int) -> int:
        """Get the next sequence number for session events"""
        try:
            last_event = db.query(SessionEvent).filter(
                SessionEvent.session_id == session_id
            ).order_by(SessionEvent.sequence.desc()).first()
            
            return last_event.sequence + 1 if last_event else 1
        except Exception as e:
            logger.error(f"Error getting next sequence: {str(e)}")
            return 1

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
            
            # Clean up session data
            if session_id in self.active_sessions:
                del self.active_sessions[session_id]
            if session_id in self.suspicious_attempts:
                del self.suspicious_attempts[session_id]
            if session_id in self.current_command_input:
                del self.current_command_input[session_id]
            
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

    async def check_command_safety(self, session_id: str, command: str) -> Dict:
        """Check if a command is safe to execute"""
        if session_id not in self.suspicious_attempts:
            return {"safe": True, "warning": None}
        
        # Check real-time suspicious patterns
        real_time_check = await self._check_real_time_suspicious(command)
        if real_time_check:
            return {
                "safe": False,
                "warning": "This command matches suspicious patterns and cannot be executed.",
                "block_execution": True
            }
        
        # Check attempt counts for similar patterns
        command_lower = command.strip().lower()
        for pattern in self.suspicious_regex:
            if pattern.search(command_lower):
                pattern_key = pattern.pattern
                attempt_count = self.suspicious_attempts[session_id].get(pattern_key, 0)
                
                if attempt_count >= 2:  # 3rd attempt will be blocked
                    return {
                        "safe": False,
                        "warning": f"Multiple attempts to run suspicious commands detected. This will result in session termination.",
                        "block_execution": True
                    }
                elif attempt_count >= 1:
                    return {
                        "safe": True,
                        "warning": f"Warning: This command matches suspicious patterns. {2 - attempt_count} attempts remaining before session termination.",
                        "block_execution": False
                    }
        
        return {"safe": True, "warning": None}

# Global instance
session_recording_service = SessionRecordingService()