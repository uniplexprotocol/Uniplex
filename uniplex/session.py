"""
Uniplex Sessions - Managing ongoing authorization relationships.

Sessions allow:
- Reduced overhead for repeated authorizations
- Session-bound PoP for enhanced security
- Audit trails across related requests

Per spec: Session tokens use ISO 8601 timestamps, not epoch seconds.
"""

import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Set

from pydantic import BaseModel, Field

from . import crypto
from .passport import Passport


class SessionToken(BaseModel):
    """
    Session token for ongoing authorization.
    
    Contains session metadata and can be used for session-bound PoP.
    """
    
    session_id: str = Field(default_factory=lambda: f"ses_{uuid.uuid4().hex[:16]}")
    nonce: str = Field(default_factory=lambda: secrets.token_urlsafe(16))
    
    # Passport binding
    passport_id: str
    agent_id: str
    
    # Target binding
    target: Optional[str] = None
    
    # Timing (ISO 8601 per spec)
    iat: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    exp: str  # Required - when session expires
    
    # Permissions granted for this session
    permissions: list[str] = Field(default_factory=list)
    
    # Metadata
    metadata: Dict = Field(default_factory=dict)
    
    @classmethod
    def create(
        cls,
        passport: Passport,
        target: Optional[str] = None,
        duration: timedelta = timedelta(hours=1),
        permissions: Optional[list[str]] = None,
    ) -> "SessionToken":
        """
        Create a new session token.
        
        Args:
            passport: The passport to bind the session to
            target: Optional target binding
            duration: Session duration (default 1 hour)
            permissions: Permissions for this session (default: passport permissions)
        
        Returns:
            New SessionToken
        """
        now = datetime.now(timezone.utc)
        exp = now + duration
        
        # Default to passport permissions
        if permissions is None:
            permissions = [p.action for p in passport.permissions]
        
        return cls(
            passport_id=passport.passport_id,
            agent_id=passport.identity.agent_id,
            target=target,
            exp=exp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            permissions=permissions,
        )
    
    def is_expired(self) -> bool:
        """Check if the session has expired."""
        try:
            exp = datetime.fromisoformat(self.exp.replace("Z", "+00:00"))
            return datetime.now(timezone.utc) > exp
        except Exception:
            return True
    
    def is_valid_for(self, passport_id: str, action: Optional[str] = None) -> bool:
        """
        Check if session is valid for a given passport and action.
        
        Args:
            passport_id: Passport ID to check
            action: Optional action to check permission for
        
        Returns:
            True if session is valid
        """
        if self.is_expired():
            return False
        
        if self.passport_id != passport_id:
            return False
        
        if action and not self._has_permission(action):
            return False
        
        return True
    
    def _has_permission(self, action: str) -> bool:
        """Check if session grants permission for action."""
        for perm in self.permissions:
            if perm == "*":
                return True
            if perm == action:
                return True
            if perm.endswith(":*"):
                prefix = perm[:-1]
                if action.startswith(prefix):
                    return True
        return False
    
    def to_dict(self) -> dict:
        """Export as dictionary."""
        return self.model_dump(exclude_none=True)
    
    def to_json(self) -> str:
        """Export as JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: dict) -> "SessionToken":
        """Create from dictionary."""
        return cls.model_validate(data)
    
    @classmethod
    def from_json(cls, json_str: str) -> "SessionToken":
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


class SessionManager:
    """
    Manager for authorization sessions.
    
    Provides session creation, validation, and cleanup.
    """
    
    def __init__(
        self,
        default_duration: timedelta = timedelta(hours=1),
        max_sessions_per_agent: int = 10,
    ):
        """
        Create a session manager.
        
        Args:
            default_duration: Default session duration
            max_sessions_per_agent: Maximum concurrent sessions per agent
        """
        self.default_duration = default_duration
        self.max_sessions_per_agent = max_sessions_per_agent
        
        self._sessions: Dict[str, SessionToken] = {}  # session_id -> token
        self._agent_sessions: Dict[str, Set[str]] = {}  # agent_id -> set of session_ids
        self._revoked: Set[str] = set()  # Revoked session IDs
    
    def create_session(
        self,
        passport: Passport,
        target: Optional[str] = None,
        duration: Optional[timedelta] = None,
        permissions: Optional[list[str]] = None,
    ) -> SessionToken:
        """
        Create a new session for a passport.
        
        Args:
            passport: The passport to create session for
            target: Optional target binding
            duration: Session duration (uses default if not provided)
            permissions: Session permissions (uses passport permissions if not provided)
        
        Returns:
            New SessionToken
        """
        # Check max sessions
        agent_id = passport.identity.agent_id
        if agent_id in self._agent_sessions:
            if len(self._agent_sessions[agent_id]) >= self.max_sessions_per_agent:
                # Clean up expired sessions first
                self._cleanup_agent_sessions(agent_id)
                # Check again
                if len(self._agent_sessions.get(agent_id, set())) >= self.max_sessions_per_agent:
                    raise ValueError(f"Maximum sessions reached for agent {agent_id}")
        
        # Create session
        token = SessionToken.create(
            passport=passport,
            target=target,
            duration=duration or self.default_duration,
            permissions=permissions,
        )
        
        # Store
        self._sessions[token.session_id] = token
        if agent_id not in self._agent_sessions:
            self._agent_sessions[agent_id] = set()
        self._agent_sessions[agent_id].add(token.session_id)
        
        return token
    
    def get_session(self, session_id: str) -> Optional[SessionToken]:
        """Get a session by ID."""
        if session_id in self._revoked:
            return None
        return self._sessions.get(session_id)
    
    def validate_session(
        self,
        session_id: str,
        passport_id: str,
        action: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
        """
        Validate a session.
        
        Args:
            session_id: Session ID to validate
            passport_id: Expected passport ID
            action: Optional action to check permission for
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if session_id in self._revoked:
            return False, "SESSION_REVOKED"
        
        session = self._sessions.get(session_id)
        if not session:
            return False, "SESSION_NOT_FOUND"
        
        if session.is_expired():
            return False, "SESSION_EXPIRED"
        
        if session.passport_id != passport_id:
            return False, "SESSION_PASSPORT_MISMATCH"
        
        if action and not session._has_permission(action):
            return False, "SESSION_PERMISSION_DENIED"
        
        return True, None
    
    def revoke_session(self, session_id: str) -> bool:
        """
        Revoke a session.
        
        Args:
            session_id: Session to revoke
        
        Returns:
            True if session was found and revoked
        """
        if session_id in self._sessions:
            self._revoked.add(session_id)
            session = self._sessions[session_id]
            if session.agent_id in self._agent_sessions:
                self._agent_sessions[session.agent_id].discard(session_id)
            del self._sessions[session_id]
            return True
        return False
    
    def revoke_all_for_agent(self, agent_id: str) -> int:
        """
        Revoke all sessions for an agent.
        
        Returns:
            Number of sessions revoked
        """
        session_ids = self._agent_sessions.get(agent_id, set()).copy()
        count = 0
        for session_id in session_ids:
            if self.revoke_session(session_id):
                count += 1
        return count
    
    def _cleanup_agent_sessions(self, agent_id: str) -> None:
        """Remove expired sessions for an agent."""
        if agent_id not in self._agent_sessions:
            return
        
        expired = []
        for session_id in self._agent_sessions[agent_id]:
            session = self._sessions.get(session_id)
            if not session or session.is_expired():
                expired.append(session_id)
        
        for session_id in expired:
            self._agent_sessions[agent_id].discard(session_id)
            self._sessions.pop(session_id, None)
    
    def cleanup_expired(self) -> int:
        """
        Remove all expired sessions.
        
        Returns:
            Number of sessions removed
        """
        expired = []
        for session_id, session in self._sessions.items():
            if session.is_expired():
                expired.append(session_id)
        
        for session_id in expired:
            session = self._sessions.pop(session_id, None)
            if session and session.agent_id in self._agent_sessions:
                self._agent_sessions[session.agent_id].discard(session_id)
        
        return len(expired)
    
    def get_agent_sessions(self, agent_id: str) -> list[SessionToken]:
        """Get all active sessions for an agent."""
        self._cleanup_agent_sessions(agent_id)
        session_ids = self._agent_sessions.get(agent_id, set())
        return [self._sessions[sid] for sid in session_ids if sid in self._sessions]


# Global session manager
_default_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get the default session manager."""
    global _default_manager
    if _default_manager is None:
        _default_manager = SessionManager()
    return _default_manager


def set_session_manager(manager: SessionManager) -> None:
    """Set the default session manager."""
    global _default_manager
    _default_manager = manager
