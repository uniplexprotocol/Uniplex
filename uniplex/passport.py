"""
Uniplex Passport - Agent identity and permissions.

A Passport is the core identity document for an AI agent. It contains:
- Agent identity (agent_id)
- Permissions (what actions the agent can take)
- Provenance (who issued it, when, expiration)
- Cryptographic proof (signature + public key for self-issued)
"""

import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

from . import crypto


class PassportIdentity(BaseModel):
    """Agent identity information."""
    agent_id: str


class PassportIssuer(BaseModel):
    """Issuer information."""
    id: str
    type: str = "self"  # "self", "internal", "verified", "certified"


class PassportProvenance(BaseModel):
    """Provenance information - who issued, when, expiration."""
    issuer: PassportIssuer
    issued_at: str  # ISO 8601
    expires_at: str  # ISO 8601


class PassportPermission(BaseModel):
    """A single permission grant."""
    action: str  # Action pattern, e.g. "tools:*" or "*"
    target: Optional[str] = None  # Optional target restriction


class Passport(BaseModel):
    """
    Uniplex Passport - the agent's identity and authorization document.
    
    For L1 (self-issued), the passport contains an embedded public key
    and is signed with the corresponding private key.
    """
    
    uni_version: str = "2026-01-25"
    passport_id: str
    identity: PassportIdentity
    permissions: List[PassportPermission]
    provenance: PassportProvenance
    public_key: Optional[str] = None  # Base64-encoded, for self-issued
    signature: Optional[str] = None  # Base64-encoded Ed25519 signature
    
    # Not serialized - used for signing
    _private_key: Optional[bytes] = None
    
    model_config = ConfigDict(extra="allow")  # Allow extension fields
    
    @classmethod
    def create_self_issued(
        cls,
        agent_id: str,
        permissions: Union[str, List[str]] = "*",
        expires_in: timedelta = timedelta(days=7),
        passport_id: Optional[str] = None,
    ) -> "Passport":
        """
        Create a new self-issued (L1) passport.
        
        Args:
            agent_id: Unique identifier for the agent
            permissions: Permission pattern(s). Use "*" for all, or list like ["tools:*", "mcp:*"]
            expires_in: How long until the passport expires (default 7 days)
            passport_id: Optional custom passport ID (auto-generated if not provided)
        
        Returns:
            A signed Passport ready for use
        """
        # Generate keypair
        private_key, public_key = crypto.generate_keypair()
        
        # Normalize permissions
        if isinstance(permissions, str):
            permissions = [permissions]
        perm_objects = [PassportPermission(action=p) for p in permissions]
        
        # Timestamps
        now = datetime.now(timezone.utc)
        issued_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        expires_at = (now + expires_in).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Create passport
        passport = cls(
            passport_id=passport_id or f"uni_{uuid.uuid4().hex[:16]}",
            identity=PassportIdentity(agent_id=agent_id),
            permissions=perm_objects,
            provenance=PassportProvenance(
                issuer=PassportIssuer(id=agent_id, type="self"),
                issued_at=issued_at,
                expires_at=expires_at,
            ),
            public_key=crypto.encode_base64(crypto.public_key_to_bytes(public_key)),
        )
        
        # Store private key for signing
        passport._private_key = crypto.private_key_to_bytes(private_key)
        
        # Sign the passport
        passport._sign()
        
        return passport
    
    def _sign(self) -> None:
        """Sign the passport with the stored private key."""
        if self._private_key is None:
            raise ValueError("No private key available for signing")
        
        private_key = crypto.private_key_from_bytes(self._private_key)
        
        # Get canonical JSON of passport (without signature)
        data = self.to_signable_dict()
        message = crypto.canonical_json(data)
        
        # Sign
        sig = crypto.sign(private_key, message)
        self.signature = crypto.encode_base64(sig)
    
    def to_signable_dict(self) -> dict:
        """Get passport data for signing (excludes signature field)."""
        data = self.model_dump(exclude={"signature"}, exclude_none=True)
        # Remove any private fields
        data = {k: v for k, v in data.items() if not k.startswith("_")}
        return data
    
    def to_dict(self) -> dict:
        """Export passport as dictionary (for JSON serialization)."""
        data = self.model_dump(exclude_none=True)
        # Remove any private fields
        return {k: v for k, v in data.items() if not k.startswith("_")}
    
    def to_json(self, indent: Optional[int] = 2) -> str:
        """Export passport as JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
    
    def save(self, path: str) -> None:
        """Save passport to a JSON file."""
        with open(path, "w") as f:
            f.write(self.to_json())
    
    def save_with_key(self, passport_path: str, key_path: str) -> None:
        """Save passport and private key to separate files."""
        self.save(passport_path)
        if self._private_key:
            with open(key_path, "wb") as f:
                f.write(self._private_key)
    
    @classmethod
    def load(cls, path: str) -> "Passport":
        """Load passport from a JSON file."""
        with open(path, "r") as f:
            data = json.load(f)
        return cls.model_validate(data)
    
    @classmethod
    def from_json(cls, json_str: str) -> "Passport":
        """Parse passport from JSON string."""
        data = json.loads(json_str)
        return cls.model_validate(data)
    
    @classmethod
    def from_dict(cls, data: dict) -> "Passport":
        """Create passport from dictionary."""
        return cls.model_validate(data)
    
    @classmethod
    def from_env(cls, env_var: str = "UNIPLEX_PASSPORT") -> "Passport":
        """
        Load passport from environment variable.
        
        The env var can contain either:
        - A JSON string of the passport
        - A file path to the passport JSON
        """
        value = os.environ.get(env_var)
        if not value:
            raise ValueError(f"Environment variable {env_var} not set")
        
        # Check if it's a file path
        if os.path.isfile(value):
            return cls.load(value)
        
        # Otherwise treat as JSON string
        return cls.from_json(value)
    
    def verify_signature(self) -> bool:
        """
        Verify the passport's signature using its embedded public key.
        
        Returns True if signature is valid, False otherwise.
        """
        if not self.signature or not self.public_key:
            return False
        
        try:
            # Decode public key and signature
            public_key_bytes = crypto.decode_base64(self.public_key)
            signature_bytes = crypto.decode_base64(self.signature)
            public_key = crypto.public_key_from_bytes(public_key_bytes)
            
            # Get canonical JSON of signable content
            data = self.to_signable_dict()
            message = crypto.canonical_json(data)
            
            # Verify
            return crypto.verify(public_key, signature_bytes, message)
        except Exception:
            return False
    
    def is_expired(self) -> bool:
        """Check if the passport has expired."""
        try:
            expires_at = datetime.fromisoformat(
                self.provenance.expires_at.replace("Z", "+00:00")
            )
            return datetime.now(timezone.utc) > expires_at
        except Exception:
            return True
    
    def has_permission(self, action: str) -> bool:
        """
        Check if this passport grants permission for an action.
        
        Supports wildcard matching:
        - "*" matches everything
        - "tools:*" matches "tools:search", "tools:read", etc.
        """
        for perm in self.permissions:
            if self._action_matches(perm.action, action):
                return True
        return False
    
    @staticmethod
    def _action_matches(pattern: str, action: str) -> bool:
        """Check if an action matches a permission pattern."""
        if pattern == "*":
            return True
        if pattern == action:
            return True
        if pattern.endswith(":*"):
            prefix = pattern[:-1]  # "tools:*" -> "tools:"
            return action.startswith(prefix)
        return False
