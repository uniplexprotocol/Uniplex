"""
Uniplex Proof of Possession (PoP) - Binding requests to passport holders.

PoP proves that the entity making a request actually controls the private key
associated with the passport. This prevents replay attacks and credential theft.

Required for L2+ trust profiles.

Per spec section 4.12:
- PoP is a signed JWT-like structure
- Contains: jti (nonce), iat (timestamp), aud (target), passport_id
- Signed with the passport's private key
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from pydantic import BaseModel, Field

from . import crypto


class PoPPayload(BaseModel):
    """Proof of Possession payload."""
    
    jti: str = Field(default_factory=lambda: f"pop_{uuid.uuid4().hex[:16]}")
    iat: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    passport_id: str
    aud: str  # Target audience (e.g., MCP server ID)
    
    # Optional session binding
    session_nonce: Optional[str] = None


class ProofOfPossession(BaseModel):
    """
    Proof of Possession - proves control of passport private key.
    
    Structure:
    {
        "payload": { "jti": "...", "iat": "...", "passport_id": "...", "aud": "..." },
        "signature": "base64...",
        "public_key": "base64..."
    }
    """
    
    payload: PoPPayload
    signature: Optional[str] = None
    public_key: Optional[str] = None
    
    @classmethod
    def create(
        cls,
        passport_id: str,
        audience: str,
        private_key_bytes: bytes,
        session_nonce: Optional[str] = None,
    ) -> "ProofOfPossession":
        """
        Create a new Proof of Possession.
        
        Args:
            passport_id: ID of the passport being proven
            audience: Target audience (e.g., "mcp://tools.example.com")
            private_key_bytes: Raw bytes of the passport's private key
            session_nonce: Optional session nonce for binding
        
        Returns:
            Signed ProofOfPossession
        """
        payload = PoPPayload(
            passport_id=passport_id,
            aud=audience,
            session_nonce=session_nonce,
        )
        
        pop = cls(payload=payload)
        pop._sign(private_key_bytes)
        return pop
    
    def _sign(self, private_key_bytes: bytes) -> None:
        """Sign the PoP with the given private key."""
        private_key = crypto.private_key_from_bytes(private_key_bytes)
        public_key = private_key.public_key()
        
        # Canonical JSON of payload
        payload_dict = self.payload.model_dump(exclude_none=True)
        message = crypto.canonical_json(payload_dict)
        
        # Sign
        sig = crypto.sign(private_key, message)
        self.signature = crypto.encode_base64(sig)
        self.public_key = crypto.encode_base64(crypto.public_key_to_bytes(public_key))
    
    def verify(self, expected_public_key: Optional[str] = None) -> bool:
        """
        Verify the PoP signature.
        
        Args:
            expected_public_key: If provided, also verify the public key matches
        
        Returns:
            True if signature is valid
        """
        if not self.signature or not self.public_key:
            return False
        
        # Check public key matches if expected
        if expected_public_key and self.public_key != expected_public_key:
            return False
        
        try:
            public_key_bytes = crypto.decode_base64(self.public_key)
            signature_bytes = crypto.decode_base64(self.signature)
            public_key = crypto.public_key_from_bytes(public_key_bytes)
            
            payload_dict = self.payload.model_dump(exclude_none=True)
            message = crypto.canonical_json(payload_dict)
            
            return crypto.verify(public_key, signature_bytes, message)
        except Exception:
            return False
    
    def verify_audience(self, expected_audience: str) -> bool:
        """
        Verify the PoP audience matches the expected target.
        
        Per spec 4.12.4.1: aud can be string or array.
        """
        aud = self.payload.aud
        
        # Handle array case (though our model uses string)
        if isinstance(aud, list):
            return expected_audience in aud
        
        return aud == expected_audience
    
    def is_expired(self, max_age_seconds: int = 300) -> bool:
        """
        Check if the PoP has expired.
        
        Args:
            max_age_seconds: Maximum age in seconds (default 5 minutes)
        
        Returns:
            True if expired
        """
        try:
            iat = datetime.fromisoformat(self.payload.iat.replace("Z", "+00:00"))
            age = datetime.now(timezone.utc) - iat
            return age.total_seconds() > max_age_seconds
        except Exception:
            return True
    
    def to_dict(self) -> dict:
        """Export as dictionary."""
        return {
            "payload": self.payload.model_dump(exclude_none=True),
            "signature": self.signature,
            "public_key": self.public_key,
        }
    
    def to_json(self) -> str:
        """Export as JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: dict) -> "ProofOfPossession":
        """Create from dictionary."""
        payload = PoPPayload.model_validate(data["payload"])
        return cls(
            payload=payload,
            signature=data.get("signature"),
            public_key=data.get("public_key"),
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> "ProofOfPossession":
        """Create from JSON string."""
        return cls.from_dict(json.loads(json_str))


class PoPVerifier:
    """
    Verifier for Proof of Possession tokens.
    
    Used by Gates to validate PoP in L2+ requests.
    """
    
    def __init__(
        self,
        max_age_seconds: int = 300,
        require_session_nonce: bool = False,
    ):
        """
        Create a PoP verifier.
        
        Args:
            max_age_seconds: Maximum age of PoP (default 5 minutes)
            require_session_nonce: Whether to require session binding
        """
        self.max_age_seconds = max_age_seconds
        self.require_session_nonce = require_session_nonce
        self._used_nonces: set = set()  # For replay protection
    
    def verify(
        self,
        pop: ProofOfPossession,
        expected_passport_id: str,
        expected_audience: str,
        expected_public_key: str,
        expected_session_nonce: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
        """
        Verify a Proof of Possession.
        
        Args:
            pop: The PoP to verify
            expected_passport_id: The passport ID it should reference
            expected_audience: The target it should be bound to
            expected_public_key: The public key from the passport
            expected_session_nonce: Expected session nonce (if required)
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        # 1. Verify signature
        if not pop.verify(expected_public_key):
            return False, "POP_INVALID_SIGNATURE"
        
        # 2. Check passport ID matches
        if pop.payload.passport_id != expected_passport_id:
            return False, "POP_PASSPORT_MISMATCH"
        
        # 3. Check audience
        if not pop.verify_audience(expected_audience):
            return False, "POP_AUD_MISMATCH"
        
        # 4. Check expiration
        if pop.is_expired(self.max_age_seconds):
            return False, "POP_EXPIRED"
        
        # 5. Check replay (nonce reuse)
        if pop.payload.jti in self._used_nonces:
            return False, "POP_REPLAY_DETECTED"
        
        # 6. Check session nonce if required
        if self.require_session_nonce:
            if not pop.payload.session_nonce:
                return False, "POP_SESSION_NONCE_MISSING"
            if expected_session_nonce and pop.payload.session_nonce != expected_session_nonce:
                return False, "POP_SESSION_NONCE_MISMATCH"
        
        # Mark nonce as used
        self._used_nonces.add(pop.payload.jti)
        
        return True, None
    
    def clear_nonces(self) -> None:
        """Clear the used nonces set (for testing or periodic cleanup)."""
        self._used_nonces.clear()
