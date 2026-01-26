"""
Uniplex Attestation - Proof of authorization decisions.

An Attestation is a signed record of a Gate decision. It provides:
- Proof that an authorization check occurred
- What was checked (passport, action, target)
- What was decided (allow/deny)
- When it happened
- Cryptographic proof of integrity

Attestations can be stored, transmitted, and verified later.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from . import crypto
from .gate import GateDecision, GateRequest


class Attestation(BaseModel):
    """
    Uniplex Attestation - Signed proof of an authorization decision.
    
    Attestations provide an audit trail and can be verified by third parties
    to confirm that an authorization check was performed.
    """
    
    uni_version: str = "2026-01-25"
    attestation_id: str = Field(default_factory=lambda: f"att_{uuid.uuid4().hex[:16]}")
    
    # What was attested
    request_id: str
    passport_id: Optional[str] = None
    agent_id: Optional[str] = None
    action: str
    target: Optional[str] = None
    
    # The decision
    decision: str  # "allow" or "deny"
    reason_code: Optional[str] = None
    
    # Timing
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    
    # Gate identity
    gate_id: Optional[str] = None
    
    # Cryptographic proof
    public_key: Optional[str] = None  # Base64 encoded
    signature: Optional[str] = None  # Base64 encoded
    
    # Internal - not serialized
    _private_key: Optional[bytes] = None
    
    model_config = ConfigDict(extra="allow")
    
    @classmethod
    def from_decision(
        cls,
        request: GateRequest,
        decision: GateDecision,
        gate_id: Optional[str] = None,
        sign: bool = True,
    ) -> "Attestation":
        """
        Create an attestation from a gate decision.
        
        Args:
            request: The original authorization request
            decision: The gate's decision
            gate_id: Optional identifier for the gate
            sign: Whether to sign the attestation (default True)
        
        Returns:
            A new Attestation, optionally signed
        """
        attestation = cls(
            request_id=request.request_id,
            passport_id=decision.passport_id,
            agent_id=decision.agent_id,
            action=request.action,
            target=request.target,
            decision=decision.decision,
            reason_code=decision.reason_code,
            gate_id=gate_id,
        )
        
        if sign:
            attestation.sign_self()
        
        return attestation
    
    def sign_self(self) -> None:
        """
        Generate a new keypair and sign the attestation.
        
        This is useful for quick attestation generation where the
        gate doesn't have persistent identity.
        """
        private_key, public_key = crypto.generate_keypair()
        self._private_key = crypto.private_key_to_bytes(private_key)
        self.public_key = crypto.encode_base64(crypto.public_key_to_bytes(public_key))
        self._sign()
    
    def sign_with_key(self, private_key_bytes: bytes) -> None:
        """
        Sign the attestation with an existing private key.
        
        Args:
            private_key_bytes: Raw bytes of the Ed25519 private key
        """
        private_key = crypto.private_key_from_bytes(private_key_bytes)
        public_key = private_key.public_key()
        
        self._private_key = private_key_bytes
        self.public_key = crypto.encode_base64(crypto.public_key_to_bytes(public_key))
        self._sign()
    
    def _sign(self) -> None:
        """Sign the attestation with the stored private key."""
        if self._private_key is None:
            raise ValueError("No private key available for signing")
        
        private_key = crypto.private_key_from_bytes(self._private_key)
        
        # Get canonical JSON of attestation (without signature)
        data = self.to_signable_dict()
        message = crypto.canonical_json(data)
        
        # Sign
        sig = crypto.sign(private_key, message)
        self.signature = crypto.encode_base64(sig)
    
    def to_signable_dict(self) -> dict:
        """Get attestation data for signing (excludes signature field)."""
        data = self.model_dump(exclude={"signature"}, exclude_none=True)
        # Remove any private fields
        return {k: v for k, v in data.items() if not k.startswith("_")}
    
    def to_dict(self) -> dict:
        """Export attestation as dictionary."""
        data = self.model_dump(exclude_none=True)
        return {k: v for k, v in data.items() if not k.startswith("_")}
    
    def to_json(self, indent: Optional[int] = 2) -> str:
        """Export attestation as JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
    
    def verify_signature(self) -> bool:
        """
        Verify the attestation's signature.
        
        Returns True if signature is valid, False otherwise.
        """
        if not self.signature or not self.public_key:
            return False
        
        try:
            public_key_bytes = crypto.decode_base64(self.public_key)
            signature_bytes = crypto.decode_base64(self.signature)
            public_key = crypto.public_key_from_bytes(public_key_bytes)
            
            data = self.to_signable_dict()
            message = crypto.canonical_json(data)
            
            return crypto.verify(public_key, signature_bytes, message)
        except Exception:
            return False
    
    @classmethod
    def from_json(cls, json_str: str) -> "Attestation":
        """Parse attestation from JSON string."""
        data = json.loads(json_str)
        return cls.model_validate(data)
    
    @classmethod
    def from_dict(cls, data: dict) -> "Attestation":
        """Create attestation from dictionary."""
        return cls.model_validate(data)
    
    @property
    def allowed(self) -> bool:
        """Check if this attestation records an allow decision."""
        return self.decision == "allow"
    
    @property
    def denied(self) -> bool:
        """Check if this attestation records a deny decision."""
        return self.decision == "deny"
