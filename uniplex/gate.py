"""
Uniplex Gate - Authorization enforcement point.

A Gate receives authorization requests and makes allow/deny decisions
based on the passport's validity, permissions, and the gate's policy.

For L1 (self-issued passports), the Gate performs:
1. Signature verification (using embedded public key)
2. Expiration check
3. Issuer policy (allow_self_issued must be true)
4. Permission check (action must match granted permissions)

For L2+ (verified/certified), the Gate additionally performs:
5. Issuer trust verification (via registry)
6. Proof of Possession verification
7. Revocation checking
"""

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Optional, Union

from pydantic import BaseModel, Field

from .passport import Passport

# Avoid circular imports
if TYPE_CHECKING:
    from .pop import ProofOfPossession, PoPVerifier
    from .registry import TrustRegistry, TrustResolver


class TrustProfile(str, Enum):
    """Trust profile levels."""
    L1 = "L1"  # Self-issued passports allowed
    L2 = "L2"  # Verified issuers required
    L3 = "L3"  # Certified issuers required


class DenyReason(str, Enum):
    """Standardized denial reason codes."""
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    PASSPORT_EXPIRED = "PASSPORT_EXPIRED"
    ISSUER_NOT_ALLOWED = "ISSUER_NOT_ALLOWED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    INVALID_REQUEST = "INVALID_REQUEST"
    PASSPORT_MISSING = "PASSPORT_MISSING"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    # L2+ reasons
    POP_REQUIRED = "POP_REQUIRED"
    POP_INVALID = "POP_INVALID"
    POP_EXPIRED = "POP_EXPIRED"
    POP_AUD_MISMATCH = "POP_AUD_MISMATCH"
    POP_PASSPORT_MISMATCH = "POP_PASSPORT_MISMATCH"
    POP_REPLAY_DETECTED = "POP_REPLAY_DETECTED"
    ISSUER_REVOKED = "ISSUER_REVOKED"
    ISSUER_NOT_VERIFIED = "ISSUER_NOT_VERIFIED"
    SESSION_INVALID = "SESSION_INVALID"


class GatePolicy(BaseModel):
    """Gate authorization policy."""
    allow_self_issued: bool = True  # Required for L1
    allowed_issuers: Optional[list[str]] = None  # For L2+, allowlist of issuer IDs
    
    @classmethod
    def for_profile(cls, profile: TrustProfile) -> "GatePolicy":
        """Create a policy for the given trust profile."""
        if profile == TrustProfile.L1:
            return cls(allow_self_issued=True)
        elif profile == TrustProfile.L2:
            return cls(allow_self_issued=False, allowed_issuers=[])
        else:  # L3
            return cls(allow_self_issued=False, allowed_issuers=[])


class GateRequest(BaseModel):
    """
    Authorization request to a Gate.
    
    Contains the passport, requested action, and optional target.
    """
    uni_version: str = "2026-01-25"
    request_id: str = Field(default_factory=lambda: f"req_{uuid.uuid4().hex[:12]}")
    passport: dict  # Raw passport data
    action: str  # The action being requested
    target: Optional[str] = None  # Optional target (e.g., MCP server ID)
    issued_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    parameters: Optional[dict] = None  # Optional action parameters
    pop: Optional[dict] = None  # Proof of Possession for L2+
    session_id: Optional[str] = None  # Session binding
    extensions: Optional[dict] = None  # Extension fields
    
    @classmethod
    def create(
        cls,
        passport: Union[Passport, dict],
        action: str,
        target: Optional[str] = None,
        parameters: Optional[dict] = None,
        pop: Optional[dict] = None,
        session_id: Optional[str] = None,
    ) -> "GateRequest":
        """Create an authorization request."""
        passport_data = passport.to_dict() if isinstance(passport, Passport) else passport
        return cls(
            passport=passport_data,
            action=action,
            target=target,
            parameters=parameters,
            pop=pop,
            session_id=session_id,
        )


class GateDecision(BaseModel):
    """
    Authorization decision from a Gate.
    
    Contains the decision (allow/deny), reason, and metadata.
    """
    uni_version: str = "2026-01-25"
    request_id: str
    decision: str  # "allow" or "deny"
    reason: Optional[str] = None  # Human-readable reason
    reason_code: Optional[str] = None  # Machine-readable code (DenyReason)
    decision_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    passport_id: Optional[str] = None
    agent_id: Optional[str] = None
    action: Optional[str] = None
    
    @property
    def allowed(self) -> bool:
        """Check if the decision allows the action."""
        return self.decision == "allow"
    
    @property
    def denied(self) -> bool:
        """Check if the decision denies the action."""
        return self.decision == "deny"


class Gate:
    """
    Uniplex Gate - Authorization enforcement point.
    
    The Gate evaluates authorization requests against its policy
    and the passport's validity and permissions.
    
    Example:
        gate = Gate(profile=TrustProfile.L1)
        decision = gate.authorize(request)
        if decision.allowed:
            # Proceed with action
    
    For L2+:
        from uniplex.registry import MemoryRegistry
        from uniplex.pop import PoPVerifier
        
        registry = MemoryRegistry()
        gate = Gate(
            profile=TrustProfile.L2,
            registry=registry,
            require_pop=True,
        )
    """
    
    def __init__(
        self,
        profile: TrustProfile = TrustProfile.L1,
        policy: Optional[GatePolicy] = None,
        registry: Optional["TrustRegistry"] = None,
        require_pop: bool = False,
        pop_max_age: int = 300,
        gate_id: Optional[str] = None,
    ):
        """
        Create a new Gate.
        
        Args:
            profile: Trust profile level (L1, L2, or L3)
            policy: Optional custom policy (default based on profile)
            registry: Trust registry for L2+ (required if profile >= L2)
            require_pop: Whether to require Proof of Possession
            pop_max_age: Maximum age of PoP in seconds
            gate_id: Identifier for this gate (for attestations)
        """
        self.profile = profile
        self.policy = policy or GatePolicy.for_profile(profile)
        self.registry = registry
        self.require_pop = require_pop or profile in (TrustProfile.L2, TrustProfile.L3)
        self.pop_max_age = pop_max_age
        self.gate_id = gate_id or f"gate_{uuid.uuid4().hex[:8]}"
        
        # Initialize PoP verifier if needed
        self._pop_verifier = None
        if self.require_pop:
            from .pop import PoPVerifier
            self._pop_verifier = PoPVerifier(max_age_seconds=pop_max_age)
    
    def authorize(self, request: GateRequest) -> GateDecision:
        """
        Process an authorization request.
        
        Performs L1 baseline checks:
        1. Verify passport signature
        2. Check passport not expired
        3. Apply issuer policy
        4. Check permission exists
        
        For L2+, additionally:
        5. Verify issuer via registry
        6. Verify Proof of Possession
        7. Check revocation status
        
        Returns a GateDecision with allow/deny.
        """
        try:
            # Parse passport from request
            passport = Passport.from_dict(request.passport)
        except Exception as e:
            return self._deny(
                request,
                DenyReason.INVALID_REQUEST,
                f"Invalid passport format: {e}",
            )
        
        # 1. Verify signature
        if not passport.verify_signature():
            return self._deny(
                request,
                DenyReason.INVALID_SIGNATURE,
                "Passport signature verification failed",
                passport=passport,
            )
        
        # 2. Check expiration
        if passport.is_expired():
            return self._deny(
                request,
                DenyReason.PASSPORT_EXPIRED,
                "Passport has expired",
                passport=passport,
            )
        
        # 3. Check issuer policy
        issuer_type = passport.provenance.issuer.type
        if issuer_type == "self" and not self.policy.allow_self_issued:
            return self._deny(
                request,
                DenyReason.ISSUER_NOT_ALLOWED,
                "Self-issued passports not allowed by this gate",
                passport=passport,
            )
        
        # For L2+, check if issuer is in allowlist or registry
        if self.policy.allowed_issuers is not None and issuer_type != "self":
            issuer_id = passport.provenance.issuer.id
            if issuer_id not in self.policy.allowed_issuers:
                # Check registry if available
                if self.registry:
                    from .registry import TrustTier
                    min_tier = TrustTier.VERIFIED if self.profile == TrustProfile.L2 else TrustTier.CERTIFIED
                    if not self.registry.is_issuer_trusted(issuer_id, min_tier):
                        return self._deny(
                            request,
                            DenyReason.ISSUER_NOT_VERIFIED,
                            f"Issuer {issuer_id} not verified in registry",
                            passport=passport,
                        )
                    # Check revocation
                    if self.registry.is_revoked(issuer_id):
                        return self._deny(
                            request,
                            DenyReason.ISSUER_REVOKED,
                            f"Issuer {issuer_id} has been revoked",
                            passport=passport,
                        )
                else:
                    return self._deny(
                        request,
                        DenyReason.ISSUER_NOT_ALLOWED,
                        f"Issuer {issuer_id} not in allowlist",
                        passport=passport,
                    )
        
        # 4. Check permission
        if not passport.has_permission(request.action):
            return self._deny(
                request,
                DenyReason.PERMISSION_DENIED,
                f"Passport does not grant permission for action: {request.action}",
                passport=passport,
            )
        
        # 5. For L2+, verify Proof of Possession
        if self.require_pop:
            pop_result = self._verify_pop(request, passport)
            if pop_result is not None:
                return pop_result
        
        # All checks passed - allow
        return self._allow(request, passport)
    
    def _verify_pop(self, request: GateRequest, passport: Passport) -> Optional[GateDecision]:
        """
        Verify Proof of Possession for L2+ requests.
        
        Returns a deny decision if PoP is invalid, None if valid.
        """
        if not request.pop:
            return self._deny(
                request,
                DenyReason.POP_REQUIRED,
                "Proof of Possession required for this gate",
                passport=passport,
            )
        
        try:
            from .pop import ProofOfPossession
            pop = ProofOfPossession.from_dict(request.pop)
        except Exception as e:
            return self._deny(
                request,
                DenyReason.POP_INVALID,
                f"Invalid PoP format: {e}",
                passport=passport,
            )
        
        # Use PoP verifier
        is_valid, error_code = self._pop_verifier.verify(
            pop=pop,
            expected_passport_id=passport.passport_id,
            expected_audience=request.target or self.gate_id,
            expected_public_key=passport.public_key,
        )
        
        if not is_valid:
            reason_map = {
                "POP_INVALID_SIGNATURE": DenyReason.POP_INVALID,
                "POP_PASSPORT_MISMATCH": DenyReason.POP_PASSPORT_MISMATCH,
                "POP_AUD_MISMATCH": DenyReason.POP_AUD_MISMATCH,
                "POP_EXPIRED": DenyReason.POP_EXPIRED,
                "POP_REPLAY_DETECTED": DenyReason.POP_REPLAY_DETECTED,
            }
            reason = reason_map.get(error_code, DenyReason.POP_INVALID)
            return self._deny(
                request,
                reason,
                f"PoP verification failed: {error_code}",
                passport=passport,
            )
        
        return None  # PoP is valid
    
    def _allow(self, request: GateRequest, passport: Passport) -> GateDecision:
        """Create an allow decision."""
        return GateDecision(
            request_id=request.request_id,
            decision="allow",
            passport_id=passport.passport_id,
            agent_id=passport.identity.agent_id,
            action=request.action,
        )
    
    def _deny(
        self,
        request: GateRequest,
        reason_code: DenyReason,
        reason: str,
        passport: Optional[Passport] = None,
    ) -> GateDecision:
        """Create a deny decision."""
        return GateDecision(
            request_id=request.request_id,
            decision="deny",
            reason=reason,
            reason_code=reason_code.value,
            passport_id=passport.passport_id if passport else None,
            agent_id=passport.identity.agent_id if passport else None,
            action=request.action,
        )
    
    def authorize_simple(
        self,
        passport: Union[Passport, dict],
        action: str,
        target: Optional[str] = None,
        pop: Optional[dict] = None,
    ) -> GateDecision:
        """
        Simplified authorization - create request and authorize in one call.
        
        Args:
            passport: The agent's passport
            action: The action being requested
            target: Optional target identifier
            pop: Optional Proof of Possession
        
        Returns:
            GateDecision
        """
        request = GateRequest.create(passport, action, target, pop=pop)
        return self.authorize(request)
