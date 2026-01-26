"""
Uniplex Trust Registry - Issuer verification and trust resolution.

A Trust Registry provides:
- Issuer lookup (public keys, metadata)
- Revocation checking
- Trust tier verification

Per spec: Trust resolution MAY be local (file-based), self-hosted, or public.
No single registry is required or privileged.
"""

import json
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set

from pydantic import BaseModel, Field


class TrustTier(str, Enum):
    """Trust tier levels for issuers."""
    SELF = "self"           # Self-issued, no verification
    ENTERPRISE = "enterprise"  # Organization-verified
    VERIFIED = "verified"    # Registry-verified
    CERTIFIED = "certified"  # Audit + contractual agreement


class IssuerInfo(BaseModel):
    """Information about a registered issuer."""
    
    issuer_id: str
    name: Optional[str] = None
    trust_tier: TrustTier = TrustTier.VERIFIED
    public_keys: List[str] = Field(default_factory=list)  # Base64 encoded
    created_at: Optional[str] = None
    verified_at: Optional[str] = None
    metadata: Dict = Field(default_factory=dict)
    
    # Revocation
    revoked: bool = False
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None


class TrustRegistry(ABC):
    """
    Abstract base class for trust registries.
    
    Implementations can be:
    - LocalRegistry: File-based for development
    - MemoryRegistry: In-memory for testing
    - RemoteRegistry: HTTP-based for production
    """
    
    @abstractmethod
    def get_issuer(self, issuer_id: str) -> Optional[IssuerInfo]:
        """Look up an issuer by ID."""
        pass
    
    @abstractmethod
    def is_issuer_trusted(self, issuer_id: str, min_tier: TrustTier = TrustTier.VERIFIED) -> bool:
        """Check if an issuer meets the minimum trust tier."""
        pass
    
    @abstractmethod
    def is_revoked(self, issuer_id: str) -> bool:
        """Check if an issuer has been revoked."""
        pass
    
    @abstractmethod
    def get_public_keys(self, issuer_id: str) -> List[str]:
        """Get public keys for an issuer."""
        pass


class MemoryRegistry(TrustRegistry):
    """
    In-memory trust registry for testing and development.
    """
    
    def __init__(self):
        self._issuers: Dict[str, IssuerInfo] = {}
    
    def register_issuer(self, issuer: IssuerInfo) -> None:
        """Register an issuer."""
        self._issuers[issuer.issuer_id] = issuer
    
    def remove_issuer(self, issuer_id: str) -> None:
        """Remove an issuer."""
        self._issuers.pop(issuer_id, None)
    
    def revoke_issuer(self, issuer_id: str, reason: str = "Revoked") -> bool:
        """Revoke an issuer."""
        if issuer_id in self._issuers:
            issuer = self._issuers[issuer_id]
            issuer.revoked = True
            issuer.revoked_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            issuer.revocation_reason = reason
            return True
        return False
    
    def get_issuer(self, issuer_id: str) -> Optional[IssuerInfo]:
        return self._issuers.get(issuer_id)
    
    def is_issuer_trusted(self, issuer_id: str, min_tier: TrustTier = TrustTier.VERIFIED) -> bool:
        issuer = self.get_issuer(issuer_id)
        if not issuer:
            return False
        if issuer.revoked:
            return False
        
        # Trust tier ordering
        tier_order = {
            TrustTier.SELF: 0,
            TrustTier.ENTERPRISE: 1,
            TrustTier.VERIFIED: 2,
            TrustTier.CERTIFIED: 3,
        }
        
        return tier_order.get(issuer.trust_tier, 0) >= tier_order.get(min_tier, 0)
    
    def is_revoked(self, issuer_id: str) -> bool:
        issuer = self.get_issuer(issuer_id)
        return issuer.revoked if issuer else False
    
    def get_public_keys(self, issuer_id: str) -> List[str]:
        issuer = self.get_issuer(issuer_id)
        return issuer.public_keys if issuer else []
    
    def list_issuers(self) -> List[IssuerInfo]:
        """List all registered issuers."""
        return list(self._issuers.values())


class LocalRegistry(TrustRegistry):
    """
    File-based trust registry for local development.
    
    Stores issuers in a JSON file.
    """
    
    def __init__(self, path: str):
        """
        Create a local registry.
        
        Args:
            path: Path to the registry JSON file
        """
        self.path = path
        self._issuers: Dict[str, IssuerInfo] = {}
        self._load()
    
    def _load(self) -> None:
        """Load issuers from file."""
        if os.path.exists(self.path):
            with open(self.path, "r") as f:
                data = json.load(f)
                for issuer_data in data.get("issuers", []):
                    issuer = IssuerInfo.model_validate(issuer_data)
                    self._issuers[issuer.issuer_id] = issuer
    
    def _save(self) -> None:
        """Save issuers to file."""
        data = {
            "version": "1.0",
            "issuers": [issuer.model_dump() for issuer in self._issuers.values()]
        }
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2)
    
    def register_issuer(self, issuer: IssuerInfo) -> None:
        """Register an issuer and save."""
        self._issuers[issuer.issuer_id] = issuer
        self._save()
    
    def get_issuer(self, issuer_id: str) -> Optional[IssuerInfo]:
        return self._issuers.get(issuer_id)
    
    def is_issuer_trusted(self, issuer_id: str, min_tier: TrustTier = TrustTier.VERIFIED) -> bool:
        issuer = self.get_issuer(issuer_id)
        if not issuer:
            return False
        if issuer.revoked:
            return False
        
        tier_order = {
            TrustTier.SELF: 0,
            TrustTier.ENTERPRISE: 1,
            TrustTier.VERIFIED: 2,
            TrustTier.CERTIFIED: 3,
        }
        
        return tier_order.get(issuer.trust_tier, 0) >= tier_order.get(min_tier, 0)
    
    def is_revoked(self, issuer_id: str) -> bool:
        issuer = self.get_issuer(issuer_id)
        return issuer.revoked if issuer else False
    
    def get_public_keys(self, issuer_id: str) -> List[str]:
        issuer = self.get_issuer(issuer_id)
        return issuer.public_keys if issuer else []


class TrustResolver:
    """
    High-level trust resolution service.
    
    Combines multiple registries and provides unified trust queries.
    """
    
    def __init__(self, registries: Optional[List[TrustRegistry]] = None):
        """
        Create a trust resolver.
        
        Args:
            registries: List of registries to query (in priority order)
        """
        self.registries = registries or []
    
    def add_registry(self, registry: TrustRegistry) -> None:
        """Add a registry to the resolver."""
        self.registries.append(registry)
    
    def resolve_issuer(self, issuer_id: str) -> Optional[IssuerInfo]:
        """
        Resolve an issuer across all registries.
        
        Returns the first match found.
        """
        for registry in self.registries:
            issuer = registry.get_issuer(issuer_id)
            if issuer:
                return issuer
        return None
    
    def is_trusted(
        self,
        issuer_id: str,
        min_tier: TrustTier = TrustTier.VERIFIED,
        allow_self_issued: bool = False,
    ) -> bool:
        """
        Check if an issuer is trusted.
        
        Args:
            issuer_id: The issuer to check
            min_tier: Minimum required trust tier
            allow_self_issued: Whether to allow self-issued (bypasses registry check)
        
        Returns:
            True if trusted
        """
        # Self-issued bypass
        if allow_self_issued and min_tier == TrustTier.SELF:
            return True
        
        # Check all registries
        for registry in self.registries:
            if registry.is_issuer_trusted(issuer_id, min_tier):
                return True
        
        return False
    
    def check_revocation(self, issuer_id: str) -> bool:
        """
        Check if an issuer is revoked in any registry.
        
        Returns True if revoked in ANY registry.
        """
        for registry in self.registries:
            if registry.is_revoked(issuer_id):
                return True
        return False
    
    def get_public_keys(self, issuer_id: str) -> List[str]:
        """
        Get all public keys for an issuer across registries.
        """
        keys = []
        for registry in self.registries:
            keys.extend(registry.get_public_keys(issuer_id))
        return list(set(keys))  # Deduplicate


# Global default resolver (can be configured at startup)
_default_resolver: Optional[TrustResolver] = None


def get_default_resolver() -> TrustResolver:
    """Get the default trust resolver."""
    global _default_resolver
    if _default_resolver is None:
        _default_resolver = TrustResolver()
    return _default_resolver


def set_default_resolver(resolver: TrustResolver) -> None:
    """Set the default trust resolver."""
    global _default_resolver
    _default_resolver = resolver
