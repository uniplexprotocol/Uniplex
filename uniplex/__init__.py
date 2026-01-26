"""
Uniplex - The Open Protocol for AI Agent Trust

Uniplex provides a universal protocol for:
- Agent identity (Uni-Passport)
- Runtime permission enforcement (Uni-Gate)
- Portable verification evidence (Uni-Attestation)

Quick Start:
    # Create a self-issued agent
    from uniplex import Agent
    
    agent = Agent.create("my-agent", permissions="*")
    agent.save("passport.json")
    
    # Or load from environment
    agent = Agent.from_env()  # Reads UNIPLEX_PASSPORT
    
    # Check authorization
    decision = agent.authorize("search")
    if decision.allowed:
        print("Action authorized!")

For more information, visit https://uniplex.dev
"""

__version__ = "2026.01.25"

# Core classes
from .passport import (
    Passport,
    PassportIdentity,
    PassportIssuer,
    PassportPermission,
    PassportProvenance,
)

from .gate import (
    Gate,
    GateRequest,
    GateDecision,
    GatePolicy,
    TrustProfile,
    DenyReason,
)

from .attestation import Attestation

from .agent import Agent, AuthorizationError

# Extensions
from .pop import (
    ProofOfPossession,
    PoPPayload,
    PoPVerifier,
)

from .registry import (
    TrustRegistry,
    MemoryRegistry,
    LocalRegistry,
    TrustResolver,
    TrustTier,
    IssuerInfo,
    get_default_resolver,
    set_default_resolver,
)

from .session import (
    SessionToken,
    SessionManager,
    get_session_manager,
    set_session_manager,
)

from .mcp import (
    MCPAuthorizer,
    MCPAuthConfig,
    MCPAuthResult,
    MCPClient,
    create_mcp_gate_middleware,
)

# Public API
__all__ = [
    # Version
    "__version__",
    
    # High-level API
    "Agent",
    "AuthorizationError",
    
    # Passport
    "Passport",
    "PassportIdentity",
    "PassportIssuer",
    "PassportPermission",
    "PassportProvenance",
    
    # Gate
    "Gate",
    "GateRequest",
    "GateDecision",
    "GatePolicy",
    "TrustProfile",
    "DenyReason",
    
    # Attestation
    "Attestation",
    
    # Proof of Possession
    "ProofOfPossession",
    "PoPPayload",
    "PoPVerifier",
    
    # Registry
    "TrustRegistry",
    "MemoryRegistry",
    "LocalRegistry",
    "TrustResolver",
    "TrustTier",
    "IssuerInfo",
    "get_default_resolver",
    "set_default_resolver",
    
    # Sessions
    "SessionToken",
    "SessionManager",
    "get_session_manager",
    "set_session_manager",
    
    # MCP
    "MCPAuthorizer",
    "MCPAuthConfig",
    "MCPAuthResult",
    "MCPClient",
    "create_mcp_gate_middleware",
]
