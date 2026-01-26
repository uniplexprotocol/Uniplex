"""
Uniplex MCP Integration - Trust layer for Model Context Protocol.

"MCP is the plumbing. Uniplex is the trust."

This module provides:
- MCP server wrapping (add authorization to any MCP server)
- MCP client helpers (authorized tool calls)
- Field mapping per Uni-MCP profile spec

Per spec section 10:
| MCP Concept      | Uniplex Field                              |
|------------------|--------------------------------------------|
| Tool name        | action                                     |
| Tool arguments   | parameters                                 |
| MCP server ID    | target                                     |
| MCP session      | extensions["org.modelcontextprotocol.session"] |
"""

import functools
import json
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union

from pydantic import BaseModel, Field

from .passport import Passport
from .gate import Gate, GateRequest, GateDecision, TrustProfile, DenyReason
from .pop import ProofOfPossession, PoPVerifier
from .attestation import Attestation


# Type for decorated functions
F = TypeVar("F", bound=Callable[..., Any])


class MCPAuthConfig(BaseModel):
    """Configuration for MCP authorization."""
    
    server_id: str  # Unique identifier for this MCP server
    profile: TrustProfile = TrustProfile.L1
    require_pop: bool = False  # Require Proof of Possession
    allowed_tools: Optional[List[str]] = None  # None = all tools allowed
    log_decisions: bool = True


class MCPAuthResult(BaseModel):
    """Result of MCP authorization check."""
    
    allowed: bool
    decision: Optional[GateDecision] = None
    attestation: Optional[Attestation] = None
    error: Optional[str] = None
    error_code: Optional[str] = None


class MCPAuthorizer:
    """
    Authorizer for MCP tool calls.
    
    Wraps an MCP server to add Uniplex authorization.
    
    Example:
        authorizer = MCPAuthorizer(
            server_id="mcp://mytools.example.com",
            profile=TrustProfile.L2,
        )
        
        # Check authorization before tool execution
        result = authorizer.authorize(passport, tool_name, args)
        if result.allowed:
            # Execute tool
    """
    
    def __init__(
        self,
        server_id: str,
        profile: TrustProfile = TrustProfile.L1,
        gate: Optional[Gate] = None,
        require_pop: bool = False,
        pop_max_age: int = 300,
    ):
        """
        Create an MCP authorizer.
        
        Args:
            server_id: Unique ID for this MCP server
            profile: Trust profile level
            gate: Optional custom Gate (created from profile if not provided)
            require_pop: Whether to require Proof of Possession
            pop_max_age: Maximum age of PoP in seconds
        """
        self.server_id = server_id
        self.profile = profile
        self.gate = gate or Gate(profile=profile)
        self.require_pop = require_pop
        self.pop_verifier = PoPVerifier(max_age_seconds=pop_max_age) if require_pop else None
    
    def authorize(
        self,
        passport: Union[Passport, dict],
        tool_name: str,
        parameters: Optional[dict] = None,
        pop: Optional[Union[ProofOfPossession, dict]] = None,
        session_nonce: Optional[str] = None,
    ) -> MCPAuthResult:
        """
        Authorize an MCP tool call.
        
        Args:
            passport: The agent's passport
            tool_name: MCP tool name (maps to action)
            parameters: Tool arguments
            pop: Proof of Possession (required for L2+)
            session_nonce: Session nonce for PoP binding
        
        Returns:
            MCPAuthResult with authorization decision
        """
        # Parse passport if dict
        if isinstance(passport, dict):
            try:
                passport = Passport.from_dict(passport)
            except Exception as e:
                return MCPAuthResult(
                    allowed=False,
                    error=f"Invalid passport: {e}",
                    error_code="INVALID_PASSPORT",
                )
        
        # Map MCP concepts to Uniplex
        action = f"mcp:{tool_name}"  # Prefix with mcp: namespace
        target = self.server_id
        
        # Create gate request
        request = GateRequest.create(
            passport=passport,
            action=action,
            target=target,
            parameters=parameters,
        )
        
        # Add MCP session extension if we have a session nonce
        if session_nonce:
            request.extensions = {
                "org.modelcontextprotocol.session": session_nonce
            }
        
        # Check PoP if required
        if self.require_pop:
            if not pop:
                return MCPAuthResult(
                    allowed=False,
                    error="Proof of Possession required",
                    error_code="POP_REQUIRED",
                )
            
            # Parse PoP if dict
            if isinstance(pop, dict):
                try:
                    pop = ProofOfPossession.from_dict(pop)
                except Exception as e:
                    return MCPAuthResult(
                        allowed=False,
                        error=f"Invalid PoP: {e}",
                        error_code="POP_INVALID",
                    )
            
            # Verify PoP
            is_valid, error_code = self.pop_verifier.verify(
                pop=pop,
                expected_passport_id=passport.passport_id,
                expected_audience=target,
                expected_public_key=passport.public_key,
                expected_session_nonce=session_nonce,
            )
            
            if not is_valid:
                return MCPAuthResult(
                    allowed=False,
                    error=f"PoP verification failed: {error_code}",
                    error_code=error_code,
                )
        
        # Run gate authorization
        decision = self.gate.authorize(request)
        
        # Generate attestation
        attestation = None
        if decision.allowed:
            attestation = Attestation.from_decision(
                request=request,
                decision=decision,
                gate_id=self.server_id,
            )
        
        return MCPAuthResult(
            allowed=decision.allowed,
            decision=decision,
            attestation=attestation,
            error=decision.reason if decision.denied else None,
            error_code=decision.reason_code if decision.denied else None,
        )
    
    def wrap_tool(self, tool_name: str) -> Callable[[F], F]:
        """
        Decorator to wrap an MCP tool with authorization.
        
        The decorated function must accept 'passport' as first argument.
        
        Example:
            @authorizer.wrap_tool("search")
            def search(passport, query: str) -> dict:
                return {"results": [...]}
        """
        def decorator(func: F) -> F:
            @functools.wraps(func)
            def wrapper(passport: Union[Passport, dict], *args, **kwargs):
                # Extract parameters for logging
                parameters = kwargs.copy()
                
                # Authorize
                result = self.authorize(passport, tool_name, parameters)
                
                if not result.allowed:
                    raise PermissionError(f"Unauthorized: {result.error}")
                
                # Execute tool
                return func(passport, *args, **kwargs)
            
            return wrapper  # type: ignore
        return decorator


def create_mcp_gate_middleware(
    server_id: str,
    profile: TrustProfile = TrustProfile.L1,
) -> Callable:
    """
    Create middleware for MCP server frameworks.
    
    Returns a function that can be used as middleware in various
    MCP server implementations.
    
    Example with a hypothetical MCP framework:
        middleware = create_mcp_gate_middleware(
            server_id="mcp://myserver",
            profile=TrustProfile.L1,
        )
        
        server.use(middleware)
    """
    authorizer = MCPAuthorizer(server_id=server_id, profile=profile)
    
    def middleware(request: dict, next_handler: Callable) -> Any:
        """
        MCP middleware function.
        
        Expects request to have:
        - passport: The agent's passport
        - tool: Tool name
        - arguments: Tool arguments
        """
        passport = request.get("passport")
        tool = request.get("tool") or request.get("method")
        arguments = request.get("arguments") or request.get("params", {})
        
        if not passport:
            return {
                "error": {
                    "code": "PASSPORT_MISSING",
                    "message": "No passport provided",
                }
            }
        
        result = authorizer.authorize(passport, tool, arguments)
        
        if not result.allowed:
            return {
                "error": {
                    "code": result.error_code,
                    "message": result.error,
                }
            }
        
        # Add attestation to response
        response = next_handler(request)
        if isinstance(response, dict) and result.attestation:
            response["attestation"] = result.attestation.to_dict()
        
        return response
    
    return middleware


class MCPClient:
    """
    MCP client with built-in authorization.
    
    Wraps tool calls with passport and optional PoP.
    
    Example:
        client = MCPClient(passport, server_url="mcp://tools.example.com")
        result = client.call("search", {"query": "weather"})
    """
    
    def __init__(
        self,
        passport: Passport,
        server_id: str,
        private_key: Optional[bytes] = None,
        use_pop: bool = False,
    ):
        """
        Create an MCP client.
        
        Args:
            passport: The agent's passport
            server_id: Target MCP server ID
            private_key: Private key for PoP signing (required if use_pop=True)
            use_pop: Whether to include PoP with requests
        """
        self.passport = passport
        self.server_id = server_id
        self.private_key = private_key
        self.use_pop = use_pop
        
        if use_pop and not private_key:
            raise ValueError("Private key required for PoP")
    
    def create_request(
        self,
        tool_name: str,
        arguments: Optional[dict] = None,
        session_nonce: Optional[str] = None,
    ) -> dict:
        """
        Create an authorized MCP request.
        
        Returns a dict that can be sent to an MCP server.
        """
        request = {
            "jsonrpc": "2.0",
            "method": tool_name,
            "params": arguments or {},
            "passport": self.passport.to_dict(),
        }
        
        # Add PoP if enabled
        if self.use_pop:
            pop = ProofOfPossession.create(
                passport_id=self.passport.passport_id,
                audience=self.server_id,
                private_key_bytes=self.private_key,
                session_nonce=session_nonce,
            )
            request["pop"] = pop.to_dict()
        
        return request
    
    def call(
        self,
        tool_name: str,
        arguments: Optional[dict] = None,
        handler: Optional[Callable[[dict], Any]] = None,
    ) -> Any:
        """
        Make an authorized tool call.
        
        Args:
            tool_name: The tool to call
            arguments: Tool arguments
            handler: Function to actually send the request (for testing/flexibility)
        
        Returns:
            Result from handler, or the request dict if no handler
        """
        request = self.create_request(tool_name, arguments)
        
        if handler:
            return handler(request)
        
        return request


def generate_wrapper_code(
    input_file: str,
    output_file: str,
    server_id: str,
    profile: TrustProfile = TrustProfile.L2,
) -> str:
    """
    Generate wrapper code for an existing MCP server.
    
    This is used by the CLI 'uniplex wrap' command.
    
    Args:
        input_file: Path to the original MCP server
        output_file: Path for the wrapped server
        server_id: Server ID for the wrapper
        profile: Trust profile to use
    
    Returns:
        The generated wrapper code
    """
    wrapper_code = f'''"""
Uniplex-wrapped MCP server.

Generated from: {input_file}
Server ID: {server_id}
Trust Profile: {profile.value}
"""

import sys
sys.path.insert(0, ".")

from uniplex import Gate, TrustProfile
from uniplex.mcp import MCPAuthorizer

# Import the original server
# Note: You may need to adjust this import based on your server structure
from {input_file.replace(".py", "").replace("/", ".")} import *

# Create authorizer
authorizer = MCPAuthorizer(
    server_id="{server_id}",
    profile=TrustProfile.{profile.value},
    require_pop={profile != TrustProfile.L1},
)

# Wrap the server's tool handlers
# This is a template - actual wrapping depends on your MCP framework

def authorize_request(passport, tool_name, arguments):
    """Check authorization before tool execution."""
    result = authorizer.authorize(passport, tool_name, arguments)
    if not result.allowed:
        raise PermissionError(f"Unauthorized: {{result.error}}")
    return result.attestation

# Add authorization middleware to your server
# Example for different frameworks:

# If using FastAPI-based MCP:
# @app.middleware("http")
# async def auth_middleware(request, call_next):
#     passport = request.headers.get("X-Uniplex-Passport")
#     if passport:
#         # Validate passport
#         pass
#     return await call_next(request)

# If using stdio MCP:
# Original handlers are wrapped automatically via decorator

print(f"Uniplex Gate active: {{authorizer.server_id}} (Profile: {{authorizer.profile.value}})")
'''
    
    return wrapper_code
