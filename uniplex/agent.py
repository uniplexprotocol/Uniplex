"""
Uniplex Agent - High-level interface for authorized actions.

The Agent class wraps a Passport and provides convenient methods
for making authorized calls to tools and services.

Example:
    agent = Agent.from_env()
    result = agent.call("mcp://tools.example.com", "search", {"query": "weather"})
"""

import os
from typing import Any, Callable, Optional

from .passport import Passport
from .gate import Gate, GateRequest, GateDecision, TrustProfile


class AuthorizationError(Exception):
    """Raised when an authorization check fails."""
    
    def __init__(self, decision: GateDecision):
        self.decision = decision
        super().__init__(f"Authorization denied: {decision.reason}")


class Agent:
    """
    Uniplex Agent - High-level interface for authorized actions.
    
    An Agent wraps a Passport and provides methods for:
    - Making authorized calls to tools and services
    - Checking permissions before acting
    - Generating authorization requests
    
    Example:
        # Load from environment
        agent = Agent.from_env()
        
        # Check if action is allowed
        if agent.can("search", target="mcp://tools.example.com"):
            result = agent.call("mcp://tools.example.com", "search", {"query": "test"})
    """
    
    def __init__(self, passport: Passport):
        """
        Create an Agent with the given passport.
        
        Args:
            passport: The agent's Uniplex passport
        """
        self.passport = passport
    
    @classmethod
    def from_env(cls, env_var: str = "UNIPLEX_PASSPORT") -> "Agent":
        """
        Create an Agent from environment variable.
        
        The env var can contain either:
        - A JSON string of the passport
        - A file path to the passport JSON
        
        Args:
            env_var: Name of the environment variable (default: UNIPLEX_PASSPORT)
        
        Returns:
            A new Agent instance
        """
        passport = Passport.from_env(env_var)
        return cls(passport)
    
    @classmethod
    def from_file(cls, path: str) -> "Agent":
        """
        Create an Agent from a passport file.
        
        Args:
            path: Path to the passport JSON file
        
        Returns:
            A new Agent instance
        """
        passport = Passport.load(path)
        return cls(passport)
    
    @classmethod
    def create(
        cls,
        agent_id: str,
        permissions: str = "*",
        **kwargs,
    ) -> "Agent":
        """
        Create a new Agent with a self-issued passport.
        
        Args:
            agent_id: Unique identifier for the agent
            permissions: Permission pattern (default: "*" for all)
            **kwargs: Additional arguments passed to Passport.create_self_issued
        
        Returns:
            A new Agent with a fresh passport
        """
        passport = Passport.create_self_issued(agent_id, permissions, **kwargs)
        return cls(passport)
    
    @property
    def agent_id(self) -> str:
        """Get the agent's ID."""
        return self.passport.identity.agent_id
    
    @property
    def passport_id(self) -> str:
        """Get the passport ID."""
        return self.passport.passport_id
    
    def can(self, action: str, target: Optional[str] = None) -> bool:
        """
        Check if the agent has permission for an action.
        
        This performs a local permission check. For full authorization
        (including signature verification), use authorize().
        
        Args:
            action: The action to check
            target: Optional target identifier
        
        Returns:
            True if permitted, False otherwise
        """
        return self.passport.has_permission(action)
    
    def authorize(
        self,
        action: str,
        target: Optional[str] = None,
        gate: Optional[Gate] = None,
    ) -> GateDecision:
        """
        Perform a full authorization check.
        
        Creates a Gate request and evaluates it, including:
        - Signature verification
        - Expiration check
        - Permission check
        
        Args:
            action: The action to authorize
            target: Optional target identifier
            gate: Optional Gate instance (creates L1 gate if not provided)
        
        Returns:
            GateDecision with the authorization result
        """
        if gate is None:
            gate = Gate(profile=TrustProfile.L1)
        
        request = GateRequest.create(
            passport=self.passport,
            action=action,
            target=target,
        )
        
        return gate.authorize(request)
    
    def require(
        self,
        action: str,
        target: Optional[str] = None,
        gate: Optional[Gate] = None,
    ) -> GateDecision:
        """
        Require authorization for an action.
        
        Like authorize(), but raises AuthorizationError if denied.
        
        Args:
            action: The action to authorize
            target: Optional target identifier
            gate: Optional Gate instance
        
        Returns:
            GateDecision if allowed
        
        Raises:
            AuthorizationError: If authorization is denied
        """
        decision = self.authorize(action, target, gate)
        if decision.denied:
            raise AuthorizationError(decision)
        return decision
    
    def call(
        self,
        target: str,
        action: str,
        parameters: Optional[dict] = None,
        handler: Optional[Callable[[str, str, dict], Any]] = None,
    ) -> Any:
        """
        Make an authorized call to a target.
        
        This is a placeholder for the full MCP integration.
        Currently requires a handler function to actually execute the call.
        
        Args:
            target: The target identifier (e.g., "mcp://tools.example.com")
            action: The action to perform
            parameters: Optional parameters for the action
            handler: Function to handle the actual call (receives target, action, params)
        
        Returns:
            Result from the handler, or the authorization decision if no handler
        
        Raises:
            AuthorizationError: If authorization is denied
        
        Example:
            def my_handler(target, action, params):
                # Actually call the MCP server
                return {"result": "success"}
            
            result = agent.call("mcp://server", "search", {"q": "test"}, handler=my_handler)
        """
        # Check authorization
        decision = self.require(action, target)
        
        # If we have a handler, execute it
        if handler:
            return handler(target, action, parameters or {})
        
        # Otherwise just return the decision
        return decision
    
    def create_request(
        self,
        action: str,
        target: Optional[str] = None,
        parameters: Optional[dict] = None,
    ) -> GateRequest:
        """
        Create a GateRequest for this agent.
        
        Useful when you need to send the request to a remote Gate.
        
        Args:
            action: The action being requested
            target: Optional target identifier
            parameters: Optional action parameters
        
        Returns:
            A GateRequest ready to be sent to a Gate
        """
        return GateRequest.create(
            passport=self.passport,
            action=action,
            target=target,
            parameters=parameters,
        )
    
    def save(self, path: str) -> None:
        """Save the agent's passport to a file."""
        self.passport.save(path)
    
    def to_dict(self) -> dict:
        """Export the agent's passport as a dictionary."""
        return self.passport.to_dict()
    
    def to_json(self) -> str:
        """Export the agent's passport as JSON."""
        return self.passport.to_json()
