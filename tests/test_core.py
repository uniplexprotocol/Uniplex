"""
Tests for Uniplex core SDK.

Run with: pytest tests/
"""

import json
import os
import tempfile
from datetime import timedelta

import pytest

from uniplex import (
    Agent,
    AuthorizationError,
    Passport,
    Gate,
    GateRequest,
    GateDecision,
    TrustProfile,
    DenyReason,
    Attestation,
)


class TestPassport:
    """Tests for Passport class."""
    
    def test_create_self_issued(self):
        """Test creating a self-issued passport."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
        )
        
        assert passport.identity.agent_id == "test-agent"
        assert passport.passport_id.startswith("uni_")
        assert len(passport.permissions) == 1
        assert passport.permissions[0].action == "*"
        assert passport.provenance.issuer.type == "self"
        assert passport.public_key is not None
        assert passport.signature is not None
    
    def test_signature_verification(self):
        """Test that passport signature can be verified."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
        )
        
        assert passport.verify_signature() is True
    
    def test_tampered_passport_fails_verification(self):
        """Test that tampering with passport breaks signature."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
        )
        
        # Tamper with the passport
        passport.identity.agent_id = "evil-agent"
        
        assert passport.verify_signature() is False
    
    def test_has_permission_wildcard(self):
        """Test wildcard permission matching."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
        )
        
        assert passport.has_permission("anything") is True
        assert passport.has_permission("tools:search") is True
        assert passport.has_permission("mcp:execute") is True
    
    def test_has_permission_prefix_wildcard(self):
        """Test prefix wildcard permission matching."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="tools:*",
        )
        
        assert passport.has_permission("tools:search") is True
        assert passport.has_permission("tools:read") is True
        assert passport.has_permission("mcp:execute") is False
        assert passport.has_permission("other") is False
    
    def test_has_permission_exact(self):
        """Test exact permission matching."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions=["tools:search", "tools:read"],
        )
        
        assert passport.has_permission("tools:search") is True
        assert passport.has_permission("tools:read") is True
        assert passport.has_permission("tools:write") is False
    
    def test_is_expired(self):
        """Test expiration checking."""
        # Create a passport that expires immediately
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
            expires_in=timedelta(seconds=-1),  # Already expired
        )
        
        assert passport.is_expired() is True
    
    def test_not_expired(self):
        """Test non-expired passport."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
            expires_in=timedelta(days=7),
        )
        
        assert passport.is_expired() is False
    
    def test_save_and_load(self):
        """Test saving and loading passport from file."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
        )
        
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            passport.save(f.name)
            loaded = Passport.load(f.name)
        
        assert loaded.passport_id == passport.passport_id
        assert loaded.identity.agent_id == passport.identity.agent_id
        assert loaded.verify_signature() is True
        
        os.unlink(f.name)
    
    def test_to_json_and_from_json(self):
        """Test JSON serialization."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
        )
        
        json_str = passport.to_json()
        loaded = Passport.from_json(json_str)
        
        assert loaded.passport_id == passport.passport_id
        assert loaded.verify_signature() is True
    
    def test_from_env(self, monkeypatch):
        """Test loading passport from environment variable."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
        )
        
        monkeypatch.setenv("UNIPLEX_PASSPORT", passport.to_json())
        
        loaded = Passport.from_env()
        assert loaded.passport_id == passport.passport_id


class TestGate:
    """Tests for Gate class."""
    
    def test_authorize_valid_passport(self):
        """Test authorizing a valid passport."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
        )
        
        gate = Gate(profile=TrustProfile.L1)
        request = GateRequest.create(passport, action="search")
        decision = gate.authorize(request)
        
        assert decision.allowed is True
        assert decision.passport_id == passport.passport_id
        assert decision.agent_id == "test-agent"
    
    def test_deny_invalid_signature(self):
        """Test denying passport with invalid signature."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
        )
        
        # Tamper with passport
        passport.identity.agent_id = "evil-agent"
        
        gate = Gate(profile=TrustProfile.L1)
        decision = gate.authorize_simple(passport, "search")
        
        assert decision.denied is True
        assert decision.reason_code == DenyReason.INVALID_SIGNATURE.value
    
    def test_deny_expired_passport(self):
        """Test denying expired passport."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
            expires_in=timedelta(seconds=-1),
        )
        
        gate = Gate(profile=TrustProfile.L1)
        decision = gate.authorize_simple(passport, "search")
        
        assert decision.denied is True
        assert decision.reason_code == DenyReason.PASSPORT_EXPIRED.value
    
    def test_deny_missing_permission(self):
        """Test denying action without permission."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="tools:read",
        )
        
        gate = Gate(profile=TrustProfile.L1)
        decision = gate.authorize_simple(passport, "tools:write")
        
        assert decision.denied is True
        assert decision.reason_code == DenyReason.PERMISSION_DENIED.value
    
    def test_authorize_simple(self):
        """Test simplified authorization API."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
        )
        
        gate = Gate(profile=TrustProfile.L1)
        decision = gate.authorize_simple(passport, "search", target="mcp://server")
        
        assert decision.allowed is True


class TestAttestation:
    """Tests for Attestation class."""
    
    def test_create_from_decision(self):
        """Test creating attestation from gate decision."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
        )
        
        gate = Gate(profile=TrustProfile.L1)
        request = GateRequest.create(passport, action="search", target="mcp://server")
        decision = gate.authorize(request)
        
        attestation = Attestation.from_decision(request, decision, gate_id="test-gate")
        
        assert attestation.attestation_id.startswith("att_")
        assert attestation.request_id == request.request_id
        assert attestation.decision == "allow"
        assert attestation.action == "search"
        assert attestation.target == "mcp://server"
        assert attestation.signature is not None
    
    def test_attestation_signature_verification(self):
        """Test verifying attestation signature."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
        )
        
        gate = Gate(profile=TrustProfile.L1)
        request = GateRequest.create(passport, action="search")
        decision = gate.authorize(request)
        
        attestation = Attestation.from_decision(request, decision)
        
        assert attestation.verify_signature() is True
    
    def test_attestation_json_roundtrip(self):
        """Test JSON serialization of attestation."""
        passport = Passport.create_self_issued(
            agent_id="test-agent",
            permissions="*",
        )
        
        gate = Gate(profile=TrustProfile.L1)
        request = GateRequest.create(passport, action="search")
        decision = gate.authorize(request)
        
        attestation = Attestation.from_decision(request, decision)
        
        json_str = attestation.to_json()
        loaded = Attestation.from_json(json_str)
        
        assert loaded.attestation_id == attestation.attestation_id
        assert loaded.verify_signature() is True


class TestAgent:
    """Tests for Agent class."""
    
    def test_create_agent(self):
        """Test creating a new agent."""
        agent = Agent.create("my-agent", permissions="*")
        
        assert agent.agent_id == "my-agent"
        assert agent.passport.verify_signature() is True
    
    def test_agent_can(self):
        """Test checking permissions."""
        agent = Agent.create("my-agent", permissions="tools:*")
        
        assert agent.can("tools:search") is True
        assert agent.can("mcp:execute") is False
    
    def test_agent_authorize(self):
        """Test full authorization check."""
        agent = Agent.create("my-agent", permissions="*")
        
        decision = agent.authorize("search")
        assert decision.allowed is True
    
    def test_agent_require_success(self):
        """Test require() with permitted action."""
        agent = Agent.create("my-agent", permissions="*")
        
        decision = agent.require("search")
        assert decision.allowed is True
    
    def test_agent_require_failure(self):
        """Test require() with denied action."""
        agent = Agent.create("my-agent", permissions="tools:read")
        
        with pytest.raises(AuthorizationError) as exc_info:
            agent.require("tools:write")
        
        assert exc_info.value.decision.denied is True
    
    def test_agent_from_env(self, monkeypatch):
        """Test loading agent from environment."""
        passport = Passport.create_self_issued(
            agent_id="env-agent",
            permissions="*",
        )
        
        monkeypatch.setenv("UNIPLEX_PASSPORT", passport.to_json())
        
        agent = Agent.from_env()
        assert agent.agent_id == "env-agent"
    
    def test_agent_create_request(self):
        """Test creating a gate request."""
        agent = Agent.create("my-agent", permissions="*")
        
        request = agent.create_request("search", target="mcp://server", parameters={"q": "test"})
        
        assert request.action == "search"
        assert request.target == "mcp://server"
        assert request.parameters == {"q": "test"}


class TestEndToEnd:
    """End-to-end integration tests."""
    
    def test_full_authorization_flow(self):
        """Test complete authorization flow from agent to attestation."""
        # 1. Create agent with passport
        agent = Agent.create("my-agent", permissions="mcp:*")
        
        # 2. Create gate
        gate = Gate(profile=TrustProfile.L1)
        
        # 3. Create request
        request = agent.create_request("mcp:search", target="mcp://tools.example.com")
        
        # 4. Authorize
        decision = gate.authorize(request)
        assert decision.allowed is True
        
        # 5. Create attestation
        attestation = Attestation.from_decision(request, decision, gate_id="my-gate")
        
        # 6. Verify attestation
        assert attestation.verify_signature() is True
        assert attestation.allowed is True
    
    def test_quickstart_example(self, monkeypatch):
        """Test the quickstart example from docs actually works."""
        # Setup: Create passport and set in environment
        passport = Passport.create_self_issued(
            agent_id="my-agent",
            permissions="*",
        )
        monkeypatch.setenv("UNIPLEX_PASSPORT", passport.to_json())
        
        # This is the quickstart code:
        from uniplex import Agent
        
        agent = Agent.from_env()  # Reads UNIPLEX_PASSPORT from environment
        
        # Since we don't have a real MCP server, just verify authorization works
        decision = agent.authorize("search")
        assert decision.allowed is True
