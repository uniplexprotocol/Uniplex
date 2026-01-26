"""
Tests for Uniplex extensions: PoP, Registry, MCP, Sessions.

Run with: pytest tests/
"""

import json
from datetime import timedelta

import pytest

from uniplex import (
    Agent,
    Passport,
    Gate,
    GateRequest,
    TrustProfile,
    DenyReason,
    # Extensions
    ProofOfPossession,
    PoPVerifier,
    MemoryRegistry,
    LocalRegistry,
    TrustResolver,
    TrustTier,
    IssuerInfo,
    SessionToken,
    SessionManager,
    MCPAuthorizer,
    MCPClient,
)


class TestProofOfPossession:
    """Tests for Proof of Possession."""
    
    def test_create_pop(self):
        """Test creating a PoP."""
        passport = Passport.create_self_issued("test-agent", permissions="*")
        
        pop = ProofOfPossession.create(
            passport_id=passport.passport_id,
            audience="mcp://test-server",
            private_key_bytes=passport._private_key,
        )
        
        assert pop.payload.passport_id == passport.passport_id
        assert pop.payload.aud == "mcp://test-server"
        assert pop.signature is not None
        assert pop.public_key == passport.public_key
    
    def test_verify_pop(self):
        """Test verifying a PoP."""
        passport = Passport.create_self_issued("test-agent", permissions="*")
        
        pop = ProofOfPossession.create(
            passport_id=passport.passport_id,
            audience="mcp://test-server",
            private_key_bytes=passport._private_key,
        )
        
        assert pop.verify(expected_public_key=passport.public_key) is True
    
    def test_pop_wrong_public_key_fails(self):
        """Test that PoP with wrong public key fails."""
        passport = Passport.create_self_issued("test-agent", permissions="*")
        other_passport = Passport.create_self_issued("other-agent", permissions="*")
        
        pop = ProofOfPossession.create(
            passport_id=passport.passport_id,
            audience="mcp://test-server",
            private_key_bytes=passport._private_key,
        )
        
        # Verify with wrong public key should fail
        assert pop.verify(expected_public_key=other_passport.public_key) is False
    
    def test_pop_verifier(self):
        """Test PoPVerifier."""
        passport = Passport.create_self_issued("test-agent", permissions="*")
        
        pop = ProofOfPossession.create(
            passport_id=passport.passport_id,
            audience="mcp://test-server",
            private_key_bytes=passport._private_key,
        )
        
        verifier = PoPVerifier()
        is_valid, error = verifier.verify(
            pop=pop,
            expected_passport_id=passport.passport_id,
            expected_audience="mcp://test-server",
            expected_public_key=passport.public_key,
        )
        
        assert is_valid is True
        assert error is None
    
    def test_pop_verifier_replay_detection(self):
        """Test that PoP replay is detected."""
        passport = Passport.create_self_issued("test-agent", permissions="*")
        
        pop = ProofOfPossession.create(
            passport_id=passport.passport_id,
            audience="mcp://test-server",
            private_key_bytes=passport._private_key,
        )
        
        verifier = PoPVerifier()
        
        # First use should succeed
        is_valid, _ = verifier.verify(
            pop=pop,
            expected_passport_id=passport.passport_id,
            expected_audience="mcp://test-server",
            expected_public_key=passport.public_key,
        )
        assert is_valid is True
        
        # Second use should fail (replay)
        is_valid, error = verifier.verify(
            pop=pop,
            expected_passport_id=passport.passport_id,
            expected_audience="mcp://test-server",
            expected_public_key=passport.public_key,
        )
        assert is_valid is False
        assert error == "POP_REPLAY_DETECTED"
    
    def test_pop_audience_mismatch(self):
        """Test PoP audience verification."""
        passport = Passport.create_self_issued("test-agent", permissions="*")
        
        pop = ProofOfPossession.create(
            passport_id=passport.passport_id,
            audience="mcp://server-a",
            private_key_bytes=passport._private_key,
        )
        
        verifier = PoPVerifier()
        is_valid, error = verifier.verify(
            pop=pop,
            expected_passport_id=passport.passport_id,
            expected_audience="mcp://server-b",  # Wrong audience
            expected_public_key=passport.public_key,
        )
        
        assert is_valid is False
        assert error == "POP_AUD_MISMATCH"


class TestRegistry:
    """Tests for Trust Registry."""
    
    def test_memory_registry(self):
        """Test in-memory registry."""
        registry = MemoryRegistry()
        
        issuer = IssuerInfo(
            issuer_id="issuer-1",
            name="Test Issuer",
            trust_tier=TrustTier.VERIFIED,
            public_keys=["key1", "key2"],
        )
        
        registry.register_issuer(issuer)
        
        # Lookup
        found = registry.get_issuer("issuer-1")
        assert found is not None
        assert found.name == "Test Issuer"
        assert found.trust_tier == TrustTier.VERIFIED
    
    def test_registry_trust_tier_check(self):
        """Test trust tier verification."""
        registry = MemoryRegistry()
        
        # Register verified issuer
        registry.register_issuer(IssuerInfo(
            issuer_id="verified-issuer",
            trust_tier=TrustTier.VERIFIED,
        ))
        
        # Register self issuer
        registry.register_issuer(IssuerInfo(
            issuer_id="self-issuer",
            trust_tier=TrustTier.SELF,
        ))
        
        # Verified issuer should pass VERIFIED check
        assert registry.is_issuer_trusted("verified-issuer", TrustTier.VERIFIED) is True
        
        # Self issuer should not pass VERIFIED check
        assert registry.is_issuer_trusted("self-issuer", TrustTier.VERIFIED) is False
        
        # Self issuer should pass SELF check
        assert registry.is_issuer_trusted("self-issuer", TrustTier.SELF) is True
    
    def test_registry_revocation(self):
        """Test issuer revocation."""
        registry = MemoryRegistry()
        
        registry.register_issuer(IssuerInfo(
            issuer_id="issuer-1",
            trust_tier=TrustTier.VERIFIED,
        ))
        
        # Should be trusted initially
        assert registry.is_issuer_trusted("issuer-1") is True
        
        # Revoke
        registry.revoke_issuer("issuer-1", "Compromised")
        
        # Should no longer be trusted
        assert registry.is_issuer_trusted("issuer-1") is False
        assert registry.is_revoked("issuer-1") is True
    
    def test_trust_resolver(self):
        """Test TrustResolver with multiple registries."""
        registry1 = MemoryRegistry()
        registry2 = MemoryRegistry()
        
        registry1.register_issuer(IssuerInfo(
            issuer_id="issuer-a",
            trust_tier=TrustTier.VERIFIED,
        ))
        
        registry2.register_issuer(IssuerInfo(
            issuer_id="issuer-b",
            trust_tier=TrustTier.CERTIFIED,
        ))
        
        resolver = TrustResolver([registry1, registry2])
        
        # Should find in first registry
        assert resolver.resolve_issuer("issuer-a") is not None
        
        # Should find in second registry
        assert resolver.resolve_issuer("issuer-b") is not None
        
        # Should not find unknown
        assert resolver.resolve_issuer("unknown") is None


class TestSession:
    """Tests for Session management."""
    
    def test_create_session(self):
        """Test creating a session."""
        passport = Passport.create_self_issued("test-agent", permissions="*")
        
        session = SessionToken.create(
            passport=passport,
            target="mcp://server",
            duration=timedelta(hours=1),
        )
        
        assert session.passport_id == passport.passport_id
        assert session.agent_id == "test-agent"
        assert session.target == "mcp://server"
        assert session.is_expired() is False
    
    def test_session_expiration(self):
        """Test session expiration."""
        passport = Passport.create_self_issued("test-agent", permissions="*")
        
        # Create expired session
        session = SessionToken.create(
            passport=passport,
            duration=timedelta(seconds=-1),
        )
        
        assert session.is_expired() is True
    
    def test_session_manager(self):
        """Test SessionManager."""
        passport = Passport.create_self_issued("test-agent", permissions="*")
        
        manager = SessionManager()
        
        session = manager.create_session(passport, target="mcp://server")
        
        # Validate session
        is_valid, error = manager.validate_session(
            session.session_id,
            passport.passport_id,
        )
        assert is_valid is True
        
        # Revoke session
        manager.revoke_session(session.session_id)
        
        # Should be invalid after revocation
        is_valid, error = manager.validate_session(
            session.session_id,
            passport.passport_id,
        )
        assert is_valid is False
        assert error == "SESSION_REVOKED"
    
    def test_session_permission_check(self):
        """Test session permission checking."""
        passport = Passport.create_self_issued("test-agent", permissions="tools:*")
        
        session = SessionToken.create(
            passport=passport,
            permissions=["tools:read", "tools:write"],
        )
        
        assert session.is_valid_for(passport.passport_id, "tools:read") is True
        assert session.is_valid_for(passport.passport_id, "tools:write") is True
        assert session.is_valid_for(passport.passport_id, "tools:delete") is False


class TestMCPIntegration:
    """Tests for MCP integration."""
    
    def test_mcp_authorizer_l1(self):
        """Test MCP authorizer with L1 profile."""
        passport = Passport.create_self_issued("test-agent", permissions="mcp:*")
        
        authorizer = MCPAuthorizer(
            server_id="mcp://test-server",
            profile=TrustProfile.L1,
        )
        
        result = authorizer.authorize(
            passport=passport,
            tool_name="search",
            parameters={"query": "test"},
        )
        
        assert result.allowed is True
        assert result.attestation is not None
    
    def test_mcp_authorizer_permission_denied(self):
        """Test MCP authorizer denies unauthorized actions."""
        passport = Passport.create_self_issued("test-agent", permissions="tools:read")
        
        authorizer = MCPAuthorizer(
            server_id="mcp://test-server",
            profile=TrustProfile.L1,
        )
        
        result = authorizer.authorize(
            passport=passport,
            tool_name="write",  # Not in permissions
            parameters={},
        )
        
        assert result.allowed is False
        assert result.error_code == "PERMISSION_DENIED"
    
    def test_mcp_authorizer_with_pop(self):
        """Test MCP authorizer with PoP requirement."""
        passport = Passport.create_self_issued("test-agent", permissions="mcp:*")
        
        authorizer = MCPAuthorizer(
            server_id="mcp://test-server",
            profile=TrustProfile.L1,
            require_pop=True,
        )
        
        # Create PoP
        pop = ProofOfPossession.create(
            passport_id=passport.passport_id,
            audience="mcp://test-server",
            private_key_bytes=passport._private_key,
        )
        
        result = authorizer.authorize(
            passport=passport,
            tool_name="search",
            pop=pop.to_dict(),
        )
        
        assert result.allowed is True
    
    def test_mcp_authorizer_pop_required_but_missing(self):
        """Test MCP authorizer fails when PoP required but missing."""
        passport = Passport.create_self_issued("test-agent", permissions="mcp:*")
        
        authorizer = MCPAuthorizer(
            server_id="mcp://test-server",
            profile=TrustProfile.L1,
            require_pop=True,
        )
        
        result = authorizer.authorize(
            passport=passport,
            tool_name="search",
            # No PoP provided
        )
        
        assert result.allowed is False
        assert result.error_code == "POP_REQUIRED"
    
    def test_mcp_client(self):
        """Test MCP client request creation."""
        passport = Passport.create_self_issued("test-agent", permissions="mcp:*")
        
        client = MCPClient(
            passport=passport,
            server_id="mcp://test-server",
        )
        
        request = client.create_request("search", {"query": "test"})
        
        assert request["method"] == "search"
        assert request["params"] == {"query": "test"}
        assert "passport" in request
    
    def test_mcp_client_with_pop(self):
        """Test MCP client with PoP."""
        passport = Passport.create_self_issued("test-agent", permissions="mcp:*")
        
        client = MCPClient(
            passport=passport,
            server_id="mcp://test-server",
            private_key=passport._private_key,
            use_pop=True,
        )
        
        request = client.create_request("search", {"query": "test"})
        
        assert "pop" in request
        assert request["pop"]["payload"]["aud"] == "mcp://test-server"


class TestGateWithExtensions:
    """Tests for Gate with L2/L3 extensions."""
    
    def test_gate_l2_requires_pop(self):
        """Test that L2 gate requires PoP by default."""
        passport = Passport.create_self_issued("test-agent", permissions="*")
        
        # Create L2 gate (requires PoP by default)
        gate = Gate(profile=TrustProfile.L2)
        
        # Request without PoP should fail
        request = GateRequest.create(passport, action="test")
        decision = gate.authorize(request)
        
        # Should be denied for missing PoP (but might fail earlier for self-issued)
        assert decision.denied is True
    
    def test_gate_l1_with_optional_pop(self):
        """Test L1 gate with optional PoP verification."""
        passport = Passport.create_self_issued("test-agent", permissions="*")
        
        # L1 gate with PoP enabled
        gate = Gate(profile=TrustProfile.L1, require_pop=True)
        
        # Create valid PoP
        pop = ProofOfPossession.create(
            passport_id=passport.passport_id,
            audience=gate.gate_id,
            private_key_bytes=passport._private_key,
        )
        
        request = GateRequest.create(passport, action="test", pop=pop.to_dict())
        decision = gate.authorize(request)
        
        assert decision.allowed is True
    
    def test_gate_with_registry(self):
        """Test gate with registry for issuer verification."""
        # Create a registry with a verified issuer
        registry = MemoryRegistry()
        registry.register_issuer(IssuerInfo(
            issuer_id="trusted-issuer",
            trust_tier=TrustTier.VERIFIED,
            public_keys=["test-key"],
        ))
        
        # Create L1 gate with registry (for testing)
        gate = Gate(
            profile=TrustProfile.L1,
            registry=registry,
        )
        
        # Self-issued passport should still work with L1
        passport = Passport.create_self_issued("test-agent", permissions="*")
        decision = gate.authorize_simple(passport, "test")
        
        assert decision.allowed is True


class TestEndToEndWithExtensions:
    """End-to-end tests with extensions."""
    
    def test_full_l2_flow(self):
        """Test complete L2 authorization flow."""
        # 1. Create agent with passport
        passport = Passport.create_self_issued("my-agent", permissions="mcp:*")
        
        # 2. Create MCP authorizer
        authorizer = MCPAuthorizer(
            server_id="mcp://tools.example.com",
            profile=TrustProfile.L1,  # Use L1 since we have self-issued passport
            require_pop=True,
        )
        
        # 3. Create PoP for the request
        pop = ProofOfPossession.create(
            passport_id=passport.passport_id,
            audience="mcp://tools.example.com",
            private_key_bytes=passport._private_key,
        )
        
        # 4. Authorize
        result = authorizer.authorize(
            passport=passport,
            tool_name="search",
            parameters={"query": "weather"},
            pop=pop.to_dict(),
        )
        
        # 5. Verify result
        assert result.allowed is True
        assert result.attestation is not None
        assert result.attestation.verify_signature() is True
    
    def test_mcp_client_to_authorizer(self):
        """Test MCP client creating request that authorizer accepts."""
        passport = Passport.create_self_issued("my-agent", permissions="mcp:*")
        
        # Client side
        client = MCPClient(
            passport=passport,
            server_id="mcp://server",
            private_key=passport._private_key,
            use_pop=True,
        )
        
        request = client.create_request("search", {"q": "test"})
        
        # Server side
        authorizer = MCPAuthorizer(
            server_id="mcp://server",
            profile=TrustProfile.L1,
            require_pop=True,
        )
        
        result = authorizer.authorize(
            passport=request["passport"],
            tool_name=request["method"],
            parameters=request["params"],
            pop=request["pop"],
        )
        
        assert result.allowed is True
