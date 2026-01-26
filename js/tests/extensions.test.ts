/**
 * Uniplex TypeScript SDK Extension Tests
 * Tests for PoP, Registry, Sessions, MCP
 */

import { describe, it, expect } from 'vitest';
import {
  Passport,
  Gate,
  GateRequest,
  Attestation,
  TrustProfile,
  // Extensions
  ProofOfPossession,
  PoPVerifier,
  MemoryRegistry,
  TrustResolver,
  TrustTier,
  IssuerInfo,
  SessionToken,
  SessionManager,
  MCPAuthorizer,
  MCPClient,
} from '../src/index.js';

describe('ProofOfPossession', () => {
  it('should create a PoP', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: '*' });
    const privateKey = passport.getPrivateKey()!;

    const pop = await ProofOfPossession.create(
      passport.passportId,
      'mcp://test-server',
      privateKey
    );

    expect(pop.payload.passport_id).toBe(passport.passportId);
    expect(pop.payload.aud).toBe('mcp://test-server');
    expect(pop.signature).toBeDefined();
    expect(pop.publicKey).toBe(passport.publicKey);
  });

  it('should verify a PoP', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: '*' });
    const privateKey = passport.getPrivateKey()!;

    const pop = await ProofOfPossession.create(
      passport.passportId,
      'mcp://test-server',
      privateKey
    );

    const valid = await pop.verify(passport.publicKey);
    expect(valid).toBe(true);
  });

  it('should fail with wrong public key', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: '*' });
    const otherPassport = await Passport.createSelfIssued('other-agent', { permissions: '*' });
    const privateKey = passport.getPrivateKey()!;

    const pop = await ProofOfPossession.create(
      passport.passportId,
      'mcp://test-server',
      privateKey
    );

    const valid = await pop.verify(otherPassport.publicKey);
    expect(valid).toBe(false);
  });

  it('should detect replay', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: '*' });
    const privateKey = passport.getPrivateKey()!;

    const pop = await ProofOfPossession.create(
      passport.passportId,
      'mcp://test-server',
      privateKey
    );

    const verifier = new PoPVerifier();

    // First use should succeed
    const result1 = await verifier.verify(
      pop,
      passport.passportId,
      'mcp://test-server',
      passport.publicKey
    );
    expect(result1.valid).toBe(true);

    // Second use should fail (replay)
    const result2 = await verifier.verify(
      pop,
      passport.passportId,
      'mcp://test-server',
      passport.publicKey
    );
    expect(result2.valid).toBe(false);
    expect(result2.error).toBe('POP_REPLAY_DETECTED');
  });

  it('should detect audience mismatch', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: '*' });
    const privateKey = passport.getPrivateKey()!;

    const pop = await ProofOfPossession.create(passport.passportId, 'mcp://server-a', privateKey);

    const verifier = new PoPVerifier();
    const result = await verifier.verify(
      pop,
      passport.passportId,
      'mcp://server-b', // Wrong audience
      passport.publicKey
    );

    expect(result.valid).toBe(false);
    expect(result.error).toBe('POP_AUD_MISMATCH');
  });
});

describe('Registry', () => {
  it('should register and lookup issuer', () => {
    const registry = new MemoryRegistry();

    const issuer: IssuerInfo = {
      issuerId: 'issuer-1',
      name: 'Test Issuer',
      trustTier: TrustTier.VERIFIED,
      publicKeys: ['key1', 'key2'],
      revoked: false,
    };

    registry.registerIssuer(issuer);

    const found = registry.getIssuer('issuer-1');
    expect(found).toBeDefined();
    expect(found!.name).toBe('Test Issuer');
    expect(found!.trustTier).toBe(TrustTier.VERIFIED);
  });

  it('should check trust tier', () => {
    const registry = new MemoryRegistry();

    registry.registerIssuer({
      issuerId: 'verified-issuer',
      trustTier: TrustTier.VERIFIED,
      publicKeys: [],
      revoked: false,
    });

    registry.registerIssuer({
      issuerId: 'self-issuer',
      trustTier: TrustTier.SELF,
      publicKeys: [],
      revoked: false,
    });

    expect(registry.isIssuerTrusted('verified-issuer', TrustTier.VERIFIED)).toBe(true);
    expect(registry.isIssuerTrusted('self-issuer', TrustTier.VERIFIED)).toBe(false);
    expect(registry.isIssuerTrusted('self-issuer', TrustTier.SELF)).toBe(true);
  });

  it('should handle revocation', () => {
    const registry = new MemoryRegistry();

    registry.registerIssuer({
      issuerId: 'issuer-1',
      trustTier: TrustTier.VERIFIED,
      publicKeys: [],
      revoked: false,
    });

    expect(registry.isIssuerTrusted('issuer-1')).toBe(true);

    registry.revokeIssuer('issuer-1', 'Compromised');

    expect(registry.isIssuerTrusted('issuer-1')).toBe(false);
    expect(registry.isRevoked('issuer-1')).toBe(true);
  });

  it('should resolve across multiple registries', () => {
    const registry1 = new MemoryRegistry();
    const registry2 = new MemoryRegistry();

    registry1.registerIssuer({
      issuerId: 'issuer-a',
      trustTier: TrustTier.VERIFIED,
      publicKeys: [],
      revoked: false,
    });

    registry2.registerIssuer({
      issuerId: 'issuer-b',
      trustTier: TrustTier.CERTIFIED,
      publicKeys: [],
      revoked: false,
    });

    const resolver = new TrustResolver([registry1, registry2]);

    expect(resolver.resolveIssuer('issuer-a')).toBeDefined();
    expect(resolver.resolveIssuer('issuer-b')).toBeDefined();
    expect(resolver.resolveIssuer('unknown')).toBeUndefined();
  });
});

describe('Session', () => {
  it('should create a session', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: '*' });

    const session = SessionToken.create(passport, {
      target: 'mcp://server',
      durationMs: 60 * 60 * 1000,
    });

    expect(session.passportId).toBe(passport.passportId);
    expect(session.agentId).toBe('test-agent');
    expect(session.target).toBe('mcp://server');
    expect(session.isExpired()).toBe(false);
  });

  it('should detect expired session', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: '*' });

    const session = SessionToken.create(passport, {
      durationMs: -1000, // Already expired
    });

    expect(session.isExpired()).toBe(true);
  });

  it('should manage sessions', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: '*' });

    const manager = new SessionManager();
    const session = manager.createSession(passport, { target: 'mcp://server' });

    // Validate
    const result = manager.validateSession(session.sessionId, passport.passportId);
    expect(result.valid).toBe(true);

    // Revoke
    manager.revokeSession(session.sessionId);

    // Should be invalid
    const result2 = manager.validateSession(session.sessionId, passport.passportId);
    expect(result2.valid).toBe(false);
    expect(result2.error).toBe('SESSION_REVOKED');
  });

  it('should check session permissions', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: 'tools:*' });

    const session = SessionToken.create(passport, {
      permissions: ['tools:read', 'tools:write'],
    });

    expect(session.isValidFor(passport.passportId, 'tools:read')).toBe(true);
    expect(session.isValidFor(passport.passportId, 'tools:write')).toBe(true);
    expect(session.isValidFor(passport.passportId, 'tools:delete')).toBe(false);
  });
});

describe('MCP Integration', () => {
  it('should authorize L1 request', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: 'mcp:*' });

    const authorizer = new MCPAuthorizer({
      serverId: 'mcp://test-server',
      profile: TrustProfile.L1,
    });

    const result = await authorizer.authorize(passport, 'search', {
      parameters: { query: 'test' },
    });

    expect(result.allowed).toBe(true);
    expect(result.attestation).toBeDefined();
  });

  it('should deny unauthorized action', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: 'tools:read' });

    const authorizer = new MCPAuthorizer({
      serverId: 'mcp://test-server',
      profile: TrustProfile.L1,
    });

    const result = await authorizer.authorize(passport, 'write');

    expect(result.allowed).toBe(false);
    expect(result.errorCode).toBe('PERMISSION_DENIED');
  });

  it('should require PoP when configured', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: 'mcp:*' });

    const authorizer = new MCPAuthorizer({
      serverId: 'mcp://test-server',
      profile: TrustProfile.L1,
      requirePop: true,
    });

    // Without PoP
    const result = await authorizer.authorize(passport, 'search');
    expect(result.allowed).toBe(false);
    expect(result.errorCode).toBe('POP_REQUIRED');
  });

  it('should authorize with PoP', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: 'mcp:*' });
    const privateKey = passport.getPrivateKey()!;

    const authorizer = new MCPAuthorizer({
      serverId: 'mcp://test-server',
      profile: TrustProfile.L1,
      requirePop: true,
    });

    const pop = await ProofOfPossession.create(
      passport.passportId,
      'mcp://test-server',
      privateKey
    );

    const result = await authorizer.authorize(passport, 'search', { pop });
    expect(result.allowed).toBe(true);
  });

  it('should create MCP client request', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: 'mcp:*' });

    const client = new MCPClient({
      passport,
      serverId: 'mcp://test-server',
    });

    const request = await client.createRequest('search', { arguments: { query: 'test' } });

    expect(request.method).toBe('search');
    expect(request.params).toEqual({ query: 'test' });
    expect(request.passport).toBeDefined();
  });

  it('should create MCP client request with PoP', async () => {
    const passport = await Passport.createSelfIssued('test-agent', { permissions: 'mcp:*' });
    const privateKey = passport.getPrivateKey()!;

    const client = new MCPClient({
      passport,
      serverId: 'mcp://test-server',
      privateKey,
      usePop: true,
    });

    const request = await client.createRequest('search', { arguments: { query: 'test' } });

    expect(request.pop).toBeDefined();
    expect(request.pop!.payload.aud).toBe('mcp://test-server');
  });
});

describe('End-to-End with Extensions', () => {
  it('should complete full L2-style flow', async () => {
    // 1. Create agent
    const passport = await Passport.createSelfIssued('my-agent', { permissions: 'mcp:*' });
    const privateKey = passport.getPrivateKey()!;

    // 2. Create authorizer
    const authorizer = new MCPAuthorizer({
      serverId: 'mcp://tools.example.com',
      profile: TrustProfile.L1,
      requirePop: true,
    });

    // 3. Create PoP
    const pop = await ProofOfPossession.create(
      passport.passportId,
      'mcp://tools.example.com',
      privateKey
    );

    // 4. Authorize
    const result = await authorizer.authorize(passport, 'search', {
      parameters: { query: 'weather' },
      pop,
    });

    // 5. Verify
    expect(result.allowed).toBe(true);
    expect(result.attestation).toBeDefined();
    const validAttestation = await result.attestation!.verifySignature();
    expect(validAttestation).toBe(true);
  });

  it('should work with MCP client and authorizer', async () => {
    const passport = await Passport.createSelfIssued('my-agent', { permissions: 'mcp:*' });
    const privateKey = passport.getPrivateKey()!;

    // Client side
    const client = new MCPClient({
      passport,
      serverId: 'mcp://server',
      privateKey,
      usePop: true,
    });

    const request = await client.createRequest('search', { arguments: { q: 'test' } });

    // Server side
    const authorizer = new MCPAuthorizer({
      serverId: 'mcp://server',
      profile: TrustProfile.L1,
      requirePop: true,
    });

    const result = await authorizer.authorize(request.passport, 'search', {
      parameters: request.params,
      pop: request.pop,
    });

    expect(result.allowed).toBe(true);
  });
});
