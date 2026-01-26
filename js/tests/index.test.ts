/**
 * Uniplex TypeScript SDK Tests
 */

import { describe, it, expect, beforeAll } from 'vitest';
import {
  Agent,
  Passport,
  Gate,
  GateRequest,
  Attestation,
  TrustProfile,
  DenyReason,
  AuthorizationError,
} from '../src/index.js';

describe('Passport', () => {
  it('should create a self-issued passport', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: '*',
    });

    expect(passport.passportId).toMatch(/^uni_/);
    expect(passport.identity.agent_id).toBe('test-agent');
    expect(passport.provenance.issuer.type).toBe('self');
    expect(passport.signature).toBeDefined();
  });

  it('should verify signature', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: '*',
    });

    const valid = await passport.verifySignature();
    expect(valid).toBe(true);
  });

  it('should detect tampered passport', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: '*',
    });

    // Tamper with the passport
    (passport.identity as any).agent_id = 'hacked-agent';

    const valid = await passport.verifySignature();
    expect(valid).toBe(false);
  });

  it('should check wildcard permission', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: '*',
    });

    expect(passport.hasPermission('anything')).toBe(true);
    expect(passport.hasPermission('mcp:search')).toBe(true);
  });

  it('should check prefix wildcard permission', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: 'mcp:*',
    });

    expect(passport.hasPermission('mcp:search')).toBe(true);
    expect(passport.hasPermission('mcp:read')).toBe(true);
    expect(passport.hasPermission('other:action')).toBe(false);
  });

  it('should check exact permission', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: 'mcp:search',
    });

    expect(passport.hasPermission('mcp:search')).toBe(true);
    expect(passport.hasPermission('mcp:read')).toBe(false);
  });

  it('should detect expired passport', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: '*',
      duration: -1000, // Already expired
    });

    expect(passport.isExpired()).toBe(true);
  });

  it('should not be expired by default', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: '*',
    });

    expect(passport.isExpired()).toBe(false);
  });

  it('should serialize and deserialize', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: '*',
    });

    const json = passport.toJson();
    const restored = Passport.fromJson(json);

    expect(restored.passportId).toBe(passport.passportId);
    expect(restored.identity.agent_id).toBe('test-agent');
    expect(await restored.verifySignature()).toBe(true);
  });
});

describe('Gate', () => {
  it('should authorize valid passport', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: '*',
    });
    const gate = new Gate({ profile: TrustProfile.L1 });
    const request = GateRequest.create(passport, 'test:action');

    const decision = await gate.authorize(request);

    expect(decision.allowed).toBe(true);
    expect(decision.passportId).toBe(passport.passportId);
  });

  it('should deny invalid signature', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: '*',
    });
    
    // Tamper with passport
    (passport.identity as any).agent_id = 'hacked';

    const gate = new Gate({ profile: TrustProfile.L1 });
    const request = GateRequest.create(passport, 'test:action');

    const decision = await gate.authorize(request);

    expect(decision.denied).toBe(true);
    expect(decision.reasonCode).toBe(DenyReason.INVALID_SIGNATURE);
  });

  it('should deny expired passport', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: '*',
      duration: -1000,
    });

    const gate = new Gate({ profile: TrustProfile.L1 });
    const request = GateRequest.create(passport, 'test:action');

    const decision = await gate.authorize(request);

    expect(decision.denied).toBe(true);
    expect(decision.reasonCode).toBe(DenyReason.PASSPORT_EXPIRED);
  });

  it('should deny missing permission', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: 'other:action',
    });

    const gate = new Gate({ profile: TrustProfile.L1 });
    const request = GateRequest.create(passport, 'test:action');

    const decision = await gate.authorize(request);

    expect(decision.denied).toBe(true);
    expect(decision.reasonCode).toBe(DenyReason.PERMISSION_DENIED);
  });

  it('should use authorizeSimple', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: '*',
    });
    const gate = new Gate({ profile: TrustProfile.L1 });

    const decision = await gate.authorizeSimple(passport, 'test:action');

    expect(decision.allowed).toBe(true);
  });
});

describe('Attestation', () => {
  it('should create from decision', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: '*',
    });
    const gate = new Gate({ profile: TrustProfile.L1 });
    const request = GateRequest.create(passport, 'test:action');
    const decision = await gate.authorize(request);

    const attestation = await Attestation.fromDecision(request, decision, {
      gateId: 'test-gate',
    });

    expect(attestation.attestationId).toMatch(/^att_/);
    expect(attestation.decision).toBe('allow');
    expect(attestation.gateId).toBe('test-gate');
    expect(attestation.signature).toBeDefined();
  });

  it('should verify signature', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: '*',
    });
    const gate = new Gate({ profile: TrustProfile.L1 });
    const request = GateRequest.create(passport, 'test:action');
    const decision = await gate.authorize(request);

    const attestation = await Attestation.fromDecision(request, decision);

    const valid = await attestation.verifySignature();
    expect(valid).toBe(true);
  });

  it('should serialize and deserialize', async () => {
    const passport = await Passport.createSelfIssued('test-agent', {
      permissions: '*',
    });
    const gate = new Gate({ profile: TrustProfile.L1 });
    const request = GateRequest.create(passport, 'test:action');
    const decision = await gate.authorize(request);
    const attestation = await Attestation.fromDecision(request, decision);

    const json = attestation.toJson();
    const restored = Attestation.fromJson(json);

    expect(restored.attestationId).toBe(attestation.attestationId);
    expect(await restored.verifySignature()).toBe(true);
  });
});

describe('Agent', () => {
  it('should create agent', async () => {
    const agent = await Agent.create('my-agent', { permissions: '*' });

    expect(agent.agentId).toBe('my-agent');
    expect(agent.passportId).toMatch(/^uni_/);
  });

  it('should check can()', async () => {
    const agent = await Agent.create('my-agent', { permissions: 'mcp:*' });

    expect(agent.can('mcp:search')).toBe(true);
    expect(agent.can('other:action')).toBe(false);
  });

  it('should authorize', async () => {
    const agent = await Agent.create('my-agent', { permissions: '*' });

    const decision = await agent.authorize('test:action');

    expect(decision.allowed).toBe(true);
  });

  it('should require (success)', async () => {
    const agent = await Agent.create('my-agent', { permissions: '*' });

    const decision = await agent.require('test:action');

    expect(decision.allowed).toBe(true);
  });

  it('should require (failure)', async () => {
    const agent = await Agent.create('my-agent', { permissions: 'other:action' });

    await expect(agent.require('test:action')).rejects.toThrow(AuthorizationError);
  });

  it('should create request', async () => {
    const agent = await Agent.create('my-agent', { permissions: '*' });

    const request = agent.createRequest('test:action', { target: 'mcp://server' });

    expect(request.action).toBe('test:action');
    expect(request.target).toBe('mcp://server');
  });
});

describe('End-to-End', () => {
  it('should complete full authorization flow', async () => {
    // 1. Create agent
    const agent = await Agent.create('my-agent', { permissions: 'mcp:*' });

    // 2. Create request
    const request = agent.createRequest('mcp:search', {
      target: 'mcp://tools.example.com',
      parameters: { query: 'weather' },
    });

    // 3. Authorize
    const gate = new Gate({ profile: TrustProfile.L1 });
    const decision = await gate.authorize(request);
    expect(decision.allowed).toBe(true);

    // 4. Create attestation
    const attestation = await Attestation.fromDecision(request, decision, {
      gateId: 'prod-gate-1',
    });
    expect(await attestation.verifySignature()).toBe(true);
  });

  it('should match quickstart example', async () => {
    // From the docs quickstart
    const agent = await Agent.create('my-agent', { permissions: '*' });
    const decision = await agent.authorize('search');

    expect(decision.allowed).toBe(true);
  });
});
