# Uniplex TypeScript SDK

The official TypeScript/JavaScript SDK for the [Uniplex protocol](https://uniplex.io) - AI agent trust infrastructure.

## Installation

```bash
npm install uniplex
```

## Quick Start

```typescript
import { Agent } from 'uniplex';

// Create a self-issued agent
const agent = await Agent.create('my-agent', { permissions: '*' });

// Check authorization
const decision = await agent.authorize('search');
if (decision.allowed) {
  console.log('Action authorized!');
}
```

## Core Concepts

### Passport

Agent identity and permissions:

```typescript
import { Passport } from 'uniplex';

const passport = await Passport.createSelfIssued('my-agent', {
  permissions: 'mcp:*',
  duration: 7 * 24 * 60 * 60 * 1000, // 7 days
});

// Verify signature
const valid = await passport.verifySignature();

// Check permissions
passport.hasPermission('mcp:search'); // true
passport.hasPermission('other:action'); // false
```

### Gate

Authorization enforcement:

```typescript
import { Gate, GateRequest, TrustProfile } from 'uniplex';

const gate = new Gate({ profile: TrustProfile.L1 });

const request = GateRequest.create(passport, 'mcp:search', {
  target: 'mcp://tools.example.com',
});

const decision = await gate.authorize(request);
if (decision.allowed) {
  // Proceed
} else {
  console.log(`Denied: ${decision.reasonCode}`);
}
```

### Attestation

Signed proof of authorization:

```typescript
import { Attestation } from 'uniplex';

const attestation = await Attestation.fromDecision(request, decision, {
  gateId: 'my-gate',
});

// Verify later
const valid = await attestation.verifySignature();
```

## Extensions

### Proof of Possession (PoP)

Required for L2+, binds requests to passport holder:

```typescript
import { ProofOfPossession, PoPVerifier } from 'uniplex';

const pop = await ProofOfPossession.create(
  passport.passportId,
  'mcp://server',
  privateKey
);

// Verify
const verifier = new PoPVerifier();
const result = await verifier.verify(pop, passportId, audience, publicKey);
```

### MCP Integration

Secure Model Context Protocol servers:

```typescript
import { MCPAuthorizer, MCPClient, TrustProfile } from 'uniplex';

// Server side
const authorizer = new MCPAuthorizer({
  serverId: 'mcp://mytools',
  profile: TrustProfile.L2,
  requirePop: true,
});

const result = await authorizer.authorize(passport, 'search', { pop });

// Client side
const client = new MCPClient({
  passport,
  serverId: 'mcp://mytools',
  privateKey,
  usePop: true,
});

const request = await client.createRequest('search', { arguments: { query: 'test' } });
```

### Trust Registry

Manage verified issuers:

```typescript
import { MemoryRegistry, TrustTier } from 'uniplex';

const registry = new MemoryRegistry();
registry.registerIssuer({
  issuerId: 'acme-corp',
  trustTier: TrustTier.VERIFIED,
  publicKeys: [],
  revoked: false,
});
```

### Sessions

Manage ongoing authorization:

```typescript
import { SessionManager } from 'uniplex';

const manager = new SessionManager();
const session = manager.createSession(passport, { target: 'mcp://server' });

// Validate
const { valid, error } = manager.validateSession(session.sessionId, passportId);
```

## Trust Profiles

| Profile | Use Case | Self-Issued | PoP Required |
|---------|----------|-------------|--------------|
| **L1** | Development | ✓ | ✗ |
| **L2** | Production | ✗ | ✓ |
| **L3** | High-assurance | ✗ | ✓ |

## Environment Variables

```bash
export UNIPLEX_PASSPORT='{"passport_id":"..."}'
```

```typescript
const agent = Agent.fromEnv();
```

## License

Apache-2.0

## Links

- [Documentation](https://uniplex.io)
- [GitHub](https://github.com/uniplexprotocol/uniplex)
- [Python SDK](https://pypi.org/project/uniplex/)
