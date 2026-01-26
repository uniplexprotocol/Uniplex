/**
 * Uniplex - The Trust Layer for AI Agents
 *
 * Uniplex provides a universal protocol for:
 * - Agent identity (Uni-Passport)
 * - Runtime permission enforcement (Uni-Gate)
 * - Portable verification evidence (Uni-Attestation)
 *
 * @example
 * ```typescript
 * import { Agent } from 'uniplex';
 *
 * // Create a self-issued agent
 * const agent = await Agent.create('my-agent', { permissions: '*' });
 *
 * // Check authorization
 * const decision = await agent.authorize('search');
 * if (decision.allowed) {
 *   console.log('Action authorized!');
 * }
 * ```
 *
 * @see https://uniplex.io
 */

export const VERSION = '2026.1.25';

// Passport
export {
  Passport,
  PassportIdentity,
  PassportIssuer,
  PassportPermission,
  PassportProvenance,
  PassportData,
} from './passport.js';

// Gate
export {
  Gate,
  GateRequest,
  GateDecision,
  GatePolicy,
  GateRequestData,
  GateDecisionData,
  TrustProfile,
  DenyReason,
} from './gate.js';

// Attestation
export { Attestation, AttestationData } from './attestation.js';

// Agent (high-level API)
export { Agent, AuthorizationError } from './agent.js';

// Proof of Possession
export {
  ProofOfPossession,
  PoPVerifier,
  PoPPayloadData,
  ProofOfPossessionData,
} from './pop.js';

// Registry
export {
  TrustRegistry,
  MemoryRegistry,
  TrustResolver,
  TrustTier,
  IssuerInfo,
  getDefaultResolver,
  setDefaultResolver,
} from './registry.js';

// Sessions
export {
  SessionToken,
  SessionManager,
  SessionTokenData,
  getSessionManager,
  setSessionManager,
} from './session.js';

// MCP Integration
export {
  MCPAuthorizer,
  MCPClient,
  MCPAuthConfig,
  MCPAuthResult,
  createMcpGateMiddleware,
} from './mcp.js';

// Crypto utilities (for advanced use)
export * as crypto from './crypto.js';
