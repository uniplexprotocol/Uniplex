/**
 * Uniplex Agent - High-level API for agent authorization.
 *
 * Provides a simple interface for common authorization tasks.
 */

import { Passport } from './passport.js';
import { Gate, GateRequest, GateDecision, TrustProfile } from './gate.js';
import { Attestation } from './attestation.js';

// ============================================================================
// Errors
// ============================================================================

export class AuthorizationError extends Error {
  readonly decision: GateDecision;

  constructor(message: string, decision: GateDecision) {
    super(message);
    this.name = 'AuthorizationError';
    this.decision = decision;
  }
}

// ============================================================================
// Agent Class
// ============================================================================

export class Agent {
  readonly passport: Passport;
  private readonly gate: Gate;

  constructor(passport: Passport, gate?: Gate) {
    this.passport = passport;
    this.gate = gate ?? new Gate({ profile: TrustProfile.L1 });
  }

  /**
   * Create a new agent with a self-issued passport.
   */
  static async create(
    agentId: string,
    options: {
      permissions?: string | string[];
      duration?: number;
      type?: string;
      metadata?: Record<string, unknown>;
    } = {}
  ): Promise<Agent> {
    const passport = await Passport.createSelfIssued(agentId, options);
    return new Agent(passport);
  }

  /**
   * Load agent from environment variable.
   */
  static fromEnv(envVar = 'UNIPLEX_PASSPORT'): Agent {
    const passport = Passport.fromEnv(envVar);
    return new Agent(passport);
  }

  /**
   * Load agent from a passport file (JSON).
   */
  static fromJson(json: string): Agent {
    const passport = Passport.fromJson(json);
    return new Agent(passport);
  }

  /**
   * Get the agent ID.
   */
  get agentId(): string {
    return this.passport.identity.agent_id;
  }

  /**
   * Get the passport ID.
   */
  get passportId(): string {
    return this.passport.passportId;
  }

  /**
   * Check if an action is authorized (quick check, no attestation).
   */
  can(action: string): boolean {
    if (this.passport.isExpired()) {
      return false;
    }
    return this.passport.hasPermission(action);
  }

  /**
   * Authorize an action (full check with decision).
   */
  async authorize(
    action: string,
    options: {
      target?: string;
      parameters?: Record<string, unknown>;
    } = {}
  ): Promise<GateDecision> {
    const request = GateRequest.create(this.passport, action, options);
    return this.gate.authorize(request);
  }

  /**
   * Require authorization (throws if denied).
   */
  async require(
    action: string,
    options: {
      target?: string;
      parameters?: Record<string, unknown>;
    } = {}
  ): Promise<GateDecision> {
    const decision = await this.authorize(action, options);
    if (decision.denied) {
      throw new AuthorizationError(
        `Authorization denied: ${decision.reason ?? decision.reasonCode}`,
        decision
      );
    }
    return decision;
  }

  /**
   * Create a gate request for this agent.
   */
  createRequest(
    action: string,
    options: {
      target?: string;
      parameters?: Record<string, unknown>;
    } = {}
  ): GateRequest {
    return GateRequest.create(this.passport, action, options);
  }

  /**
   * Export passport to JSON.
   */
  toJson(): string {
    return this.passport.toJson();
  }
}
