/**
 * Uniplex Gate - Authorization enforcement point.
 *
 * A Gate receives authorization requests and makes allow/deny decisions
 * based on the passport's validity, permissions, and the gate's policy.
 */

import { z } from 'zod';
import { Passport, PassportData } from './passport.js';

// ============================================================================
// Types
// ============================================================================

export enum TrustProfile {
  L1 = 'L1',
  L2 = 'L2',
  L3 = 'L3',
}

export enum DenyReason {
  INVALID_SIGNATURE = 'INVALID_SIGNATURE',
  PASSPORT_EXPIRED = 'PASSPORT_EXPIRED',
  ISSUER_NOT_ALLOWED = 'ISSUER_NOT_ALLOWED',
  PERMISSION_DENIED = 'PERMISSION_DENIED',
  INVALID_REQUEST = 'INVALID_REQUEST',
  PASSPORT_MISSING = 'PASSPORT_MISSING',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
  POP_REQUIRED = 'POP_REQUIRED',
  POP_INVALID = 'POP_INVALID',
}

export interface GatePolicy {
  allowSelfIssued: boolean;
  allowedIssuers?: string[];
}

export interface GateRequestData {
  uni_version: string;
  request_id: string;
  passport: PassportData;
  action: string;
  target?: string | null;
  issued_at: string;
  parameters?: Record<string, unknown>;
}

export interface GateDecisionData {
  uni_version: string;
  request_id: string;
  decision: 'allow' | 'deny';
  decision_at: string;
  passport_id?: string | null;
  agent_id?: string | null;
  action: string;
  reason?: string;
  reason_code?: string;
}

// ============================================================================
// Schemas
// ============================================================================

export const GateRequestSchema = z.object({
  uni_version: z.string().default('2026-01-25'),
  request_id: z.string(),
  passport: z.record(z.unknown()),
  action: z.string(),
  target: z.string().nullable().optional(),
  issued_at: z.string(),
  parameters: z.record(z.unknown()).optional(),
});

// ============================================================================
// Helper Functions
// ============================================================================

function generateRequestId(): string {
  const chars = 'abcdef0123456789';
  let id = 'req_';
  for (let i = 0; i < 12; i++) {
    id += chars[Math.floor(Math.random() * chars.length)];
  }
  return id;
}

// ============================================================================
// GateRequest Class
// ============================================================================

export class GateRequest {
  readonly uniVersion: string;
  readonly requestId: string;
  readonly passport: PassportData;
  readonly action: string;
  readonly target?: string | null;
  readonly issuedAt: string;
  readonly parameters?: Record<string, unknown>;

  constructor(data: GateRequestData) {
    this.uniVersion = data.uni_version;
    this.requestId = data.request_id;
    this.passport = data.passport;
    this.action = data.action;
    this.target = data.target;
    this.issuedAt = data.issued_at;
    this.parameters = data.parameters;
  }

  /**
   * Create a new gate request.
   */
  static create(
    passport: Passport | PassportData,
    action: string,
    options: {
      target?: string;
      parameters?: Record<string, unknown>;
    } = {}
  ): GateRequest {
    const passportData = passport instanceof Passport ? passport.toDict() : passport;

    return new GateRequest({
      uni_version: '2026-01-25',
      request_id: generateRequestId(),
      passport: passportData,
      action,
      target: options.target ?? null,
      issued_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      parameters: options.parameters,
    });
  }

  toDict(): GateRequestData {
    return {
      uni_version: this.uniVersion,
      request_id: this.requestId,
      passport: this.passport,
      action: this.action,
      target: this.target,
      issued_at: this.issuedAt,
      parameters: this.parameters,
    };
  }
}

// ============================================================================
// GateDecision Class
// ============================================================================

export class GateDecision {
  readonly uniVersion: string;
  readonly requestId: string;
  readonly decision: 'allow' | 'deny';
  readonly decisionAt: string;
  readonly passportId?: string | null;
  readonly agentId?: string | null;
  readonly action: string;
  readonly reason?: string;
  readonly reasonCode?: string;

  constructor(data: GateDecisionData) {
    this.uniVersion = data.uni_version;
    this.requestId = data.request_id;
    this.decision = data.decision;
    this.decisionAt = data.decision_at;
    this.passportId = data.passport_id;
    this.agentId = data.agent_id;
    this.action = data.action;
    this.reason = data.reason;
    this.reasonCode = data.reason_code;
  }

  get allowed(): boolean {
    return this.decision === 'allow';
  }

  get denied(): boolean {
    return this.decision === 'deny';
  }

  toDict(): GateDecisionData {
    return {
      uni_version: this.uniVersion,
      request_id: this.requestId,
      decision: this.decision,
      decision_at: this.decisionAt,
      passport_id: this.passportId,
      agent_id: this.agentId,
      action: this.action,
      reason: this.reason,
      reason_code: this.reasonCode,
    };
  }
}

// ============================================================================
// Gate Class
// ============================================================================

export class Gate {
  readonly profile: TrustProfile;
  readonly policy: GatePolicy;

  constructor(options: { profile?: TrustProfile; policy?: Partial<GatePolicy> } = {}) {
    this.profile = options.profile ?? TrustProfile.L1;
    this.policy = {
      allowSelfIssued: this.profile === TrustProfile.L1,
      allowedIssuers: undefined,
      ...options.policy,
    };
  }

  /**
   * Process an authorization request.
   */
  async authorize(request: GateRequest): Promise<GateDecision> {
    let passport: Passport;

    // Parse passport
    try {
      passport = Passport.fromDict(request.passport as PassportData);
    } catch (e) {
      return this.deny(request, DenyReason.INVALID_REQUEST, `Invalid passport format: ${e}`);
    }

    // 1. Verify signature
    const validSig = await passport.verifySignature();
    if (!validSig) {
      return this.deny(
        request,
        DenyReason.INVALID_SIGNATURE,
        'Passport signature verification failed',
        passport
      );
    }

    // 2. Check expiration
    if (passport.isExpired()) {
      return this.deny(request, DenyReason.PASSPORT_EXPIRED, 'Passport has expired', passport);
    }

    // 3. Check issuer policy
    const issuerType = passport.provenance.issuer.type;
    if (issuerType === 'self' && !this.policy.allowSelfIssued) {
      return this.deny(
        request,
        DenyReason.ISSUER_NOT_ALLOWED,
        'Self-issued passports not allowed by this gate',
        passport
      );
    }

    // Check allowed issuers if specified
    if (this.policy.allowedIssuers && issuerType !== 'self') {
      const issuerId = passport.provenance.issuer.id;
      if (!this.policy.allowedIssuers.includes(issuerId)) {
        return this.deny(
          request,
          DenyReason.ISSUER_NOT_ALLOWED,
          `Issuer ${issuerId} not in allowlist`,
          passport
        );
      }
    }

    // 4. Check permission
    if (!passport.hasPermission(request.action)) {
      return this.deny(
        request,
        DenyReason.PERMISSION_DENIED,
        `Passport does not grant permission for action: ${request.action}`,
        passport
      );
    }

    // All checks passed
    return this.allow(request, passport);
  }

  /**
   * Simplified authorization.
   */
  async authorizeSimple(
    passport: Passport | PassportData,
    action: string,
    target?: string
  ): Promise<GateDecision> {
    const request = GateRequest.create(passport, action, { target });
    return this.authorize(request);
  }

  private allow(request: GateRequest, passport: Passport): GateDecision {
    return new GateDecision({
      uni_version: '2026-01-25',
      request_id: request.requestId,
      decision: 'allow',
      decision_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      passport_id: passport.passportId,
      agent_id: passport.identity.agent_id,
      action: request.action,
    });
  }

  private deny(
    request: GateRequest,
    reasonCode: DenyReason,
    reason: string,
    passport?: Passport
  ): GateDecision {
    return new GateDecision({
      uni_version: '2026-01-25',
      request_id: request.requestId,
      decision: 'deny',
      decision_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      passport_id: passport?.passportId ?? null,
      agent_id: passport?.identity.agent_id ?? null,
      action: request.action,
      reason,
      reason_code: reasonCode,
    });
  }
}
