/**
 * Uniplex Sessions - Managing ongoing authorization relationships.
 *
 * Sessions allow:
 * - Reduced overhead for repeated authorizations
 * - Session-bound PoP for enhanced security
 * - Audit trails across related requests
 */

import { Passport } from './passport.js';

// ============================================================================
// Types
// ============================================================================

export interface SessionTokenData {
  session_id: string;
  nonce: string;
  passport_id: string;
  agent_id: string;
  target?: string;
  iat: string;
  exp: string;
  permissions: string[];
  metadata?: Record<string, unknown>;
}

// ============================================================================
// Helper Functions
// ============================================================================

function generateSessionId(): string {
  const chars = 'abcdef0123456789';
  let id = 'ses_';
  for (let i = 0; i < 16; i++) {
    id += chars[Math.floor(Math.random() * chars.length)];
  }
  return id;
}

function generateNonce(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let nonce = '';
  for (let i = 0; i < 22; i++) {
    nonce += chars[Math.floor(Math.random() * chars.length)];
  }
  return nonce;
}

// ============================================================================
// SessionToken Class
// ============================================================================

export class SessionToken {
  readonly sessionId: string;
  readonly nonce: string;
  readonly passportId: string;
  readonly agentId: string;
  readonly target?: string;
  readonly iat: string;
  readonly exp: string;
  readonly permissions: string[];
  readonly metadata?: Record<string, unknown>;

  constructor(data: SessionTokenData) {
    this.sessionId = data.session_id;
    this.nonce = data.nonce;
    this.passportId = data.passport_id;
    this.agentId = data.agent_id;
    this.target = data.target;
    this.iat = data.iat;
    this.exp = data.exp;
    this.permissions = data.permissions;
    this.metadata = data.metadata;
  }

  /**
   * Create a new session token.
   */
  static create(
    passport: Passport,
    options: {
      target?: string;
      durationMs?: number;
      permissions?: string[];
    } = {}
  ): SessionToken {
    const { target, durationMs = 60 * 60 * 1000, permissions } = options;

    const now = new Date();
    const exp = new Date(now.getTime() + durationMs);

    // Default to passport permissions
    const perms = permissions ?? passport.permissions.map((p) => p.action);

    return new SessionToken({
      session_id: generateSessionId(),
      nonce: generateNonce(),
      passport_id: passport.passportId,
      agent_id: passport.identity.agent_id,
      target,
      iat: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
      exp: exp.toISOString().replace(/\.\d{3}Z$/, 'Z'),
      permissions: perms,
    });
  }

  /**
   * Check if the session has expired.
   */
  isExpired(): boolean {
    const expDate = new Date(this.exp);
    return new Date() > expDate;
  }

  /**
   * Check if session is valid for a given passport and action.
   */
  isValidFor(passportId: string, action?: string): boolean {
    if (this.isExpired()) {
      return false;
    }

    if (this.passportId !== passportId) {
      return false;
    }

    if (action && !this.hasPermission(action)) {
      return false;
    }

    return true;
  }

  /**
   * Check if session grants permission for action.
   */
  hasPermission(action: string): boolean {
    for (const perm of this.permissions) {
      if (perm === '*') {
        return true;
      }
      if (perm === action) {
        return true;
      }
      if (perm.endsWith(':*')) {
        const prefix = perm.slice(0, -1);
        if (action.startsWith(prefix)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Convert to plain object.
   */
  toDict(): SessionTokenData {
    return {
      session_id: this.sessionId,
      nonce: this.nonce,
      passport_id: this.passportId,
      agent_id: this.agentId,
      target: this.target,
      iat: this.iat,
      exp: this.exp,
      permissions: this.permissions,
      metadata: this.metadata,
    };
  }

  /**
   * Convert to JSON string.
   */
  toJson(): string {
    return JSON.stringify(this.toDict(), null, 2);
  }

  /**
   * Create from plain object.
   */
  static fromDict(data: SessionTokenData): SessionToken {
    return new SessionToken(data);
  }

  /**
   * Create from JSON string.
   */
  static fromJson(json: string): SessionToken {
    return SessionToken.fromDict(JSON.parse(json));
  }
}

// ============================================================================
// SessionManager Class
// ============================================================================

export class SessionManager {
  readonly defaultDurationMs: number;
  readonly maxSessionsPerAgent: number;

  private sessions: Map<string, SessionToken> = new Map();
  private agentSessions: Map<string, Set<string>> = new Map();
  private revoked: Set<string> = new Set();

  constructor(
    options: {
      defaultDurationMs?: number;
      maxSessionsPerAgent?: number;
    } = {}
  ) {
    this.defaultDurationMs = options.defaultDurationMs ?? 60 * 60 * 1000;
    this.maxSessionsPerAgent = options.maxSessionsPerAgent ?? 10;
  }

  /**
   * Create a new session for a passport.
   */
  createSession(
    passport: Passport,
    options: {
      target?: string;
      durationMs?: number;
      permissions?: string[];
    } = {}
  ): SessionToken {
    const agentId = passport.identity.agent_id;

    // Check max sessions
    const existingSessions = this.agentSessions.get(agentId);
    if (existingSessions && existingSessions.size >= this.maxSessionsPerAgent) {
      this.cleanupAgentSessions(agentId);
      const updated = this.agentSessions.get(agentId);
      if (updated && updated.size >= this.maxSessionsPerAgent) {
        throw new Error(`Maximum sessions reached for agent ${agentId}`);
      }
    }

    // Create session
    const session = SessionToken.create(passport, {
      target: options.target,
      durationMs: options.durationMs ?? this.defaultDurationMs,
      permissions: options.permissions,
    });

    // Store
    this.sessions.set(session.sessionId, session);
    if (!this.agentSessions.has(agentId)) {
      this.agentSessions.set(agentId, new Set());
    }
    this.agentSessions.get(agentId)!.add(session.sessionId);

    return session;
  }

  /**
   * Get a session by ID.
   */
  getSession(sessionId: string): SessionToken | undefined {
    if (this.revoked.has(sessionId)) {
      return undefined;
    }
    return this.sessions.get(sessionId);
  }

  /**
   * Validate a session.
   */
  validateSession(
    sessionId: string,
    passportId: string,
    action?: string
  ): { valid: boolean; error?: string } {
    if (this.revoked.has(sessionId)) {
      return { valid: false, error: 'SESSION_REVOKED' };
    }

    const session = this.sessions.get(sessionId);
    if (!session) {
      return { valid: false, error: 'SESSION_NOT_FOUND' };
    }

    if (session.isExpired()) {
      return { valid: false, error: 'SESSION_EXPIRED' };
    }

    if (session.passportId !== passportId) {
      return { valid: false, error: 'SESSION_PASSPORT_MISMATCH' };
    }

    if (action && !session.hasPermission(action)) {
      return { valid: false, error: 'SESSION_PERMISSION_DENIED' };
    }

    return { valid: true };
  }

  /**
   * Revoke a session.
   */
  revokeSession(sessionId: string): boolean {
    const session = this.sessions.get(sessionId);
    if (session) {
      this.revoked.add(sessionId);
      this.sessions.delete(sessionId);
      const agentSessions = this.agentSessions.get(session.agentId);
      if (agentSessions) {
        agentSessions.delete(sessionId);
      }
      return true;
    }
    return false;
  }

  /**
   * Revoke all sessions for an agent.
   */
  revokeAllForAgent(agentId: string): number {
    const sessionIds = this.agentSessions.get(agentId);
    if (!sessionIds) {
      return 0;
    }

    let count = 0;
    for (const sessionId of Array.from(sessionIds)) {
      if (this.revokeSession(sessionId)) {
        count++;
      }
    }
    return count;
  }

  /**
   * Clean up expired sessions for an agent.
   */
  private cleanupAgentSessions(agentId: string): void {
    const sessionIds = this.agentSessions.get(agentId);
    if (!sessionIds) {
      return;
    }

    const expired: string[] = [];
    for (const sessionId of sessionIds) {
      const session = this.sessions.get(sessionId);
      if (!session || session.isExpired()) {
        expired.push(sessionId);
      }
    }

    for (const sessionId of expired) {
      sessionIds.delete(sessionId);
      this.sessions.delete(sessionId);
    }
  }

  /**
   * Clean up all expired sessions.
   */
  cleanupExpired(): number {
    const expired: string[] = [];
    for (const [sessionId, session] of this.sessions) {
      if (session.isExpired()) {
        expired.push(sessionId);
      }
    }

    for (const sessionId of expired) {
      const session = this.sessions.get(sessionId);
      this.sessions.delete(sessionId);
      if (session) {
        const agentSessions = this.agentSessions.get(session.agentId);
        if (agentSessions) {
          agentSessions.delete(sessionId);
        }
      }
    }

    return expired.length;
  }

  /**
   * Get all active sessions for an agent.
   */
  getAgentSessions(agentId: string): SessionToken[] {
    this.cleanupAgentSessions(agentId);
    const sessionIds = this.agentSessions.get(agentId);
    if (!sessionIds) {
      return [];
    }

    const sessions: SessionToken[] = [];
    for (const sessionId of sessionIds) {
      const session = this.sessions.get(sessionId);
      if (session) {
        sessions.push(session);
      }
    }
    return sessions;
  }
}

// ============================================================================
// Default Manager
// ============================================================================

let defaultManager: SessionManager | undefined;

export function getSessionManager(): SessionManager {
  if (!defaultManager) {
    defaultManager = new SessionManager();
  }
  return defaultManager;
}

export function setSessionManager(manager: SessionManager): void {
  defaultManager = manager;
}
