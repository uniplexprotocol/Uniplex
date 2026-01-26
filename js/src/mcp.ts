/**
 * Uniplex MCP Integration - Trust layer for Model Context Protocol.
 *
 * "MCP is the plumbing. Uniplex is the trust."
 *
 * This module provides:
 * - MCP server wrapping (add authorization to any MCP server)
 * - MCP client helpers (authorized tool calls)
 */

import { Passport, PassportData } from './passport.js';
import { Gate, GateRequest, GateDecision, TrustProfile } from './gate.js';
import { Attestation } from './attestation.js';
import { ProofOfPossession, ProofOfPossessionData, PoPVerifier } from './pop.js';

// ============================================================================
// Types
// ============================================================================

export interface MCPAuthConfig {
  serverId: string;
  profile?: TrustProfile;
  requirePop?: boolean;
  allowedTools?: string[];
  logDecisions?: boolean;
}

export interface MCPAuthResult {
  allowed: boolean;
  decision?: GateDecision;
  attestation?: Attestation;
  error?: string;
  errorCode?: string;
}

// ============================================================================
// MCPAuthorizer Class
// ============================================================================

export class MCPAuthorizer {
  readonly serverId: string;
  readonly profile: TrustProfile;
  readonly gate: Gate;
  readonly requirePop: boolean;
  private popVerifier?: PoPVerifier;

  constructor(options: {
    serverId: string;
    profile?: TrustProfile;
    gate?: Gate;
    requirePop?: boolean;
    popMaxAge?: number;
  }) {
    this.serverId = options.serverId;
    this.profile = options.profile ?? TrustProfile.L1;
    this.gate = options.gate ?? new Gate({ profile: this.profile });
    this.requirePop =
      options.requirePop ?? (this.profile === TrustProfile.L2 || this.profile === TrustProfile.L3);

    if (this.requirePop) {
      this.popVerifier = new PoPVerifier({ maxAgeSeconds: options.popMaxAge ?? 300 });
    }
  }

  /**
   * Authorize an MCP tool call.
   */
  async authorize(
    passport: Passport | PassportData,
    toolName: string,
    options: {
      parameters?: Record<string, unknown>;
      pop?: ProofOfPossession | ProofOfPossessionData;
      sessionNonce?: string;
    } = {}
  ): Promise<MCPAuthResult> {
    // Parse passport if needed
    let passportObj: Passport;
    try {
      passportObj = passport instanceof Passport ? passport : Passport.fromDict(passport);
    } catch (e) {
      return {
        allowed: false,
        error: `Invalid passport: ${e}`,
        errorCode: 'INVALID_PASSPORT',
      };
    }

    // Map MCP concepts to Uniplex
    const action = `mcp:${toolName}`;
    const target = this.serverId;

    // Create gate request
    const request = GateRequest.create(passportObj, action, {
      target,
      parameters: options.parameters,
    });

    // Check PoP if required
    if (this.requirePop) {
      if (!options.pop) {
        return {
          allowed: false,
          error: 'Proof of Possession required',
          errorCode: 'POP_REQUIRED',
        };
      }

      // Parse PoP if needed
      let popObj: ProofOfPossession;
      try {
        popObj =
          options.pop instanceof ProofOfPossession
            ? options.pop
            : ProofOfPossession.fromDict(options.pop);
      } catch (e) {
        return {
          allowed: false,
          error: `Invalid PoP: ${e}`,
          errorCode: 'POP_INVALID',
        };
      }

      // Verify PoP
      const popResult = await this.popVerifier!.verify(
        popObj,
        passportObj.passportId,
        target,
        passportObj.publicKey,
        options.sessionNonce
      );

      if (!popResult.valid) {
        return {
          allowed: false,
          error: `PoP verification failed: ${popResult.error}`,
          errorCode: popResult.error,
        };
      }
    }

    // Run gate authorization
    const decision = await this.gate.authorize(request);

    // Generate attestation
    let attestation: Attestation | undefined;
    if (decision.allowed) {
      attestation = await Attestation.fromDecision(request, decision, {
        gateId: this.serverId,
      });
    }

    return {
      allowed: decision.allowed,
      decision,
      attestation,
      error: decision.denied ? decision.reason : undefined,
      errorCode: decision.denied ? decision.reasonCode : undefined,
    };
  }
}

// ============================================================================
// MCPClient Class
// ============================================================================

export class MCPClient {
  readonly passport: Passport;
  readonly serverId: string;
  readonly privateKey?: Uint8Array;
  readonly usePop: boolean;

  constructor(options: {
    passport: Passport;
    serverId: string;
    privateKey?: Uint8Array;
    usePop?: boolean;
  }) {
    this.passport = options.passport;
    this.serverId = options.serverId;
    this.privateKey = options.privateKey;
    this.usePop = options.usePop ?? false;

    if (this.usePop && !this.privateKey) {
      throw new Error('Private key required for PoP');
    }
  }

  /**
   * Create an authorized MCP request.
   */
  async createRequest(
    toolName: string,
    options: {
      arguments?: Record<string, unknown>;
      sessionNonce?: string;
    } = {}
  ): Promise<{
    jsonrpc: string;
    method: string;
    params: Record<string, unknown>;
    passport: PassportData;
    pop?: ProofOfPossessionData;
  }> {
    const request: {
      jsonrpc: string;
      method: string;
      params: Record<string, unknown>;
      passport: PassportData;
      pop?: ProofOfPossessionData;
    } = {
      jsonrpc: '2.0',
      method: toolName,
      params: options.arguments ?? {},
      passport: this.passport.toDict(),
    };

    // Add PoP if enabled
    if (this.usePop && this.privateKey) {
      const pop = await ProofOfPossession.create(
        this.passport.passportId,
        this.serverId,
        this.privateKey,
        { sessionNonce: options.sessionNonce }
      );
      request.pop = pop.toDict();
    }

    return request;
  }

  /**
   * Make an authorized tool call.
   */
  async call<T = unknown>(
    toolName: string,
    options: {
      arguments?: Record<string, unknown>;
      handler?: (request: Record<string, unknown>) => Promise<T>;
    } = {}
  ): Promise<T | Record<string, unknown>> {
    const request = await this.createRequest(toolName, {
      arguments: options.arguments,
    });

    if (options.handler) {
      return options.handler(request);
    }

    return request;
  }
}

// ============================================================================
// Middleware Helper
// ============================================================================

export function createMcpGateMiddleware(options: {
  serverId: string;
  profile?: TrustProfile;
}): (
  request: Record<string, unknown>,
  next: (request: Record<string, unknown>) => unknown
) => Promise<unknown> {
  const authorizer = new MCPAuthorizer({
    serverId: options.serverId,
    profile: options.profile,
  });

  return async (request, next) => {
    const passport = request.passport as PassportData | undefined;
    const tool = (request.tool || request.method) as string | undefined;
    const args = (request.arguments || request.params || {}) as Record<string, unknown>;

    if (!passport) {
      return {
        error: {
          code: 'PASSPORT_MISSING',
          message: 'No passport provided',
        },
      };
    }

    if (!tool) {
      return {
        error: {
          code: 'TOOL_MISSING',
          message: 'No tool specified',
        },
      };
    }

    const result = await authorizer.authorize(passport, tool, { parameters: args });

    if (!result.allowed) {
      return {
        error: {
          code: result.errorCode,
          message: result.error,
        },
      };
    }

    // Proceed to next handler
    const response = (await next(request)) as Record<string, unknown>;

    // Add attestation to response
    if (typeof response === 'object' && response !== null && result.attestation) {
      response.attestation = result.attestation.toDict();
    }

    return response;
  };
}
