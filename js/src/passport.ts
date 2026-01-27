/**
 * Uniplex Passport - Agent identity and permissions.
 *
 * A Passport is a signed credential that an AI agent carries to prove
 * its identity and permissions.
 */

import { z } from 'zod';
import * as crypto from './crypto.js';

// ============================================================================
// Schemas
// ============================================================================

export const PassportIdentitySchema = z.object({
  agent_id: z.string(),
  type: z.string().default('assistant'),
  metadata: z.record(z.unknown()).optional(),
});

export const PassportIssuerSchema = z.object({
  id: z.string(),
  type: z.enum(['self', 'internal', 'verified', 'certified']),
});

export const PassportPermissionSchema = z.object({
  action: z.string(),
  target: z.string().nullable().default(null),
  constraints: z.record(z.unknown()).optional(),
});

export const PassportProvenanceSchema = z.object({
  issuer: PassportIssuerSchema,
  issued_at: z.string(),
  expires_at: z.string(),
});

export const PassportSchema = z.object({
  uni_version: z.string().default('2026-01-25'),
  passport_id: z.string(),
  identity: PassportIdentitySchema,
  permissions: z.array(PassportPermissionSchema),
  provenance: PassportProvenanceSchema,
  public_key: z.string(),
  signature: z.string().optional(),
});

// ============================================================================
// Types
// ============================================================================

export type PassportIdentity = z.infer<typeof PassportIdentitySchema>;
export type PassportIssuer = z.infer<typeof PassportIssuerSchema>;
export type PassportPermission = z.infer<typeof PassportPermissionSchema>;
export type PassportProvenance = z.infer<typeof PassportProvenanceSchema>;
export type PassportData = z.infer<typeof PassportSchema>;

// ============================================================================
// Passport Class
// ============================================================================

export class Passport {
  readonly uniVersion: string;
  readonly passportId: string;
  readonly identity: PassportIdentity;
  readonly permissions: PassportPermission[];
  readonly provenance: PassportProvenance;
  readonly publicKey: string;
  signature?: string;

  /** Private key for signing (only available for self-issued) */
  private _privateKey?: Uint8Array;

  constructor(data: PassportData, privateKey?: Uint8Array) {
    this.uniVersion = data.uni_version;
    this.passportId = data.passport_id;
    this.identity = data.identity;
    this.permissions = data.permissions;
    this.provenance = data.provenance;
    this.publicKey = data.public_key;
    this.signature = data.signature;
    this._privateKey = privateKey;
  }

  /**
   * Create a self-issued passport.
   */
  static async createSelfIssued(
    agentId: string,
    options: {
      permissions?: string | string[];
      duration?: number; // milliseconds, default 7 days
      type?: string;
      metadata?: Record<string, unknown>;
    } = {}
  ): Promise<Passport> {
    const {
      permissions = '*',
      duration = 7 * 24 * 60 * 60 * 1000,
      type = 'assistant',
      metadata,
    } = options;

    // Generate keypair
    const { privateKey, publicKey } = await crypto.generateKeypair();

    // Parse permissions
    const permList = Array.isArray(permissions) ? permissions : [permissions];
    const permObjects: PassportPermission[] = permList.map((p) => ({
      action: p,
      target: null,
    }));

    // Generate ID
    const passportId = `uni_${crypto.encodeBase64(publicKey).slice(0, 16)}`;

    // Timestamps
    const now = new Date();
    const expires = new Date(now.getTime() + duration);

    const data: PassportData = {
      uni_version: '2026-01-25',
      passport_id: passportId,
      identity: {
        agent_id: agentId,
        type,
        metadata,
      },
      permissions: permObjects,
      provenance: {
        issuer: {
          id: agentId,
          type: 'self',
        },
        issued_at: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
        expires_at: expires.toISOString().replace(/\.\d{3}Z$/, 'Z'),
      },
      public_key: crypto.encodeBase64(publicKey),
    };

    const passport = new Passport(data, privateKey);
    await passport.sign();
    return passport;
  }

  /**
   * Sign the passport with the private key.
   */
  async sign(): Promise<void> {
    if (!this._privateKey) {
      throw new Error('No private key available for signing');
    }

    const dataToSign = this.toDict();
    delete dataToSign.signature;

    const message = crypto.objectToBytes(dataToSign);
    const sig = await crypto.sign(this._privateKey, message);
    this.signature = crypto.encodeBase64(sig);
  }

  /**
   * Verify the passport signature.
   */
  async verifySignature(): Promise<boolean> {
    if (!this.signature) {
      return false;
    }

    try {
      const dataToVerify = this.toDict();
      delete dataToVerify.signature;

      const message = crypto.objectToBytes(dataToVerify);
      const signature = crypto.decodeBase64(this.signature);
      const publicKey = crypto.decodeBase64(this.publicKey);

      return await crypto.verify(publicKey, signature, message);
    } catch {
      return false;
    }
  }

  /**
   * Check if the passport has expired.
   */
  isExpired(): boolean {
    const expiresAt = new Date(this.provenance.expires_at);
    return new Date() > expiresAt;
  }

  /**
   * Check if the passport grants a permission.
   */
  hasPermission(action: string): boolean {
    for (const perm of this.permissions) {
      // Wildcard matches everything
      if (perm.action === '*') {
        return true;
      }

      // Prefix wildcard (e.g., "mcp:*" matches "mcp:search")
      if (perm.action.endsWith(':*')) {
        const prefix = perm.action.slice(0, -1);
        if (action.startsWith(prefix)) {
          return true;
        }
      }

      // Exact match
      if (perm.action === action) {
        return true;
      }
    }
    return false;
  }

  /**
   * Convert to plain object.
   */
  toDict(): PassportData {
    return {
      uni_version: this.uniVersion,
      passport_id: this.passportId,
      identity: this.identity,
      permissions: this.permissions,
      provenance: this.provenance,
      public_key: this.publicKey,
      signature: this.signature,
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
  static fromDict(data: PassportData): Passport {
    const validated = PassportSchema.parse(data);
    return new Passport(validated);
  }

  /**
   * Create from JSON string.
   */
  static fromJson(json: string): Passport {
    return Passport.fromDict(JSON.parse(json));
  }

  /**
   * Create from environment variable.
   */
  static fromEnv(envVar = 'UNIPLEX_PASSPORT'): Passport {
    const value = process.env[envVar];
    if (!value) {
      throw new Error(`Environment variable ${envVar} not set`);
    }
    return Passport.fromJson(value);
  }

  /**
   * Get the private key (if available).
   */
  getPrivateKey(): Uint8Array | undefined {
    return this._privateKey;
  }
}
