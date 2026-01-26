/**
 * Uniplex Attestation - Signed proof of authorization.
 *
 * An Attestation is a cryptographically signed record of an authorization decision.
 * It provides non-repudiable evidence that a specific check was performed.
 */

import * as crypto from './crypto.js';
import { GateRequest, GateDecision } from './gate.js';

// ============================================================================
// Types
// ============================================================================

export interface AttestationData {
  uni_version: string;
  attestation_id: string;
  request_id: string;
  passport_id: string | null;
  agent_id: string | null;
  action: string;
  target?: string | null;
  decision: 'allow' | 'deny';
  reason_code?: string | null;
  created_at: string;
  gate_id?: string | null;
  public_key?: string;
  signature?: string;
}

// ============================================================================
// Helper Functions
// ============================================================================

function generateAttestationId(): string {
  const chars = 'abcdef0123456789';
  let id = 'att_';
  for (let i = 0; i < 12; i++) {
    id += chars[Math.floor(Math.random() * chars.length)];
  }
  return id;
}

// ============================================================================
// Attestation Class
// ============================================================================

export class Attestation {
  readonly uniVersion: string;
  readonly attestationId: string;
  readonly requestId: string;
  readonly passportId: string | null;
  readonly agentId: string | null;
  readonly action: string;
  readonly target?: string | null;
  readonly decision: 'allow' | 'deny';
  readonly reasonCode?: string | null;
  readonly createdAt: string;
  readonly gateId?: string | null;
  publicKey?: string;
  signature?: string;

  private _privateKey?: Uint8Array;

  constructor(data: AttestationData, privateKey?: Uint8Array) {
    this.uniVersion = data.uni_version;
    this.attestationId = data.attestation_id;
    this.requestId = data.request_id;
    this.passportId = data.passport_id;
    this.agentId = data.agent_id;
    this.action = data.action;
    this.target = data.target;
    this.decision = data.decision;
    this.reasonCode = data.reason_code;
    this.createdAt = data.created_at;
    this.gateId = data.gate_id;
    this.publicKey = data.public_key;
    this.signature = data.signature;
    this._privateKey = privateKey;
  }

  /**
   * Create an attestation from a gate decision.
   */
  static async fromDecision(
    request: GateRequest,
    decision: GateDecision,
    options: {
      gateId?: string;
    } = {}
  ): Promise<Attestation> {
    const { privateKey, publicKey } = await crypto.generateKeypair();

    const attestation = new Attestation(
      {
        uni_version: '2026-01-25',
        attestation_id: generateAttestationId(),
        request_id: request.requestId,
        passport_id: decision.passportId ?? null,
        agent_id: decision.agentId ?? null,
        action: request.action,
        target: request.target,
        decision: decision.decision,
        reason_code: decision.reasonCode ?? null,
        created_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
        gate_id: options.gateId ?? null,
        public_key: crypto.encodeBase64(publicKey),
      },
      privateKey
    );

    await attestation.sign();
    return attestation;
  }

  /**
   * Sign the attestation.
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
   * Verify the attestation signature.
   */
  async verifySignature(): Promise<boolean> {
    if (!this.signature || !this.publicKey) {
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
   * Convert to plain object.
   */
  toDict(): AttestationData {
    return {
      uni_version: this.uniVersion,
      attestation_id: this.attestationId,
      request_id: this.requestId,
      passport_id: this.passportId,
      agent_id: this.agentId,
      action: this.action,
      target: this.target,
      decision: this.decision,
      reason_code: this.reasonCode,
      created_at: this.createdAt,
      gate_id: this.gateId,
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
  static fromDict(data: AttestationData): Attestation {
    return new Attestation(data);
  }

  /**
   * Create from JSON string.
   */
  static fromJson(json: string): Attestation {
    return Attestation.fromDict(JSON.parse(json));
  }
}
