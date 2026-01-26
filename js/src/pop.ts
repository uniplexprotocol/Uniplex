/**
 * Uniplex Proof of Possession (PoP) - Binding requests to passport holders.
 *
 * PoP proves that the entity making a request actually controls the private key
 * associated with the passport. This prevents replay attacks and credential theft.
 *
 * Required for L2+ trust profiles.
 */

import * as crypto from './crypto.js';

// ============================================================================
// Types
// ============================================================================

export interface PoPPayloadData {
  jti: string;
  iat: string;
  passport_id: string;
  aud: string;
  session_nonce?: string;
}

export interface ProofOfPossessionData {
  payload: PoPPayloadData;
  signature?: string;
  public_key?: string;
}

// ============================================================================
// Helper Functions
// ============================================================================

function generatePopId(): string {
  const chars = 'abcdef0123456789';
  let id = 'pop_';
  for (let i = 0; i < 16; i++) {
    id += chars[Math.floor(Math.random() * chars.length)];
  }
  return id;
}

// ============================================================================
// ProofOfPossession Class
// ============================================================================

export class ProofOfPossession {
  readonly payload: PoPPayloadData;
  signature?: string;
  publicKey?: string;

  constructor(data: ProofOfPossessionData) {
    this.payload = data.payload;
    this.signature = data.signature;
    this.publicKey = data.public_key;
  }

  /**
   * Create a new Proof of Possession.
   */
  static async create(
    passportId: string,
    audience: string,
    privateKey: Uint8Array,
    options: {
      sessionNonce?: string;
    } = {}
  ): Promise<ProofOfPossession> {
    const publicKey = await getPublicKeyFromPrivate(privateKey);

    const payload: PoPPayloadData = {
      jti: generatePopId(),
      iat: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      passport_id: passportId,
      aud: audience,
      session_nonce: options.sessionNonce,
    };

    const pop = new ProofOfPossession({ payload });
    pop.publicKey = crypto.encodeBase64(publicKey);

    // Sign
    const message = crypto.objectToBytes(payload);
    const sig = await crypto.sign(privateKey, message);
    pop.signature = crypto.encodeBase64(sig);

    return pop;
  }

  /**
   * Verify the PoP signature.
   */
  async verify(expectedPublicKey?: string): Promise<boolean> {
    if (!this.signature || !this.publicKey) {
      return false;
    }

    if (expectedPublicKey && this.publicKey !== expectedPublicKey) {
      return false;
    }

    try {
      const publicKeyBytes = crypto.decodeBase64(this.publicKey);
      const signatureBytes = crypto.decodeBase64(this.signature);
      const message = crypto.objectToBytes(this.payload);

      return await crypto.verify(publicKeyBytes, signatureBytes, message);
    } catch {
      return false;
    }
  }

  /**
   * Verify the audience matches.
   */
  verifyAudience(expectedAudience: string): boolean {
    return this.payload.aud === expectedAudience;
  }

  /**
   * Check if the PoP has expired.
   */
  isExpired(maxAgeSeconds = 300): boolean {
    try {
      const iat = new Date(this.payload.iat);
      const age = (Date.now() - iat.getTime()) / 1000;
      return age > maxAgeSeconds;
    } catch {
      return true;
    }
  }

  /**
   * Convert to plain object.
   */
  toDict(): ProofOfPossessionData {
    const data: ProofOfPossessionData = {
      payload: { ...this.payload },
      signature: this.signature,
      public_key: this.publicKey,
    };
    // Remove undefined session_nonce
    if (!data.payload.session_nonce) {
      delete data.payload.session_nonce;
    }
    return data;
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
  static fromDict(data: ProofOfPossessionData): ProofOfPossession {
    return new ProofOfPossession(data);
  }

  /**
   * Create from JSON string.
   */
  static fromJson(json: string): ProofOfPossession {
    return ProofOfPossession.fromDict(JSON.parse(json));
  }
}

// ============================================================================
// PoPVerifier Class
// ============================================================================

export class PoPVerifier {
  readonly maxAgeSeconds: number;
  readonly requireSessionNonce: boolean;
  private usedNonces: Set<string> = new Set();

  constructor(options: { maxAgeSeconds?: number; requireSessionNonce?: boolean } = {}) {
    this.maxAgeSeconds = options.maxAgeSeconds ?? 300;
    this.requireSessionNonce = options.requireSessionNonce ?? false;
  }

  /**
   * Verify a Proof of Possession.
   */
  async verify(
    pop: ProofOfPossession,
    expectedPassportId: string,
    expectedAudience: string,
    expectedPublicKey: string,
    expectedSessionNonce?: string
  ): Promise<{ valid: boolean; error?: string }> {
    // 1. Verify signature
    const validSig = await pop.verify(expectedPublicKey);
    if (!validSig) {
      return { valid: false, error: 'POP_INVALID_SIGNATURE' };
    }

    // 2. Check passport ID matches
    if (pop.payload.passport_id !== expectedPassportId) {
      return { valid: false, error: 'POP_PASSPORT_MISMATCH' };
    }

    // 3. Check audience
    if (!pop.verifyAudience(expectedAudience)) {
      return { valid: false, error: 'POP_AUD_MISMATCH' };
    }

    // 4. Check expiration
    if (pop.isExpired(this.maxAgeSeconds)) {
      return { valid: false, error: 'POP_EXPIRED' };
    }

    // 5. Check replay (nonce reuse)
    if (this.usedNonces.has(pop.payload.jti)) {
      return { valid: false, error: 'POP_REPLAY_DETECTED' };
    }

    // 6. Check session nonce if required
    if (this.requireSessionNonce) {
      if (!pop.payload.session_nonce) {
        return { valid: false, error: 'POP_SESSION_NONCE_MISSING' };
      }
      if (expectedSessionNonce && pop.payload.session_nonce !== expectedSessionNonce) {
        return { valid: false, error: 'POP_SESSION_NONCE_MISMATCH' };
      }
    }

    // Mark nonce as used
    this.usedNonces.add(pop.payload.jti);

    return { valid: true };
  }

  /**
   * Clear used nonces.
   */
  clearNonces(): void {
    this.usedNonces.clear();
  }
}

// ============================================================================
// Helper to get public key from private key
// ============================================================================

async function getPublicKeyFromPrivate(privateKey: Uint8Array): Promise<Uint8Array> {
  const { getPublicKeyAsync } = await import('@noble/ed25519');
  return getPublicKeyAsync(privateKey);
}
