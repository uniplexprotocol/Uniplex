/**
 * Uniplex Cryptographic Utilities
 *
 * Ed25519 signing, canonical JSON, and base64 encoding.
 */

import * as ed from '@noble/ed25519';

// Use synchronous methods if available in Node.js environment
if (typeof globalThis.crypto === 'undefined') {
  // @ts-ignore - Node.js crypto shim for @noble/ed25519
  import('crypto').then((crypto) => {
    // @ts-ignore
    ed.etc.sha512Sync = (...m: Uint8Array[]) =>
      new Uint8Array(crypto.createHash('sha512').update(Buffer.concat(m)).digest());
  });
}

/**
 * Generate an Ed25519 keypair.
 */
export async function generateKeypair(): Promise<{
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}> {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

/**
 * Sign a message with an Ed25519 private key.
 */
export async function sign(
  privateKey: Uint8Array,
  message: Uint8Array
): Promise<Uint8Array> {
  return await ed.signAsync(message, privateKey);
}

/**
 * Verify an Ed25519 signature.
 */
export async function verify(
  publicKey: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array
): Promise<boolean> {
  try {
    return await ed.verifyAsync(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Convert object to canonical JSON (sorted keys, no whitespace).
 */
export function canonicalJson(obj: unknown): string {
  return JSON.stringify(obj, (_, value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return Object.keys(value)
        .sort()
        .reduce((sorted: Record<string, unknown>, key) => {
          sorted[key] = value[key];
          return sorted;
        }, {});
    }
    return value;
  });
}

/**
 * Encode bytes to base64url (no padding).
 */
export function encodeBase64(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decode base64url to bytes.
 */
export function decodeBase64(str: string): Uint8Array {
  // Add padding if needed
  const padded = str + '==='.slice(0, (4 - (str.length % 4)) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  return new Uint8Array([...binary].map((c) => c.charCodeAt(0)));
}

/**
 * Convert a canonical JSON object to bytes for signing.
 */
export function objectToBytes(obj: unknown): Uint8Array {
  const json = canonicalJson(obj);
  return new TextEncoder().encode(json);
}
