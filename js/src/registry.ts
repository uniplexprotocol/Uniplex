/**
 * Uniplex Trust Registry - Issuer verification and trust resolution.
 *
 * A Trust Registry provides:
 * - Issuer lookup (public keys, metadata)
 * - Revocation checking
 * - Trust tier verification
 */

// ============================================================================
// Types
// ============================================================================

export enum TrustTier {
  SELF = 'self',
  ENTERPRISE = 'enterprise',
  VERIFIED = 'verified',
  CERTIFIED = 'certified',
}

export interface IssuerInfo {
  issuerId: string;
  name?: string;
  trustTier: TrustTier;
  publicKeys: string[];
  createdAt?: string;
  verifiedAt?: string;
  metadata?: Record<string, unknown>;
  revoked: boolean;
  revokedAt?: string;
  revocationReason?: string;
}

// ============================================================================
// TrustRegistry Interface
// ============================================================================

export interface TrustRegistry {
  getIssuer(issuerId: string): IssuerInfo | undefined;
  isIssuerTrusted(issuerId: string, minTier?: TrustTier): boolean;
  isRevoked(issuerId: string): boolean;
  getPublicKeys(issuerId: string): string[];
}

// ============================================================================
// MemoryRegistry Class
// ============================================================================

export class MemoryRegistry implements TrustRegistry {
  private issuers: Map<string, IssuerInfo> = new Map();

  /**
   * Register an issuer.
   */
  registerIssuer(issuer: IssuerInfo): void {
    this.issuers.set(issuer.issuerId, issuer);
  }

  /**
   * Remove an issuer.
   */
  removeIssuer(issuerId: string): void {
    this.issuers.delete(issuerId);
  }

  /**
   * Revoke an issuer.
   */
  revokeIssuer(issuerId: string, reason = 'Revoked'): boolean {
    const issuer = this.issuers.get(issuerId);
    if (issuer) {
      issuer.revoked = true;
      issuer.revokedAt = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
      issuer.revocationReason = reason;
      return true;
    }
    return false;
  }

  /**
   * Get an issuer by ID.
   */
  getIssuer(issuerId: string): IssuerInfo | undefined {
    return this.issuers.get(issuerId);
  }

  /**
   * Check if an issuer is trusted.
   */
  isIssuerTrusted(issuerId: string, minTier: TrustTier = TrustTier.VERIFIED): boolean {
    const issuer = this.getIssuer(issuerId);
    if (!issuer) {
      return false;
    }
    if (issuer.revoked) {
      return false;
    }

    const tierOrder: Record<TrustTier, number> = {
      [TrustTier.SELF]: 0,
      [TrustTier.ENTERPRISE]: 1,
      [TrustTier.VERIFIED]: 2,
      [TrustTier.CERTIFIED]: 3,
    };

    return tierOrder[issuer.trustTier] >= tierOrder[minTier];
  }

  /**
   * Check if an issuer is revoked.
   */
  isRevoked(issuerId: string): boolean {
    const issuer = this.getIssuer(issuerId);
    return issuer?.revoked ?? false;
  }

  /**
   * Get public keys for an issuer.
   */
  getPublicKeys(issuerId: string): string[] {
    const issuer = this.getIssuer(issuerId);
    return issuer?.publicKeys ?? [];
  }

  /**
   * List all issuers.
   */
  listIssuers(): IssuerInfo[] {
    return Array.from(this.issuers.values());
  }
}

// ============================================================================
// TrustResolver Class
// ============================================================================

export class TrustResolver {
  private registries: TrustRegistry[] = [];

  constructor(registries?: TrustRegistry[]) {
    this.registries = registries ?? [];
  }

  /**
   * Add a registry to the resolver.
   */
  addRegistry(registry: TrustRegistry): void {
    this.registries.push(registry);
  }

  /**
   * Resolve an issuer across all registries.
   */
  resolveIssuer(issuerId: string): IssuerInfo | undefined {
    for (const registry of this.registries) {
      const issuer = registry.getIssuer(issuerId);
      if (issuer) {
        return issuer;
      }
    }
    return undefined;
  }

  /**
   * Check if an issuer is trusted.
   */
  isTrusted(
    issuerId: string,
    minTier: TrustTier = TrustTier.VERIFIED,
    allowSelfIssued = false
  ): boolean {
    if (allowSelfIssued && minTier === TrustTier.SELF) {
      return true;
    }

    for (const registry of this.registries) {
      if (registry.isIssuerTrusted(issuerId, minTier)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if an issuer is revoked in any registry.
   */
  checkRevocation(issuerId: string): boolean {
    for (const registry of this.registries) {
      if (registry.isRevoked(issuerId)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Get all public keys for an issuer across registries.
   */
  getPublicKeys(issuerId: string): string[] {
    const keys: Set<string> = new Set();
    for (const registry of this.registries) {
      for (const key of registry.getPublicKeys(issuerId)) {
        keys.add(key);
      }
    }
    return Array.from(keys);
  }
}

// ============================================================================
// Default Resolver
// ============================================================================

let defaultResolver: TrustResolver | undefined;

export function getDefaultResolver(): TrustResolver {
  if (!defaultResolver) {
    defaultResolver = new TrustResolver();
  }
  return defaultResolver;
}

export function setDefaultResolver(resolver: TrustResolver): void {
  defaultResolver = resolver;
}
