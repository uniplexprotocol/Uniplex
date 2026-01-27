# Uniplex Specification

**Protocol:** Uniplex — The Trust Layer for AI Agents
**Specification Version:** 2026.01.25
**Status:** Initial Release

---

> **Uniplex gives agents portable, signed credentials and gives tools deterministic authorization decisions you can audit — starting lightweight in dev and scaling to production-grade controls.**

---

## What Uniplex Does

```
┌─────────────────────────────────────────────────────────────────┐
│                     UNIPLEX IN 30 SECONDS                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   BEFORE UNIPLEX:                                               │
│   Agent ──► Tool                                                │
│        ↑                                                        │
│        No identity. No authorization. No audit.                 │
│                                                                 │
│   AFTER UNIPLEX:                                                │
│   Agent ──► Uni-Gate ──► Tool                                   │
│        ↑         ↑          ↑                                   │
│     Passport  Decision   Attestation                            │
│     (who)     (allowed?) (proof)                                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Uniplex is Additive (Not a Replacement)

**You keep your existing infrastructure. Uniplex plugs in.**

```
┌─────────────────────────────────────────────────────────────────┐
│                  YOUR EXISTING STACK                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
│  │  Okta/   │  │  SPIFFE/ │  │   OPA/   │  │   MCP    │         │
│  │ Azure AD │  │  SPIRE   │  │  Cedar   │  │          │         │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘         │
│       │             │             │             │               │
│       └─────────────┴──────┬──────┴─────────────┘               │
│                            │                                    │
│                            ▼                                    │
│                    ┌──────────────┐                             │
│                    │   Uni-Gate   │  ◄── Uniplex adds this      │
│                    └──────────────┘                             │
│                            │                                    │
│                            ▼                                    │
│                    Decision + Attestation                       │
│                    (portable proof)                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2026-01-25 | January 25, 2026 | Initial public release |

---

## Terminology Note

**"Uni-" prefix:** Throughout this document, "Uni-" (e.g., Uni-Passport, Uni-Gate) is informal shorthand for readability. All normative terms use "Uniplex" as the formal protocol name. Implementations SHOULD use the full term in logs and error messages.

**Normative keywords:** The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14](https://datatracker.ietf.org/doc/html/bcp14) [[RFC2119](https://datatracker.ietf.org/doc/html/rfc2119)] [[RFC8174](https://datatracker.ietf.org/doc/html/rfc8174)] when, and only when, they appear in all capitals, as shown here.

---

## Compatibility Matrix

| System | Integration Type | What It Does | What Uniplex Adds | Profile |
|--------|------------------|--------------|-------------------|---------|
| **OAuth/OIDC** | Token exchange | Human authentication | Agent authorization + portable proof | Uni-Enterprise |
| **SPIFFE/SPIRE** | Identity binding | Workload identity | Agent permissions + action gating | Uni-Workload |
| **OPA/Cedar** | Policy engine | Policy evaluation | Standardized I/O + attestations | Any |
| **MCP** | Tool authorization | Tool invocation | Trust layer for tool calls | Uni-MCP |
| **W3C VC** | Credential envelope | Verifiable credentials | Agent-specific semantics + runtime gating | Optional (Extension) |
| **SAML** | Token exchange | Enterprise SSO | Agent authorization | Uni-Enterprise |
| **Kubernetes RBAC** | Policy backend | K8s authorization | Cross-cluster agent trust | Uni-Workload |
| **Blockchain** | On-chain attestations | Stake-backed trust | Format agility for on-chain proofs | Optional (Extension) |

**W3C Verifiable Credentials:** A Uni-Passport can be carried inside a W3C VC envelope (the passport becomes the VC `credentialSubject`). Uniplex defines agent-specific semantics and runtime gating; the VC provides the cryptographic wrapper. Full mapping specification planned for future version. See the `org.w3c.proof.*` extension namespace for VC envelopes, ZK/selective disclosure, and proof-format agility.

**Blockchain:** Use `org.blockchain.*` extension namespace for on-chain attestations (e.g., stake-backed agent identity).

**The key insight:** Uniplex doesn't replace any of these. It adds a portable trust layer on top.

**Normative:** Trust resolution MAY be local (file-based), self-hosted (your registry), or public (third-party registry). **No single registry is required or privileged.** This is a local policy choice.

---

## Minimum Viable Uniplex (10-Minute Path)

### What You Need

| Component | Required? | Notes |
|-----------|-----------|-------|
| Passport | ✓ | Self-signed is fine for dev |
| Gate | ✓ | Local Gate, no external calls |
| Issuer Policy | ✓ | Either `allow_self_issued: true` OR issuer allowlist |
| Registry | ✗ | Not needed for L1 Baseline |
| PoP | ✗ | Not needed for L1 Baseline |

**⚠️ Self-Issued Warning:** Self-issued passports (`tier: self`) are **DENIED by default** unless your Gate policy explicitly sets `allow_self_issued: true`. This is intentional — it prevents accidental trust of unvetted agents in production.

### Minimal Passport (8 Fields for Self-Issued)

For self-issued passports, you MUST include `identity.public_key` so the Gate can verify the signature without external lookups:

```json
{
  "uni_version": "2026-01-25",
  "passport_id": "pass_001",
  "identity": {
    "agent_id": "my-agent",
    "public_key": {
      "kty": "EC",
      "crv": "P-256",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
    }
  },
  "permissions": [
    { "action": "*", "resources": ["*"] }
  ],
  "provenance": {
    "issuer": { "id": "issuer:self", "tier": "self" },
    "issued_at": "2026-01-23T00:00:00Z",
    "expires_at": "2026-01-30T00:00:00Z"
  },
  "proof": {
    "type": "JWS",
    "sig": "..."
  }
}
```

**⚠️ Wildcard Warning:** The `"action": "*", "resources": ["*"]` permissions above are for dev/test only. Do not ship wildcard permissions to production; use L2/L3 with scoped resources and actions.

**Signature Verification for Self-Issued (Normative):** For self-issued passports, a Gate MUST verify the signature using EITHER:
- **(a)** The embedded `identity.public_key` in the passport, OR
- **(b)** A `proof.kid` that resolves via the Gate's local trust store

If neither is available, the Gate MUST deny with `issuer_untrusted`.

### Minimal Gate Policy (L1 Baseline)

```yaml
profile: L1
trust_policy:
  allow_self_issued: true  # Required for self-signed passports
```

### L1 Baseline Checks

```
1. Verify passport signature         (embedded public_key or local trust store)
2. Check passport not expired        (timestamp comparison)
3. Apply issuer policy               (allow_self_issued OR issuer in allowlist)
4. Check permission exists           (action matches permissions[])
5. Return allow/deny
```

**No registry. No PoP. No canonical JSON. No nonce.**

### 5-Minute Setup (Reference Tooling)

The following CLI commands are **reference tooling examples** — not normative protocol requirements. Implementations MAY provide different interfaces:

```bash
# Install (reference implementation)
pip install uniplex

# Generate self-signed passport (includes public_key automatically)
uniplex init --self-signed --agent-id "my-agent" --permissions "*"

# Start local Gate (allow_self_issued enabled by default for L1)
uniplex gate --profile L1 --port 8080

# Test (note: includes all required L1 fields)
curl -X POST http://localhost:8080/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "uni_version": "2026-01-25",
    "request_id": "req_test_001",
    "passport": { "...passport contents..." },
    "action": "test",
    "issued_at": "2026-01-23T14:30:00Z"
  }'
```

### 5-Line Integration (Reference Implementation)

```python
from uniplex import Agent

agent = Agent.from_env()  # Reads UNIPLEX_PASSPORT from environment
result = agent.call("mcp://tools.example.com", "search", {"query": "weather"})
print(result)
```

**That's Minimum Viable Uniplex.** Everything else (L2 Standard, L3 Strict, registries, PoP) is opt-in when you need it.

---

## Data Format Conventions

### Timestamps (Normative)

All timestamps in Uniplex MUST use **ISO 8601 format** with timezone designator:

```
Format: YYYY-MM-DDTHH:MM:SSZ
Example: "2026-01-23T14:30:00Z"
```

This applies to:
- Passport fields (`issued_at`, `expires_at`)
- Request fields (`issued_at`)
- Decision fields (`decision_at`)
- Attestation fields (`created_at`)
- Session token fields (`iat`, `exp`) — note: use ISO strings, not epoch seconds

**Rationale:** ISO 8601 is human-readable, unambiguous, and avoids timezone confusion. Epoch seconds are avoided to maintain consistency across all Uniplex objects.

**Interop Note (JWT/OIDC):** When Uniplex objects are transported inside JWT/JWS envelopes, implementations SHOULD use standard JWT NumericDate claims for `iat`/`exp`, and treat ISO 8601 timestamps as the canonical Uniplex object representation. The canonical Uniplex fields remain ISO 8601 strings as specified here. The reference SDK handles this conversion automatically, so implementers using the SDK need not manage timestamp format translation manually.

### Extension Namespaces (Normative)

Extensions use **reverse-domain namespacing** only:

```
Correct:   org.w3c.proof.*
Correct:   org.blockchain.*
Correct:   com.acme.internal_id
Incorrect: extensions.org.w3c.proof  (do not use)
```

**Security Note:** Gates MUST ignore unknown extension namespaces by default, and MUST NOT treat extension data as authorization-critical unless the namespace is explicitly allowlisted by local policy.

### Reason Codes (Normative)

Reason codes use **lowercase_snake_case** in wire format:

| Reason Code | Algorithm Constant | Meaning |
|-------------|-------------------|---------|
| `passport_valid` | `PASSPORT_VALID` | Signature verified |
| `passport_expired` | `PASSPORT_EXPIRED` | Passport has expired |
| `passport_revoked` | `PASSPORT_REVOKED` | Passport revoked |
| `signature_invalid` | `SIGNATURE_INVALID` | Signature verification failed |
| `issuer_trusted` | `ISSUER_TRUSTED` | Issuer in trust policy |
| `issuer_untrusted` | `ISSUER_UNTRUSTED` | Issuer not in policy |
| `permission_granted` | `PERMISSION_GRANTED` | Permission exists |
| `permission_denied` | `PERMISSION_DENIED` | No permission |
| `constraint_violated` | `CONSTRAINT_VIOLATED` | Constraint failed |
| `nonce_replay` | `NONCE_REPLAY` | Nonce already used |
| `pop_invalid` | `POP_INVALID` | PoP verification failed |
| `revocation_stale` | `REVOCATION_STALE` | Revocation data too stale |
| `session_invalid` | `SESSION_INVALID` | Session token invalid or expired |
| `session_pop_invalid` | `SESSION_POP_INVALID` | Session token PoP failed |
| `session_audience_mismatch` | `SESSION_AUDIENCE_MISMATCH` | Audience does not match target |
| `session_resource_mismatch` | `SESSION_RESOURCE_MISMATCH` | Resource not in scope |
| `target_mismatch` | `TARGET_MISMATCH` | Target does not match |
| `resource_mismatch` | `RESOURCE_MISMATCH` | Resource does not match |

**Implementation Note:** Algorithms in this spec use `UPPER_CASE` constants for readability. Wire format (JSON responses) MUST use `lowercase_snake_case` reason codes.

### Target and Resource Canonicalization (Normative)

For L2 Standard and L3 Strict, targets and resources MUST be canonicalized before comparison:

**Target Canonicalization:**
1. Parse as URI
2. Lowercase the scheme and host
3. Remove default ports (80 for http, 443 for https)
4. Remove trailing slash from path (unless path is "/")
5. Sort query parameters alphabetically
6. Within each URI component, percent-encode characters not in the RFC3986 unreserved set (ALPHA / DIGIT / "-" / "." / "_" / "~"), preserving structural delimiters between components; normalize existing percent-escapes to uppercase hex

**Clarification:** Structural URI delimiters (`:`, `/`, `?`, `#`, `@`, etc.) that separate components are preserved as-is. Only characters *within* a component (path segment, query value, etc.) that fall outside the unreserved set are percent-encoded. This ensures two compliant implementations produce identical canonical forms.

**Resource Canonicalization:**
1. Lowercase the entire string
2. Trim leading/trailing whitespace
3. Collapse multiple colons to single colon
4. Remove trailing colons

**Examples:**
```
Target: "MCP://Tools.Example.COM:443/api/"  → "mcp://tools.example.com/api"
Resource: "DB:Customers "                   → "db:customers"
Resource: "table::users::"                  → "table:users"
```

**Wildcard Semantics:** The `*` wildcard matches any value. Prefix wildcards (e.g., `db:*`) match any resource starting with the prefix.

---

## Table of Contents

**Part 1: Foundation**
1. Design Principles
2. Issuer Trust Model (Open Issuance, Controlled Trust)
3. Uni-Gate Profiles (L1 Baseline / L2 Standard / L3 Strict)
4. Extension Mechanism
5. Profiles Overview

**Part 2: Core Objects**
6. Uni-Passport
7. Uni-Gate Request
8. Uni-Gate Decision
9. Uni-Attestation

**Part 3: Ecosystem Profiles**
10. Uni-MCP Profile
11. Uni-Tooling Profile
12. Uni-Workload Profile
13. Uni-Commerce Profile
14. Uni-Enterprise Profile

**Part 4: Operations**
15. Passport Issuance
16. Trust Resolution
17. Local Trust Store
18. Deployment Modes
19. Policy Engine Integration (OPA/Cedar)
20. Key Lifecycle
21. Revocation & Key Compromise
22. Failure Modes
23. Performance & Caching
24. Batch & Session Authorization
25. Debug Mode

**Part 5: Security**
26. Security Model
27. Delegation & Chain Enforcement
28. Proof of Possession
29. Canonical JSON
30. Trust Evaluation Algorithm

**Part 6: Interoperability**
31. Ecosystem Compatibility
32. Versioning & Evolution
33. Conformance Testing

**Appendices**
- A. Glossary
- B. Quick Reference
- C. Conformance Test Vectors
- D. Compliance Mapping
- E. Extension Namespace Registry
- F. Intellectual Property Notice
- G. Governance Roadmap

---

# Part 1: Foundation

## 1. Design Principles

### 1.1 Core Philosophy

1. **Open Issuance, Controlled Trust**: Anyone can issue a Uni-Passport. Acceptance is controlled by Gate policy. Valid signatures do not imply trust.

2. **Risk-Based Security**: Security scales with risk. Low-risk actions use lightweight checks (L1 Baseline). High-risk actions use full verification (L3 Strict).

3. **Portable Verification**: Verification evidence (Uni-Attestations) travels with the agent, enabling cross-system trust.

4. **Local-First**: Gates can operate without external dependencies. A Local Trust Store is a first-class deployment pattern.

5. **Federated**: No single registry is privileged. A Gate MAY trust multiple registries simultaneously. Registry selection is a local policy choice.

6. **Incremental Adoption**: Start with L1 Baseline in development, upgrade to L2 Standard or L3 Strict as needed.

### 1.2 What Uniplex Is NOT

| Uniplex Is NOT | Why |
|----------------|-----|
| A replacement for OAuth | OAuth handles human auth; Uniplex handles agent authorization |
| A replacement for SPIFFE | SPIFFE provides workload identity; Uniplex provides permissions |
| A new identity system | Uniplex uses existing identities as inputs |
| A centralized authority | Federated trust resolution, local-first operation |
| Required for every action | Risk-based profiles (L1/L2/L3) scale appropriately |

---

## 2. Issuer Trust Model (Open Issuance, Controlled Trust)

### 2.1 The Core Insight

**Anyone can issue a passport. Gates decide what to trust.**

```
┌─────────────────────────────────────────────────────────────────┐
│                     TRUST MODEL                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   "Can I issue a passport?"                                     │
│        │                                                        │
│        ▼                                                        │
│       YES ─── Anyone can issue. It's just a signed document.    │
│                                                                 │
│   "Will my passport be accepted?"                               │
│        │                                                        │
│        ▼                                                        │
│    DEPENDS ─── Gate policy decides. Not you.                    │
│                                                                 │
│   KEY INSIGHT:                                                  │
│   • Signature proves ORIGIN (who signed it)                     │
│   • Policy decides AUTHORIZATION (what's allowed)               │
│   • These are separate concerns — just like standard IAM        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Issuer Tiers

| Tier | Name | Who | Example | Default Gate Behavior |
|------|------|-----|---------|----------------------|
| `self` | Self-Issued | Agent or operator | Dev laptop self-signs | **DENY** unless `allow_self_issued: true` |
| `internal` | Internal | Organization's internal CA | Acme Corp issues for Acme agents | Allow if org is in trust policy |
| `verified` | Verified | Vetted by a registry | Public registry confirmed identity | Allow with standard limits |
| `certified` | Certified | Audited + contractual SLA | Third-party audit + SLA | Allow with elevated limits |

**Visual progression:**
```
Self            Internal           Verified           Certified
────────────────────────────────────────────────────────────────►
Dev laptop  →   Internal CA    →   Registry check  →  Third-party audit
No trust        Org trust          Public trust       Audited trust
```

### 2.3 Issuer Policy (Required for All Profiles)

**Every Gate MUST have an issuer policy.** The policy specifies which issuers are trusted.

**L1 Baseline options:**
```yaml
# Option A: Allow self-issued (for development)
trust_policy:
  allow_self_issued: true

# Option B: Explicit issuer allowlist (for production)
trust_policy:
  allow_self_issued: false
  allowed_issuers:
    - "issuer:my-org"
    - "issuer:partner-corp"
```

**Rule:** If `allow_self_issued` is false and the issuer is not in the allowlist, the Gate MUST deny the request.

### 2.4 How Trust Resolution Works

```
┌─────────────────────────────────────────────────────────────────┐
│                  TRUST RESOLUTION (NO LOCK-IN)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│                      ┌──────────────┐                           │
│                      │   Uni-Gate   │                           │
│                      └──────┬───────┘                           │
│                             │                                   │
│              "Which trust resolver should I use?"               │
│                             │                                   │
│           ┌─────────────────┼─────────────────┐                 │
│           │                 │                 │                 │
│           ▼                 ▼                 ▼                 │
│   ┌───────────────┐ ┌───────────────┐ ┌───────────────┐         │
│   │ Local Trust   │ │ Self-Hosted   │ │   Public      │         │
│   │ Store (file)  │ │ Registry      │ │   Registry    │         │
│   └───────────────┘ └───────────────┘ └───────────────┘         │
│                                                                 │
│   Gate policy chooses which resolver(s) to use.                 │
│   Multiple resolvers can be configured with priority.           │
│   NO SINGLE REGISTRY IS PRIVILEGED.                             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.5 Why This Model is Correct

| Concern | Answer |
|---------|--------|
| "Won't there be fake passports?" | Yes, but Gates won't trust them (issuer policy). |
| "How do I prevent unauthorized agents?" | Gate policy. Only trusted issuers are accepted. |
| "What if someone impersonates my org?" | They can't sign with your keys. Signature verification prevents this. |
| "Do I need a registry?" | No. L1/L2 work with local trust only. |

### 2.6 Open Issuance vs. Trust (Normative)

Any party MAY issue a Uni-Passport. A valid signature only proves who signed; it does not imply that a Gate MUST authorize actions. Authorization decisions MUST be driven by Gate policy, including issuer allow/deny rules, trust tier requirements, and optional trust resolution (local, self-hosted, or public). Implementations MUST treat "cryptographically valid" as a necessary condition, not a sufficient condition, for access.

---

## 3. Uni-Gate Profiles (L1 Baseline / L2 Standard / L3 Strict)

### 3.1 Overview

Uniplex security scales with risk. Not every action needs full verification.

| Profile | Name | Target Use Case | Complexity | Latency |
|---------|------|-----------------|------------|---------|
| **L1** | Baseline | Dev/test, low-risk reads | Minimal | ~5ms typical |
| **L2** | Standard | Production, most actions | Moderate | ~20ms typical |
| **L3** | Strict | Payments, PHI, regulated | Full | ~50ms typical |

**Key rule:** Implementers MUST support L1 Baseline. L2 Standard and L3 Strict are optional profiles.

**Latency concern?** For L2/L3, use **Session Grants** (Part 24): one strict check → session token → many ~1ms calls. Session tokens maintain theft protections per the normative requirements.

### 3.2 L1 Baseline

**The foundation everyone needs.**

**Adoption note (non-normative):** L1 Baseline is designed for dev/test and low-risk reads. It intentionally omits nonce/replay protection and resource scope enforcement; implementers SHOULD use L2 Standard (or L3 Strict) for production security, especially for write operations, multi-tenant deployments, or any action where scoped resources and replay resistance are required.

**Required Checks:**
| Check | Required | Notes |
|-------|----------|-------|
| Passport signature verification | ✓ | Local key or embedded public_key |
| Passport expiration | ✓ | Simple timestamp check |
| Issuer policy | ✓ | `allow_self_issued` OR issuer allowlist |
| Action permission | ✓ | Basic permission match |

**NOT Required:**
- External trust resolution
- Canonical JSON serialization
- PoP binding
- Nonce/replay prevention
- Signed attestations

**Example Policy:**
```yaml
profile: L1  # Baseline
trust_policy:
  allow_self_issued: true  # For development
  # OR for production:
  # allow_self_issued: false
  # allowed_issuers: ["issuer:my-org"]
logging: best-effort
```

**Performance:** ~5ms typical (local operations only)

### 3.3 L2 Standard

**The standard for production.**

**Required Checks:**
| Check | Required | Notes |
|-------|----------|-------|
| All L1 Baseline checks | ✓ | |
| Nonce uniqueness | ✓ | Replay prevention |
| Target matching | ✓ | Canonicalized comparison (see Data Format Conventions) |
| Resource scope | ✓ | Canonicalized comparison |
| Constraint evaluation | ✓ | Rate limits, budgets |

**Optional (Recommended):**
- Trust resolution lookup (cached, stale-while-revalidate)
- Revocation checking (configurable fail behavior)
- Attestation logging

**Example Policy:**
```yaml
profile: L2  # Standard
trust_policy:
  allow_self_issued: false
  allowed_issuers:
    - "issuer:my-org"
    - "issuer:partner-corp"
  trust_resolution:
    enabled: true
    cache_ttl_seconds: 300
revocation:
  enabled: true
  fail_closed: false  # Default: allow + warn if stale (configurable)
replay_prevention:
  enabled: true
  window_seconds: 300
logging: required
```

**Performance:** ~20ms typical (with cached lookups)

### 3.4 L3 Strict

**Strict verification for high-risk actions.**

**Required Checks:**
| Check | Required | Notes |
|-------|----------|-------|
| All L2 Standard checks | ✓ | |
| Canonical JSON serialization | ✓ | Deterministic hashing |
| PoP binding | ✓ | DPoP or equivalent |
| Issuer trust-resolution | ✓ | See options below |
| Signed attestations | ✓ | Non-repudiable audit |
| Policy hash | ✓ | Immutable policy reference |
| Request hash binding | ✓ | Integrity verification |

**Trust-Resolution Options for L3 Strict:**

L3 Strict requires trust-resolution (issuer metadata + revocation checking) for `verified` and `certified` tiers. **L3 requires trust resolution, but NOT any specific vendor.** Options:

- **(a)** Local Trust Store (enterprise allowlist / internal PKI)
- **(b)** Self-hosted registry implementing the Registry Interface
- **(c)** Public or industry registry
- **(d)** Any combination of the above

**No single registry is required or privileged.** This is a local policy choice.

**Latency concern?** Use **Session Grants** (Part 24): one L3 Strict check → session token → subsequent calls at ~1ms. Session tokens maintain theft protections per the normative requirements.

**Performance:** ~50ms typical (real-time checks + crypto)

### 3.5 Profile Selection Guide

| Scenario | Recommended Profile |
|----------|---------------------|
| Local development | L1 Baseline |
| Unit/integration tests | L1 Baseline |
| Internal read-only tools | L1 Baseline or L2 Standard |
| Production SaaS integration | L2 Standard |
| Customer data access | L2 Standard or L3 Strict |
| Financial transactions | L3 Strict |
| Healthcare (PHI/HIPAA) | L3 Strict |
| Payment processing | L3 Strict |

### 3.6 Profile Upgrade Path

```
Development          Production           Regulated
    │                    │                    │
    ▼                    ▼                    ▼
L1 Baseline ────────► L2 Standard ────────► L3 Strict
   
   Same passport, same SDK, different policy.
```

---

## 4. Extension Mechanism

### 4.1 Design Principle

Extensions allow ecosystem-specific fields without bloating Core.

### 4.2 Extension Structure

Extensions use reverse-domain namespacing:

```json
{
  "uni_version": "2026-01-25",
  "passport_id": "pass_abc123",
  "extensions": {
    "org.oauth.dpop": { "jwk_thumbprint": "sha256:..." },
    "org.spiffe.id": "spiffe://cluster.local/ns/prod/sa/agent1",
    "org.w3c.proof": { "type": "BBS+", "selective_disclosure": true },
    "org.blockchain.stake": { "chain": "ethereum", "amount": "1000" },
    "com.acme.internal_id": "agent-42"
  }
}
```

### 4.3 Extension Rules

1. **Core validators MUST safely ignore unknown extensions.**
2. **Extensions MUST NOT override Core field semantics.**
3. **Extensions use reverse-domain namespacing.**

### 4.4 Reserved Extension Namespaces

| Namespace | Purpose | Status |
|-----------|---------|--------|
| `org.w3c.proof.*` | W3C VC proof compatibility (ZK, BBS+, selective disclosure) | Planned |
| `org.blockchain.*` | On-chain attestations, stake-backed identity | Extension |

---

## 5. Profiles Overview

| Profile | Version | Status | Use Case |
|---------|---------|--------|----------|
| Uni-Core | 2026-01-25 | Stable | Foundation |
| Uni-MCP | 0.2 | Stable | MCP tool authorization |
| Uni-Tooling | 0.1 | Draft | LangChain, CrewAI, etc. |
| Uni-Workload | 0.1 | Draft | SPIFFE integration |
| Uni-Commerce | 0.1 | Planned | Payment authorization |
| Uni-Enterprise | 0.2 | Draft | OAuth/OIDC integration |

---

# Part 2: Core Objects

## 6. Uni-Passport

### 6.1 Overview

A Uni-Passport is a signed credential containing:
- **Identity:** Who is this agent?
- **Permissions:** What can it do?
- **Trust Evidence:** Why should we trust it?
- **Provenance:** Who issued it and when?

### 6.2 Schema

```json
{
  "uni_version": "2026-01-25",
  "passport_id": "pass_unique_id",
  
  "identity": {
    "agent_id": "agent_unique_id",
    "deploying_org": "org:acme",
    "model_identity": {
      "architecture_id": "transformer_v4",
      "version": "3.2.1",
      "weights_hash": "sha256:abc123..."
    },
    "public_key": {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    }
  },
  
  "trust": {
    "score": {
      "score": 87,
      "provider": { "id": "scorer:example" },
      "calculated_at": "2026-01-23T00:00:00Z",
      "expires_at": "2026-01-25T00:00:00Z"
    },
    "certifications": [],
    "behavioral_attestations": []
  },
  
  "permissions": [
    {
      "action": "database:query",
      "resources": ["db:customers"],
      "constraints": {
        "max_rows": 1000,
        "rate_limit": "100/hour"
      },
      "expires_at": "2026-01-25T00:00:00Z"
    }
  ],
  
  "provenance": {
    "issuer": {
      "id": "issuer:acme",
      "name": "Acme Corp",
      "tier": "internal"
    },
    "issued_at": "2026-01-23T00:00:00Z",
    "expires_at": "2026-01-30T00:00:00Z",
    "revocation_endpoint": "https://registry.acme.com/revocation"
  },
  
  "proof": {
    "type": "JWS",
    "kid": "issuer:acme#key-1",
    "sig": "BASE64URL..."
  },
  
  "extensions": {}
}
```

### 6.3 Trust Score (Advisory)

**Trust scores are advisory inputs; authorization is determined by Gate policy.**

**Non-normative clarity:** Uniplex does not define or require any global reputation network. A `trust.score` MAY be absent, MAY be computed locally, and MAY come from multiple independent providers; no provider is privileged by the protocol. Implementations MUST NOT treat a score (or any single scoring provider) as sufficient for authorization without additional checks (signature validity, issuer policy, permissions, and—where applicable—resource binding and theft protection).

A Gate MAY use `trust.score` as one input to its policy, but the score alone does not grant or deny access. Example policy usage:

```yaml
# Score as one factor among many
constraints:
  min_trust_score: 80  # Advisory threshold
  # But also requires: valid signature, issuer in allowlist, permission match
```

### 6.4 Required Fields

| Field | Type | L1 | L2 | L3 |
|-------|------|----|----|-----|
| `uni_version` | string | ✓ | ✓ | ✓ |
| `passport_id` | string | ✓ | ✓ | ✓ |
| `identity.agent_id` | string | ✓ | ✓ | ✓ |
| `provenance.issuer` | object | ✓ | ✓ | ✓ |
| `provenance.issued_at` | timestamp | ✓ | ✓ | ✓ |
| `provenance.expires_at` | timestamp | ✓ | ✓ | ✓ |
| `proof` | object | ✓ | ✓ | ✓ |
| `provenance.issuer.tier` | string | | ✓ | ✓ |
| `identity.public_key` | object | ✓* | ✓* | ✓ |

**Note:** For L1/L2 self-issued passports, `identity.public_key` is required for signature verification. For non-self-issued passports, `proof.kid` resolves via trust resolution.

### 6.5 Self-Issuance Boundary

**Self-issued passports (`tier: self`) MUST NOT be trusted outside the issuing boundary unless explicitly allowed by Gate policy (`allow_self_issued: true`).**

---

## 7. Uni-Gate Request

### 7.1 Schema

```json
{
  "uni_version": "2026-01-25",
  "request_id": "req_unique_id",
  "passport": { },
  "action": "database:query",
  "parameters": {
    "query": "SELECT * FROM users"
  },
  "target": "mcp://tools.acme.com",
  "resource": "db:users",
  "issued_at": "2026-01-23T14:30:00Z",
  "nonce": "n_abc123",
  "pop": { },
  "extensions": { }
}
```

### 7.2 Required Fields by Profile

| Field | L1 | L2 | L3 |
|-------|----|----|-----|
| `uni_version` | ✓ | ✓ | ✓ |
| `request_id` | ✓ | ✓ | ✓ |
| `passport` | ✓ | ✓ | ✓ |
| `action` | ✓ | ✓ | ✓ |
| `issued_at` | ✓ | ✓ | ✓ |
| `target` | | ✓ | ✓ |
| `resource` | | ✓ | ✓ |
| `nonce` | | ✓ | ✓ |
| `pop` | | | ✓ |

### 7.3 Audience vs. Target

**Important:** `target` is request-scoped, not credential-scoped. A single passport can make requests to multiple targets.

---

## 8. Uni-Gate Decision

### 8.1 Schema

```json
{
  "uni_version": "2026-01-25",
  "request_id": "req_unique_id",
  "decision": "allow",
  "reason_codes": ["passport_valid", "permission_granted"],
  "obligations": ["log_action"],
  "decision_at": "2026-01-23T14:30:01Z",
  "gate": {
    "id": "gate:acme-prod",
    "version": "1.0",
    "profile": "L2"
  },
  "proof": { }
}
```

### 8.2 Decision Values

| Decision | Description |
|----------|-------------|
| `allow` | Action permitted |
| `deny` | Action not permitted |

### 8.3 Standard Reason Codes

| Code | Meaning |
|------|---------|
| `passport_valid` | Signature verified |
| `passport_expired` | Passport has expired |
| `passport_revoked` | Passport revoked |
| `issuer_trusted` | Issuer in trust policy |
| `issuer_untrusted` | Issuer not in policy and `allow_self_issued` is false |
| `permission_granted` | Permission exists |
| `permission_denied` | No permission |
| `constraint_violated` | Constraint failed |
| `nonce_replay` | Nonce already used |
| `pop_invalid` | PoP verification failed |
| `revocation_stale` | Revocation data too stale (fail_closed mode) |
| `session_invalid` | Session token invalid or expired |
| `session_pop_invalid` | Session token PoP verification failed |
| `session_audience_mismatch` | Session token audience does not match target |
| `session_resource_mismatch` | Session token resource scope does not include requested resource |

---

## 9. Uni-Attestation

### 9.1 Overview

A Uni-Attestation is portable proof that a verification occurred.

### 9.2 Schema

```json
{
  "uni_version": "2026-01-25",
  "attestation_id": "att_unique_id",
  "request_id": "req_unique_id",
  "passport_id": "pass_unique_id",
  "decision": "allow",
  "checks_performed": [
    { "check": "signature", "result": "pass" },
    { "check": "issuer_policy", "result": "pass" },
    { "check": "permission", "result": "pass" }
  ],
  "profile": "L2",
  "policy_hash": "sha256:...",
  "request_hash": "sha256:...",
  "gate": {
    "id": "gate:acme",
    "version": "1.0"
  },
  "created_at": "2026-01-23T14:30:01Z",
  "proof": { }
}
```

### 9.3 Attestation by Profile

| Field | L1 | L2 | L3 |
|-------|----|----|-----|
| `attestation_id` | ✓ | ✓ | ✓ |
| `request_id` | ✓ | ✓ | ✓ |
| `decision` | ✓ | ✓ | ✓ |
| `checks_performed` | | ✓ | ✓ |
| `policy_hash` | | | ✓ |
| `request_hash` | | | ✓ |
| `proof` (signed) | | | ✓ |

---

# Part 3: Ecosystem Profiles

## 10. Uni-MCP Profile (v0.2)

**Tagline:** "MCP is the plumbing. Uniplex is the trust."

### 10.1 Field Mapping

| MCP Concept | Uniplex Field |
|-------------|---------------|
| Tool name | `action` |
| Tool arguments | `parameters` |
| MCP server ID | `target` |
| MCP session | `extensions["org.modelcontextprotocol.session"]` |

### 10.2 MCP Quickstart

```bash
pip install uniplex
uniplex init --self-signed --permissions "mcp:*"
uniplex wrap ./my-mcp-server.py --profile L2 --output ./secured-server.py
python ./secured-server.py
```

---

## 11. Uni-Tooling Profile (v0.1)

Integration with agent frameworks: LangChain, CrewAI, AutoGPT, etc.

| Extension | Purpose |
|-----------|---------|
| `ai.uniplex.tooling.framework` | Framework identifier |
| `ai.uniplex.tooling.workflow_id` | Workflow correlation |
| `ai.uniplex.tooling.step` | Current step number |

---

## 12. Uni-Workload Profile (v0.1)

SPIFFE/SPIRE integration for workload identity binding.

| Extension | Purpose |
|-----------|---------|
| `org.spiffe.id` | SPIFFE ID |
| `org.spiffe.svid_ref` | SVID reference |

---

## 13. Uni-Commerce Profile (v0.1)

Payment and financial transaction authorization.

| Extension | Purpose |
|-----------|---------|
| `ai.uniplex.commerce.merchant_id` | Payment recipient |
| `ai.uniplex.commerce.amount` | Transaction amount |
| `ai.uniplex.commerce.currency` | Currency code |

**Requirement:** Uni-Commerce MUST use L3 Strict profile.

---

## 14. Uni-Enterprise Profile (v0.2)

OAuth/OIDC integration for enterprise environments.

### 14.1 Field Mapping (Canonical Paths)

| OAuth/OIDC Claim | Uniplex Passport Path |
|------------------|----------------------|
| `iss` | `provenance.issuer.id` |
| `sub` | `identity.agent_id` |
| `scope` (parsed) | `permissions[].action` |
| `exp` | `provenance.expires_at` |
| `iat` | `provenance.issued_at` |
| `jti` | `passport_id` |

**Note:** OAuth `aud` maps to `request.target`, NOT to a passport field.

---

# Part 4: Operations

## 15. Passport Issuance

### 15.1 Issuance Methods

| Method | Use Case | Tier |
|--------|----------|------|
| Self-issuance | Development, testing | `self` |
| CLI tool | Quick start | `self` |
| Organization issuer | Internal agents | `internal` |
| Registry issuer | Cross-org trust | `verified`/`certified` |

### 15.2 Self-Issuance (Development)

```bash
uniplex init --self-signed \
  --agent-id "my-agent" \
  --permissions "tools:*" \
  --expires "7d" \
  --output ./passport.json
```

### 15.3 Issuance Requirements by Tier

| Tier | Requirements |
|------|--------------|
| `self` | None (CLI generates) |
| `internal` | Organization admin approval |
| `verified` | Registry application + verification |
| `certified` | Audit + contractual agreement |

---

## 16. Trust Resolution

### 16.1 Overview

Trust resolution provides:
- Issuer lookup (public keys, metadata)
- Revocation checking
- Trust score queries

### 16.2 When Required

| Profile | Trust Resolution Required? |
|---------|---------------------------|
| L1 Baseline | No |
| L2 Standard | Optional (recommended) |
| L3 Strict | Yes (but NOT any specific vendor) |

**Normative:** Trust resolution MAY be local (file-based), self-hosted (your registry), or public (third-party registry). No single registry is required or privileged.

### 16.3 Federated Trust Resolution

**A Gate MAY trust multiple registries simultaneously.** No single registry is privileged.

```yaml
trust_resolution:
  sources:
    - id: "local"
      type: "local_trust_store"
      path: "/etc/uniplex/trusted-issuers.json"
      priority: 1
    - id: "internal"
      type: "registry"
      url: "https://registry.internal.acme.com"
      priority: 2
    - id: "public"
      type: "registry"
      url: "https://registry.example.org"
      priority: 3
```

---

## 17. Local Trust Store

### 17.1 Overview

A Local Trust Store is a first-class deployment pattern for:
- Air-gapped environments
- Low-latency requirements
- Full control over trusted issuers

### 17.2 File Format

```json
{
  "version": "1.0",
  "updated_at": "2026-01-23T00:00:00Z",
  "issuers": [
    {
      "id": "issuer:acme",
      "name": "Acme Corp",
      "tier": "internal",
      "status": "active",
      "public_keys": [...]
    }
  ],
  "revocations": [
    {
      "passport_id": "pass_revoked_001",
      "revoked_at": "2026-01-15T00:00:00Z",
      "reason": "key_compromise"
    }
  ]
}
```

---

## 18. Deployment Modes

### 18.1 Common Deployment Patterns

| Mode | Profile | Issuer | Trust Resolution | Use Case |
|------|---------|--------|------------------|----------|
| **Solo Dev** | L1 Baseline | Self-issued | None | Developer laptop, testing |
| **Organization Internal** | L2/L3 | Internal | Local Trust Store / Internal PKI | Internal agents, no external deps |
| **Cross-Org / Marketplace** | L3 Strict | Verified/Certified | Federated (multiple registries) | Partner integrations, public agents |

### 18.2 Solo Dev Mode

**Simplest possible setup.**

```bash
# Generate self-signed passport
uniplex init --self-signed --permissions "*"

# Start local Gate
uniplex gate --profile L1 --port 8080

# Done. No registry, no external calls.
```

**Policy:**
```yaml
profile: L1
trust_policy:
  allow_self_issued: true
```

### 18.3 Organization Internal Mode

**Production-ready without external dependencies.**

```yaml
profile: L2  # or L3
trust_policy:
  allow_self_issued: false
  allowed_issuers:
    - "issuer:acme-internal"
  trust_resolution:
    local_trust_store:
      enabled: true
      path: "/etc/uniplex/trusted-issuers.json"
revocation:
  fail_closed: true  # Strict enterprise setting
```

### 18.4 Cross-Org / Marketplace Mode

**Federated trust for multi-party ecosystems.**

```yaml
profile: L3
trust_policy:
  allow_self_issued: false
  require_tier: verified
  trust_resolution:
    sources:
      - id: "internal"
        type: "registry"
        url: "https://registry.internal.acme.com"
        priority: 1
      - id: "fintech-alliance"
        type: "registry"
        url: "https://registry.fintech-alliance.org"
        priority: 2
revocation:
  max_staleness_seconds: 60
  fail_closed: true
```

---

## 19. Policy Engine Integration (OPA/Cedar)

### 19.1 Overview

**The policy engine sits inside the Gate; Uniplex standardizes the I/O and evidence.**

```
┌─────────────────────────────────────────────────────────────────┐
│                  Uni-Gate                                       │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐                 │
│  │ Signature  │  │  Policy    │  │ Attestation│                 │
│  │ Validation │──│  Engine    │──│ Generation │                 │
│  │ (Uniplex)  │  │(OPA/Cedar) │  │ (Uniplex)  │                 │
│  └────────────┘  └────────────┘  └────────────┘                 │
└─────────────────────────────────────────────────────────────────┘
```

### 19.2 Responsibility Split

| Component | Uniplex | Policy Engine |
|-----------|---------|---------------|
| Passport signature | ✓ | |
| Issuer policy | ✓ | |
| PoP verification | ✓ | |
| Permission matching | | ✓ |
| Constraint evaluation | | ✓ |
| Business rules | | ✓ |
| Attestation generation | ✓ | |

---

## 20. Key Lifecycle

### 20.1 Key Validity Windows

```json
{
  "kid": "issuer:acme#key-2",
  "valid_from": "2026-01-01T00:00:00Z",
  "valid_until": "2027-01-01T00:00:00Z"
}
```

### 20.2 Rotation Rules

1. **Overlap period:** New key SHOULD be valid 30+ days before old key expires.
2. **Signature validation:** Accept signatures from any key valid at `provenance.issued_at`.

---

## 21. Revocation & Key Compromise

### 21.1 Revocation Checklist

When a passport needs to be revoked:

```
□ 1. Add passport_id to revocation list
□ 2. Publish to all trust resolution sources
□ 3. Set cache TTL to force refresh
□ 4. Log revocation event with reason
□ 5. Notify dependent systems (optional)
```

### 21.2 Key Compromise Checklist

When an issuer key is compromised:

```
□ 1. Mark key as REVOKED (not just expired)
□ 2. Revoke ALL passports signed with that key
□ 3. Publish updated key list to trust resolution
□ 4. Generate new key pair
□ 5. Re-issue passports with new key
□ 6. Audit: identify all actions taken with compromised passports
□ 7. Notify affected parties
```

### 21.3 Selective Revocation (L3 Only)

For L3 Strict, Gates MAY support **selective revocation** — revoking specific permissions rather than the entire passport:

```json
{
  "passport_id": "pass_abc123",
  "selective_revocation": {
    "revoked_actions": ["database:delete"],
    "revoked_at": "2026-01-23T14:30:00Z",
    "reason": "scope_reduction"
  }
}
```

This allows agents to continue operating with reduced permissions after a partial breach.

### 21.4 Revocation Freshness (L2/L3)

**Configurable revocation behavior:**

```yaml
revocation:
  enabled: true
  max_staleness_seconds: 60   # L3 default; L2 default is 300
  fail_closed: false          # L2 default; L3 default is true
```

**Profile defaults:**

| Profile | `fail_closed` Default | `max_staleness` Default | Behavior When Stale |
|---------|----------------------|------------------------|---------------------|
| L1 | N/A | N/A | No revocation check |
| L2 | `false` | 300s | Allow + warn |
| L3 | `true` | 60s | Deny |

**Overriding defaults:** A Gate MAY set `fail_closed: true` at L2 for stricter security. This is a local policy choice.

### 21.5 Gate Behavior on Revoked Key

Gates MUST reject passports signed with revoked keys, regardless of:
- Key's `valid_until` date
- Passport's `expires_at` date
- Cache status (subject to freshness rules above)

---

## 22. Failure Modes

### 22.1 Failure Mode Table

| Scenario | L1 | L2 | L3 | Error Code |
|----------|----|----|-----|------------|
| Passport signature invalid | Deny | Deny | Deny | `signature_invalid` |
| Passport expired | Deny | Deny | Deny | `passport_expired` |
| Issuer not in policy | Deny | Deny | Deny | `issuer_untrusted` |
| Trust resolution unreachable, cached | N/A | Allow | Allow (if fresh) | — |
| Trust resolution unreachable, not cached | N/A | Deny | Deny | `issuer_untrusted` |
| Revocation data stale | N/A | Allow (warn)* | Deny* | `revocation_stale` |
| Nonce replay | N/A | Deny | Deny | `nonce_replay` |
| PoP invalid | N/A | N/A | Deny | `pop_invalid` |
| Target mismatch | N/A | Deny | Deny | `target_mismatch` |
| Resource mismatch | N/A | Deny | Deny | `resource_mismatch` |
| Session token audience mismatch | N/A | Deny | Deny | `session_audience_mismatch` |
| Session token resource mismatch | N/A | Deny | Deny | `session_resource_mismatch` |
| Session token PoP invalid | N/A | Deny | Deny | `session_pop_invalid` |

*Configurable via `revocation.fail_closed` policy setting.

---

## 23. Performance & Caching

### 23.1 Latency Targets

**Note (Informative):** Latency values are illustrative and assume cached trust resolution and modern cryptographic libraries. Implementations MAY vary by language, runtime, hardware, and registry mode. High-frequency actions SHOULD use Session Grants to amortize expensive checks across multiple calls.

| Profile | Target | Typical |
|---------|--------|---------|
| L1 Baseline | ~10ms | ~5ms |
| L2 Standard | ~30ms | ~20ms |
| L3 Strict | ~100ms | ~50ms |

### 23.2 Caching Rules

| Data | Cacheable | Recommended TTL |
|------|-----------|-----------------|
| Issuer public keys | ✓ | 1 hour |
| Revocation status | ✓ | 60 seconds (L3), 5 min (L2) |
| Trust scores | ✓ | 5 minutes |

---

## 24. Batch & Session Authorization

### 24.1 Session Grant (Fast Path)

**One L2/L3 check → session token → N fast calls (~1ms each)**

```
Request #1: Full L2/L3 verification (~20-50ms)
            Gate issues session_token

Requests #2-N: Local token check only (~1ms)
               Session token includes theft protections
```

This is the recommended solution for high-frequency agents using L2 Standard or L3 Strict.

### 24.2 Session Grant Security Requirements (Normative)

Session Grants are an optimization that amortizes strict verification across many actions. **A Session Grant MUST NOT reduce the theft-resistance posture required by the selected profile.** In particular:

#### 24.2.1 Audience Binding is REQUIRED

Every Session Grant token MUST be bound to a specific target (and, when applicable, resource) such that the token is not valid outside the intended execution boundary.

**Audience binding alone does not satisfy the theft-resistance requirement.** It prevents cross-target token reuse but does not, by itself, mitigate token theft within the intended target.

**Resource Binding (Normative).** When a Session Grant is requested with a bounded resource set (i.e., `scope.resources` is present in the Session Grant request), the resulting Session Grant token MUST carry the same bounded set in `session_token.scope.resources`, and subsequent fast-path requests validated under that Session Grant MUST include an explicit `resource` value. The Gate MUST deny any action whose `resource` is not within `session_token.scope.resources` (or whose resource canonical form does not match a permitted entry). If `scope.resources` is omitted, the Session Grant MUST be treated as action-only and MUST NOT be used to authorize resource-scoped operations unless the Gate policy explicitly allows an unscoped resource wildcard.

**⚠️ Security Warning:** Allowing unscoped resource wildcards significantly increases blast radius if a Session Grant is compromised. Production deployments SHOULD NOT enable unscoped wildcards except for read-only, low-risk actions. Consider requiring explicit `scope.resources` for all write operations.

#### 24.2.2 At Least One Additional Theft-Resistance Mechanism is REQUIRED

In addition to audience binding, each Session Grant token MUST implement **at least one** of the following mechanisms:

| Mechanism | Description | Requirement Level |
|-----------|-------------|-------------------|
| **Proof-of-Possession (PoP) Binding** | The Session Grant is cryptographically bound to a key held by the executing agent/runtime (e.g., DPoP, mTLS/channel binding, or an equivalent PoP scheme), and the Gate validates PoP on each action. | RECOMMENDED for all profiles |
| **Per-Action Nonce (Replay Resistance)** | Each action validated under the Session Grant includes a unique nonce and timestamp, and the Gate enforces replay prevention within the token's validity window. | Acceptable for L1/L2 |
| **Ultra-Short TTL** | The Session Grant has an extremely short lifetime (≤60 seconds for L3, ≤300 seconds for L2), such that compromise impact is strictly time-bounded. | Acceptable if combined with timestamp checks |

#### 24.2.3 Ultra-Short TTL Requirements (Normative)

When using Ultra-Short TTL as the theft-resistance mechanism (without PoP binding):

1. The Gate MUST enforce TTL at issuance time
2. Each action request MUST include `issued_at` timestamp
3. The Gate MUST verify `issued_at` is within acceptable clock skew (default: 30 seconds)
4. The Gate MUST verify `issued_at` is after the session token's `iat`
5. The Gate MUST maintain a sliding window nonce cache to prevent replay within the TTL window

**Rationale:** Without these checks, an attacker who steals a session token can replay actions freely within the TTL window. The timestamp and skew checks, combined with nonce deduplication, bound the replay window to clock skew rather than full TTL.

#### 24.2.4 Profile Alignment

| Profile | Requirements |
|---------|--------------|
| **L1/L2** | Implementers MAY select any one mechanism above, subject to local policy. PoP-binding RECOMMENDED for write operations. |
| **L3 Strict** | Session Grants MUST implement PoP Binding, OR must combine Per-Action Nonce with Ultra-Short TTL (≤60 seconds) AND timestamp/skew checks. |

#### 24.2.5 Rationale (Non-Normative)

The additional mechanism requirement ensures a stolen Session Grant cannot be replayed broadly or indefinitely. This maintains the security posture of the selected profile while enabling the performance benefits of amortized verification.

### 24.3 Session Grant Request

```json
{
  "request_type": "session_grant",
  "passport": { "...": "..." },
  "scope": {
    "actions": ["db:read"],
    "resources": ["table:users", "table:orders"],
    "max_calls": 1000,
    "duration_seconds": 300
  },
  "pop_binding": {
    "method": "dpop",
    "jwk_thumbprint": "sha256:..."
  }
}
```

**PoP Binding Scope (Normative).** The `pop_binding` object is a Session Grant–scoped theft-resistance control. It is not a Passport schema field and does not modify Passport identity semantics. When present, `pop_binding.method` identifies the proof mechanism required for fast-path use of the Session Grant token (e.g., `"dpop"`), and `pop_binding.jwk_thumbprint` identifies the expected key binding for that mechanism. A Gate that issues a Session Grant token with `pop_binding` MUST enforce the corresponding proof check for each action validated under the Session Grant, consistent with the fast-path theft-resistance requirements.

**Anti-Confusion Note:** Gates MUST NOT require Passport schema changes to enable PoP-bound Session Grants. The `pop_binding` field belongs exclusively to Session Grant request/response objects.

### 24.4 Session Token Structure

```json
{
  "session_id": "sess_abc123",
  "passport_id": "pass_xyz",
  "scope": {
    "actions": ["db:read"],
    "resources": ["table:users", "table:orders"]
  },
  "aud": "mcp://tools.acme.com",
  "iat": "2026-01-23T14:30:00Z",
  "exp": "2026-01-23T14:35:00Z",
  "remaining_calls": 1000,
  "pop_binding": {
    "method": "dpop",
    "jwk_thumbprint": "sha256:..."
  },
  "proof": "..."
}
```

### 24.5 Session Limits

| Limit | Default | Max |
|-------|---------|-----|
| `max_calls` | 100 | 10,000 |
| `duration_seconds` | 300 | 3600 (L2 with PoP), 300 (L2 without PoP), 60 (L3 without PoP) |

---

## 25. Debug Mode

### 25.1 Debug Mode (L1 Baseline Only)

Enable verbose error responses:

```yaml
profile: L1
debug:
  enabled: true
  include_expected_values: true
  include_hints: true
```

**Security Warning:** Debug mode MUST be disabled in L2/L3.

---

# Part 5: Security

## 26. Security Model

### 26.1 Threat Model

| Threat | Mitigation | Profile |
|--------|------------|---------|
| Stolen passport | PoP binding | L3 Strict |
| Stolen session token | PoP-bound sessions / short TTL / nonce | L2+, L3 |
| Forged passport | Signature verification | All |
| Replay attack | Nonce + timestamp | L2+, L3 |
| Privilege escalation | Delegation attenuation | All |
| Issuer compromise | Revocation + trust policy | All |

### 26.2 Cryptographic Requirements

| Component | Requirement |
|-----------|-------------|
| Signatures | ES256 (P-256) or EdDSA (Ed25519) |
| Hashes | SHA-256 |
| Minimum key size | 256-bit |

---

## 27. Delegation & Chain Enforcement

### 27.1 Delegation Rules

1. **Attenuation only:** Delegated permissions MUST be subset of delegator's.
2. **Duration subset:** Delegated passport MUST expire before delegator's.
3. **Depth limit:** Maximum delegation depth (default: 5).

### 27.2 Multi-Agent Delegation Example

**Scenario:** Agent A delegates to Agent B, which calls a tool.

```
Agent A (Orchestrator)
  │
  │ delegates via passport chain
  ▼
Agent B (Worker)
  │
  │ presents delegation_chain to Gate
  ▼
Gate verifies:
  1. A's passport is valid
  2. B's passport is valid
  3. B's permissions ⊆ A's permissions
  4. B's expiry ≤ A's expiry
  5. Depth ≤ max_depth
```

**Delegation in passport:**
```json
{
  "passport_id": "pass_agent_b",
  "delegation": {
    "parent_passport_id": "pass_agent_a",
    "delegated_by": "agent_a",
    "delegated_at": "2026-01-23T14:00:00Z",
    "chain": [
      { "passport": { "...parent passport inline..." } }
    ]
  },
  "permissions": [
    { "action": "db:read", "resources": ["table:users"] }
  ]
}
```

**Gate verification (Normative):**

```
FUNCTION verify_delegation(passport):
  IF passport.delegation IS NULL:
    RETURN valid()  # Not delegated
  
  # Parent passport MUST be included inline in delegation.chain
  # This enables local-first verification without network calls
  parent = passport.delegation.chain[0].passport
  
  IF NOT is_valid(parent):
    RETURN deny(PARENT_INVALID)
  
  IF NOT is_subset(passport.permissions, parent.permissions):
    RETURN deny(PRIVILEGE_ESCALATION)
  
  IF passport.provenance.expires_at > parent.provenance.expires_at:
    RETURN deny(EXPIRY_EXCEEDED)
  
  depth = count_chain_depth(passport)
  IF depth > max_depth:
    RETURN deny(CHAIN_TOO_DEEP)
  
  RETURN valid()
```

**Local-First Delegation:** The parent passport(s) are included inline in `delegation.chain` to enable verification without network lookups. This maintains the "local-first, no external dependencies" principle even for delegated passports.

### 27.3 Multi-Hop Session Grants (Swarm Pattern)

**Scenario:** Agent A (orchestrator) grants session to Agent B (worker), which calls a tool. This is common in swarm architectures (CrewAI, AutoGPT).

```
Agent A (Orchestrator, L3 Strict passport)
  │
  │ issues Session Grant to Agent B
  │ (attenuated scope: db:read only)
  ▼
Agent B (Worker)
  │
  │ presents session_token + PoP to Gate
  ▼
Gate verifies:
  1. Session token is valid
  2. Session token's parent passport (A) is valid
  3. B's PoP matches session's pop_binding
  4. Action within session scope
```

**Chain PoP verifies lineage:** For multi-hop scenarios, each Session Grant in the chain MUST include PoP binding that can be verified back to the original issuer. This prevents "session laundering" where a compromised intermediate agent issues unauthorized Session Grants.

**Session Grant with delegation context:**
```json
{
  "session_id": "sess_abc123",
  "passport_id": "pass_agent_a",
  "delegated_to": "agent_b",
  "scope": {
    "actions": ["db:read"],
    "resources": ["table:users"]
  },
  "aud": "mcp://tools.acme.com",
  "pop_binding": {
    "method": "dpop",
    "jwk_thumbprint": "sha256:agent_b_key"
  }
}
```

---

## 28. Proof of Possession

### 28.1 When Required

| Profile | PoP Required |
|---------|--------------|
| L1 Baseline | No |
| L2 Standard | No (recommended for writes) |
| L3 Strict | Yes |

### 28.2 PoP Structure

```json
{
  "type": "dpop",
  "payload": {
    "jti": "pop_unique_id",
    "iat": "2026-01-23T14:30:00Z",
    "aud": "mcp://tools.acme.com",
    "passport_id": "pass_abc123"
  },
  "signature": "..."
}
```

**Note:** The PoP payload uses `passport_id` (not `passport_jti`) to match the Uniplex naming convention.

---

## 29. Canonical JSON

### 29.1 When Required

| Profile | Required |
|---------|----------|
| L1 Baseline | No |
| L2 Standard | No (recommended) |
| L3 Strict | Yes |

### 29.2 Rules

1. No whitespace
2. Keys sorted lexicographically
3. No duplicate keys

---

## 30. Trust Evaluation Algorithm

### 30.1 L1 Baseline Algorithm

```
FUNCTION evaluate_L1(request, policy):
  passport = request.passport
  
  // 1. Verify signature
  IF NOT verify_signature(passport):
    RETURN deny(SIGNATURE_INVALID)
  
  // 2. Check expiration
  IF passport.provenance.expires_at < now():
    RETURN deny(PASSPORT_EXPIRED)
  
  // 3. Apply issuer policy
  IF NOT apply_issuer_policy(passport, policy):
    RETURN deny(ISSUER_UNTRUSTED)
  
  // 4. Check permission
  IF NOT has_permission(passport, request.action):
    RETURN deny(PERMISSION_DENIED)
  
  RETURN allow()

FUNCTION apply_issuer_policy(passport, policy):
  IF policy.allow_self_issued AND passport.provenance.issuer.tier == "self":
    RETURN true
  IF passport.provenance.issuer.id IN policy.allowed_issuers:
    RETURN true
  RETURN false

FUNCTION verify_signature(passport):
  // For self-issued: use embedded identity.public_key
  // For others: use proof.kid to resolve key from trust store
  IF passport.provenance.issuer.tier == "self":
    IF passport.identity.public_key IS NULL:
      RETURN false
    key = passport.identity.public_key
  ELSE:
    key = resolve_key(passport.proof.kid)
  
  RETURN crypto_verify(passport, key)
```

### 30.2 L2 Standard Algorithm

```
FUNCTION evaluate_L2(request, policy):
  // All L1 checks
  result = evaluate_L1(request, policy)
  IF result != allow:
    RETURN result
  
  // 5. Check nonce
  IF is_replay(request.nonce):
    RETURN deny(NONCE_REPLAY)
  
  // 6. Check target (canonicalized)
  IF canonicalize(request.target) != expected_target:
    RETURN deny(TARGET_MISMATCH)
  
  // 7. Check resource (canonicalized)
  IF NOT resource_matches(canonicalize(request.resource), passport.permissions):
    RETURN deny(RESOURCE_MISMATCH)
  
  // 8. Check constraints
  // 9. Check revocation (if enabled)
  IF policy.revocation.enabled:
    revocation_status = check_revocation(passport)
    IF revocation_status == STALE:
      IF policy.revocation.fail_closed:
        RETURN deny(REVOCATION_STALE)
      ELSE:
        log_warning("revocation_stale")
  
  RETURN allow()
```

### 30.3 L3 Strict Algorithm

```
FUNCTION evaluate_L3(request, policy):
  // All L2 checks (with fail_closed = true)
  result = evaluate_L2(request, policy)
  IF result != allow:
    RETURN result
  
  // 10. Verify PoP
  IF NOT verify_pop(request.pop, passport):
    RETURN deny(POP_INVALID)
  
  // 11. Check revocation freshness (MUST be fresh for verified/certified)
  IF passport.provenance.issuer.tier IN ["verified", "certified"]:
    IF NOT is_revocation_fresh(policy.revocation.max_staleness_seconds):
      RETURN deny(REVOCATION_STALE)
  
  // 12. Verify delegation chain (if delegated)
  IF passport.delegation IS NOT NULL:
    IF NOT verify_delegation(passport):
      RETURN deny(DELEGATION_INVALID)
  
  RETURN allow()
```

### 30.4 Session Grant Validation Algorithm

```
FUNCTION validate_session_action(session_token, action, policy):
  // 1. Verify session token signature
  IF NOT verify_signature(session_token):
    RETURN deny(SESSION_INVALID)
  
  // 2. Check session not expired
  IF parse_timestamp(session_token.exp) < now():
    RETURN deny(SESSION_INVALID)
  
  // 3. Check audience binding (REQUIRED)
  IF canonicalize(session_token.aud) != canonicalize(action.target):
    RETURN deny(SESSION_AUDIENCE_MISMATCH)
  
  // 4. Check resource scope (if present) — REQUIRED when scoped
  IF session_token.scope.resources IS NOT NULL:
    IF action.resource IS NULL:
      RETURN deny(SESSION_RESOURCE_MISMATCH)
    IF canonicalize(action.resource) NOT IN 
       canonicalize_all(session_token.scope.resources):
      RETURN deny(SESSION_RESOURCE_MISMATCH)
  
  // 5. Check theft-resistance mechanism (REQUIRED)
  IF session_token.pop_binding IS NOT NULL:
    IF NOT verify_pop(action.pop, session_token.pop_binding):
      RETURN deny(SESSION_POP_INVALID)
  ELSE IF action.nonce IS NOT NULL:
    IF is_replay(action.nonce, session_token.session_id):
      RETURN deny(NONCE_REPLAY)
    // Ultra-short TTL path: also verify timestamp
    IF action.issued_at IS NULL:
      RETURN deny(SESSION_INVALID)
    IF NOT within_clock_skew(action.issued_at, 30):
      RETURN deny(SESSION_INVALID)
  ELSE:
    // No PoP, no nonce — only acceptable for ultra-short TTL
    // Verify session token TTL is within limits
    ttl = parse_timestamp(session_token.exp) - parse_timestamp(session_token.iat)
    IF ttl > 60 AND profile == L3:
      RETURN deny(SESSION_INVALID)
    IF ttl > 300 AND profile == L2:
      RETURN deny(SESSION_INVALID)
  
  // 6. Check action in scope
  IF action.action NOT IN session_token.scope.actions:
    RETURN deny(PERMISSION_DENIED)
  
  // 7. Check remaining calls
  IF session_token.remaining_calls <= 0:
    RETURN deny(SESSION_EXHAUSTED)
  
  decrement_remaining_calls(session_token)
  RETURN allow()
```

---

# Part 6: Interoperability

## 31. Ecosystem Compatibility

### 31.1 Full Compatibility Matrix

| System | What It Does | What Uniplex Adds | Integration Profile |
|--------|--------------|-------------------|---------------------|
| OAuth/OIDC | Human auth | Agent authorization | Uni-Enterprise |
| SPIFFE/SPIRE | Workload identity | Agent permissions | Uni-Workload |
| OPA/Cedar | Policy evaluation | Standardized I/O | Any (Policy Engine) |
| MCP | Tool invocation | Trust layer | Uni-MCP |
| W3C VC | Credentials | Envelope compatibility for Uni-Passports | Optional (Extension) |
| Blockchain | On-chain attestations | Format agility for on-chain proofs | Optional (Extension) |

**W3C VC:** See Compatibility Matrix note on W3C VC envelope compatibility.

**Blockchain:** See Extension Namespace Registry for `org.blockchain.*`.

### 31.2 Interoperability Notes

The following are optional interoperability patterns for specific ecosystems:

- **SPIFFE embedding:** Uni-Passports MAY embed SPIFFE IDs as an optional claim (via `org.spiffe.*` extension namespace) for workload/agent bridging. This allows existing SPIFFE infrastructure to coexist with Uniplex authorization.

- **TAP-signed intents:** Uniplex MAY accept TAP-signed intent artifacts as input evidence via an extension namespace, without requiring replacement of existing signing flows. This enables gradual adoption in environments with existing TAP infrastructure.

---

## 32. Versioning & Evolution

### 32.1 Compatibility Rules

| Change Type | Minor Version | Major Version |
|-------------|---------------|---------------|
| New optional field | ✓ | ✓ |
| New required field | | ✓ |
| Semantic change | | ✓ |

---

## 33. Conformance Testing

### 33.1 Test Categories

| Category | Count | Required for |
|----------|-------|--------------|
| Signature verification | 20 | All |
| Issuer policy | 15 | All |
| Permission matching | 20 | All |
| Nonce handling | 15 | L2+, L3 |
| PoP binding | 30 | L3 |
| Session tokens | 25 | L2+, L3 |
| Session resource binding | 10 | L2+, L3 |
| Delegation | 20 | All |
| **Total** | **155+** | |

### 33.2 Conformance Badges

- "Uniplex L1 Baseline Conformant"
- "Uniplex L2 Standard Conformant"
- "Uniplex L3 Strict Conformant"

---

# Appendices

## Appendix A: Glossary

| Term | Definition |
|------|------------|
| **Uniplex Passport** (aka "Uni-Passport") | Signed agent credential |
| **Uniplex Gate** (aka "Uni-Gate") | Authorization decision point |
| **Uniplex Attestation** (aka "Uni-Attestation") | Portable proof of verification |
| **L1 Baseline** | Foundation profile — minimal checks |
| **L2 Standard** | Production profile — standard security |
| **L3 Strict** | Compliance profile — strict security |
| **Local Trust Store** | File-based trust resolution |
| **Issuer Policy** | Rules for which issuers to trust |
| **PoP** | Proof of Possession |
| **Session Grant** | Short-lived, scoped session credential issued after L2/L3 evaluation to amortize repeated calls. MUST preserve theft protections (PoP-binding, per-action nonce, or ultra-short TTL). NOT an unbound bearer token. |
| **Audience Binding** | Session token bound to specific target; REQUIRED but not sufficient alone |
| **Resource Binding** | Session token bound to specific resources; REQUIRED when scope.resources present |
| **Canonicalization** | Normalization of target/resource strings for comparison |

---

## Appendix B: Quick Reference

### Profile Comparison

| Feature | L1 Baseline | L2 Standard | L3 Strict |
|---------|-------------|-------------|-----------|
| Signature verification | ✓ | ✓ | ✓ |
| Expiration check | ✓ | ✓ | ✓ |
| Issuer policy | ✓ | ✓ | ✓ |
| Permission check | ✓ | ✓ | ✓ |
| Resource scope check | | ✓ | ✓ |
| Nonce/replay | | ✓ | ✓ |
| Trust resolution | | Optional | Required* |
| Revocation check | | Optional** | Required |
| Canonical JSON | | | ✓ |
| PoP binding | | | ✓ |
| Signed attestations | | | ✓ |

*L3 Strict trust resolution: Local Trust Store, self-hosted registry, or public registry. **NOT any specific vendor.**

**L2 revocation:** configurable via `revocation.fail_closed` (default: allow + warn). Set `fail_closed: true` for strict mode.

### Session Grant Requirements

| Requirement | L1/L2 | L3 Strict |
|-------------|-------|-----------|
| Audience binding | REQUIRED | REQUIRED |
| Resource binding (if scoped) | REQUIRED | REQUIRED |
| Additional theft protection | One of: PoP / nonce / short TTL | PoP, OR (nonce + TTL ≤60s) |

### Latency Targets

| Profile | Typical |
|---------|---------|
| L1 Baseline | ~5ms |
| L2 Standard | ~20ms |
| L3 Strict | ~50ms (or ~1ms with Session Grant) |

---

## Appendix C: Conformance Test Vectors

See: `uniplex-conformance-vectors-2026-01-25.json` (published alongside this specification).

**Canonicalization Gauntlet:** The test vectors include a dedicated "Canonicalization Gauntlet" section with 20+ edge-case URIs covering: mixed-case schemes/hosts, default ports, trailing slashes, query parameter ordering, percent-encoding edge cases, and reserved delimiter preservation. Third-party Gate implementations MUST pass all canonicalization vectors to ensure target/resource matching interoperability.

---

## Appendix D: Compliance Mapping

| Standard | Relevant Uniplex Feature |
|----------|-------------------------|
| SOC 2 CC6.1 | Uni-Gate authorization |
| SOC 2 CC7.1 | Uni-Attestation logging |
| ISO 27001 A.9 | L1/L2/L3 profiles |
| HIPAA 164.312 | L3 Strict + attestations |
| PCI DSS Req 7-10 | Permissions + logging |

---

## Appendix E: Extension Namespace Registry

| Namespace | Purpose | Status |
|-----------|---------|--------|
| `org.oauth.*` | OAuth/OIDC interop | Active |
| `org.spiffe.*` | SPIFFE binding | Active |
| `org.openpolicyagent.*` | OPA metadata | Active |
| `org.modelcontextprotocol.*` | MCP extensions | Active |
| `org.w3c.proof.*` | W3C VC proof compatibility (ZK, BBS+, selective disclosure) | Planned |
| `org.blockchain.*` | On-chain attestations, stake-backed identity | Extension |
| `ai.uniplex.*` | Uniplex extensions | Active |

**Namespace ownership (non-normative):** Extension namespaces follow reverse-domain ownership. Each organization SHOULD publish extensions only under a domain it controls (e.g., `com.acme.*`, `org.example.*`). The `ai.uniplex.*` namespace is reserved for maintainer-published Uniplex extensions and is provided for convenience; it carries no special trust privilege and MUST be treated like any other namespace by Gate policy. Using `ai.uniplex.*` is optional; implementations MAY ignore unknown extensions without loss of protocol interoperability.

---

## Appendix F: Intellectual Property Notice

### F.1 Patent Notice

Standard Logic Co. may have patent applications relevant to implementations of this specification. This specification is published to promote interoperability and does not constitute a grant of any patent rights.

For avoidance of doubt, this patent notice and any Non-Assertion Covenant are separate from, and do not limit, any patent license granted under the Apache-2.0 license for the Reference SDK.

For patent licensing inquiries: ip@standardlogic.ai

### F.2 Non-Assertion Covenant

Standard Logic Co. covenants not to assert patent claims against conformant implementations that are:

- **(a)** Open source software under an OSI-approved license, OR
- **(b)** Non-commercial use

This covenant applies to conformant open-source and internal enterprise deployments **regardless of scale**, and is not conditioned on using any particular registry operator.

This covenant does not extend to:
- Proprietary scoring algorithms
- Managed trust resolution services
- Certification services
- Value-added features beyond the specification

### F.3 Relationship Between SDK License and Specification IP

**Clarification for implementers:**

| Component | License | Patent Coverage |
|-----------|---------|-----------------|
| **Reference SDK** | Apache-2.0 | Apache-2.0 patent grant covers claims embodied in SDK code contributed by Standard Logic |
| **Specification** | CC BY 4.0 | No patent grant; Non-Assertion Covenant applies to conformant OSS/non-commercial implementations |
| **Non-SDK implementations** | N/A | Non-Assertion Covenant applies if OSS or non-commercial; commercial licensing available otherwise |

**In plain English:**

1. **If you use the SDK (Apache-2.0):** You receive a patent license for claims embodied in the SDK implementation itself, per Apache-2.0 Section 3.

2. **If you implement from the spec (not using SDK):** The Non-Assertion Covenant protects you if your implementation is (a) open source under an OSI-approved license, or (b) non-commercial.

3. **Commercial value that remains licensable:** Managed trust resolution services, certification programs, enterprise governance tooling, and proprietary scoring are not covered by the covenant and remain commercial offerings.

This structure is intentional: it maximizes adoption (open SDK, protected OSS implementations) while preserving commercial value in services and tooling built on top of the protocol.

### F.4 Trademark Notice

"Uniplex" is a trademark of Standard Logic Co. Conformance badges require passing the official test suite.

### F.5 Specification License

This specification is licensed under CC BY 4.0. This does not grant patent rights.

---

## Appendix G: Governance Roadmap

### G.1 Current State

Standard Logic Co. is the **initial maintainer** of the Uniplex specification.

### G.2 Roadmap

| Phase | Timeline | Model |
|-------|----------|-------|
| Phase 1 | Now | Initial maintainer |
| Phase 2 | Month 6 | Advisory board |
| Phase 3 | Month 12 | Open contribution (UIP) |
| Phase 4 | Month 18+ | Foundation consideration |

### G.3 Foundation Consideration Criteria

Foundation consideration at Phase 4 requires:
- 10+ independent implementations, OR
- 100,000+ passports issued across ecosystem, OR
- Community request with advisory board support (50+ signatories)

**Signatory Eligibility:** One signature per organization. Eligible signatories include maintainers of conformant implementations, representatives of enterprises with production deployments, or advisory board members. Signatures are collected via public petition with organizational verification.

### G.4 Contribution Process (Phase 3)

1. Proposal as UIP
2. 30-day comment period
3. Advisory board review
4. Maintainer decision based on: interop impact, security, backward compatibility
5. Appeal via advisory board supermajority

---

*Uniplex Maintainers (initially Standard Logic Co.)*
*Specification 2026-01-25*
