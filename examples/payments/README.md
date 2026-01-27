# Uniplex Payments Example

**A high-stakes demo showing why AI authorization matters.**

## The Problem

You're building an AI agent that can access your banking API. Without proper authorization:

- 🚨 The agent could transfer more than intended
- 🚨 The agent could access accounts it shouldn't
- 🚨 You'd have no audit trail for compliance
- 🚨 One compromised agent could drain everything

## What This Demo Shows

| Scenario | What Happens |
|----------|--------------|
| Agent tries $500 transfer with $100 limit | **Blocked** |
| Alice's agent tries to access Bob's account | **Blocked** |
| Read-only agent tries any transfer | **Blocked** |
| $10k agent tries $50k transfer | **Blocked** |
| Valid transfers within limits | ✅ Allowed + Attestation |

**Total prevented in demo: $50,551 in unauthorized transfers**

## Quick Start

```bash
npm install
```

**Terminal 1:**
```bash
npm run server
```

**Terminal 2:**
```bash
npm run client
```

## Sample Output

```
SCENARIO 1: Alice's Assistant - Limited Transfer Rights

Agent: alice-assistant
Owner: Alice
Permissions: read_balance, transfer up to $100

→ Checking Alice's balance...
  ✅ Balance: $5,000.00

→ Transferring $50 to Bob...
  ✅ Transfer complete! New balance: $4,950.00
  📜 Attestation: att_1706...

→ Attempting $500 transfer (SHOULD FAIL)...
  🚫 DENIED: Transfer amount $500 exceeds your limit of $100
     Your limit: $100, Requested: $500
```

## Key Concepts Demonstrated

### 1. Amount Limits

Agents have different transfer limits:

```javascript
const assistant = await Agent.create('alice-assistant', {
  permissions: ['payments:transfer:100']  // Max $100
});

const treasury = await Agent.create('corp-treasury', {
  permissions: ['payments:transfer:10000']  // Max $10,000
});
```

### 2. Account Isolation

Agents can only access accounts they own:

```javascript
// Agent ID: "alice-assistant" → Owner: "alice"
// Can access: acct_alice ✅
// Cannot access: acct_bob ❌
```

### 3. Permission Scoping

Different permissions for different actions:

```javascript
const readOnly = await Agent.create('viewer', {
  permissions: ['payments:read_balance']  // No transfers!
});

const fullAccess = await Agent.create('admin', {
  permissions: [
    'payments:read_balance',
    'payments:transfer:*'  // Unlimited
  ]
});
```

### 4. Audit Trail

Every decision includes a signed attestation:

```json
{
  "attestation_id": "att_1706...",
  "agent_id": "alice-assistant",
  "action": "payments:transfer:100",
  "decision": "allow",
  "timestamp": "2026-01-26T...",
  "signature": "base64..."
}
```

## Server Logs (Audit Trail)

```
[AUDIT] READ_BALANCE: {"agent_id":"alice-assistant","account_id":"acct_alice","balance":5000}
[AUDIT] TRANSFER_SUCCESS: {"from":"acct_alice","to":"acct_bob","amount":50,"agent":"alice-assistant"}
[AUDIT] TRANSFER_DENIED: {"amount":500,"limit":100,"reason":"exceeds_limit","agent_id":"alice-assistant"}
[AUDIT] READ_BALANCE_DENIED: {"account_id":"acct_bob","reason":"account_not_owned","agent_id":"alice-assistant"}
```

## Why This Matters

| Without Uniplex | With Uniplex |
|-----------------|--------------|
| Trust every AI agent | Verify every request |
| Hope it doesn't misbehave | Enforce limits cryptographically |
| No audit trail | Signed attestations for every decision |
| All-or-nothing access | Fine-grained permissions |
| One bad agent = breach | Isolated, scoped access |

## Real-World Applications

- **Banking**: Agents with spending limits
- **Healthcare**: Agents that can read but not modify records
- **Trading**: Agents with position size limits
- **HR**: Agents that can view salary but not change it
- **Infrastructure**: Agents that can read logs but not delete

## Files

| File | Description |
|------|-------------|
| `server.js` | Payments API with Uniplex Gate |
| `client.js` | Demo showing blocked + allowed operations |
| `package.json` | Dependencies |

## Links

- [Uniplex Documentation](https://uniplex.io)
- [GitHub](https://github.com/uniplexprotocol/uniplex)
- [npm](https://www.npmjs.com/package/uniplex)
