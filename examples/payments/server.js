/**
 * Payments API with Uniplex Authorization
 * 
 * A realistic example showing AI agents accessing a banking API.
 * Demonstrates: permission scoping, amount limits, user isolation, audit trails.
 * 
 * Run: node server.js
 */

import http from 'http';
import { Gate, GateRequest, Attestation, TrustProfile, Passport } from 'uniplex';

// Simulated database
const accounts = {
  'acct_alice': { owner: 'alice', balance: 5000.00, name: 'Alice Smith' },
  'acct_bob': { owner: 'bob', balance: 12500.00, name: 'Bob Jones' },
  'acct_corp': { owner: 'corp', balance: 1000000.00, name: 'Acme Corp' },
};

const transactions = [];

// Uniplex Gate
const gate = new Gate({ profile: TrustProfile.L1 });

// Extract transfer limit from permission
function getTransferLimit(passport) {
  const permissions = passport.permissions || [];
  let maxLimit = 0;
  
  for (const perm of permissions) {
    const action = perm.action || perm;
    if (action === 'payments:transfer:*' || action === '*') {
      return Infinity;
    }
    const match = action.match(/^payments:transfer:(\d+)$/);
    if (match) {
      maxLimit = Math.max(maxLimit, parseInt(match[1]));
    }
  }
  return maxLimit;
}

// Check if passport has a specific permission
function hasPermission(passport, requiredAction) {
  const permissions = passport.permissions || [];
  for (const perm of permissions) {
    const action = perm.action || perm;
    if (action === '*') return true;
    if (action === requiredAction) return true;
    // Check wildcard prefix (e.g., "payments:*" matches "payments:read_balance")
    if (action.endsWith(':*')) {
      const prefix = action.slice(0, -1);
      if (requiredAction.startsWith(prefix)) return true;
    }
  }
  return false;
}

// Check if passport can access this account
function canAccessAccount(passport, accountId) {
  const account = accounts[accountId];
  if (!account) return false;
  
  // Agent ID format: "alice-assistant" -> owner is "alice"
  const agentOwner = passport.identity?.agent_id?.split('-')[0];
  return agentOwner === account.owner;
}

// Create attestation for an action
async function createAttestation(passport, action) {
  const request = GateRequest.create(passport, action, {
    target: 'api://payments.acme.com'
  });
  const decision = await gate.authorize(request);
  
  if (decision.allowed) {
    const attestation = await Attestation.fromDecision(request, decision, {
      gateId: 'payments-gate'
    });
    return attestation.attestationId;
  }
  return null;
}

// API handlers
const handlers = {
  // Check balance - requires payments:read_balance
  async read_balance({ account_id }, passport) {
    // Check permission
    if (!hasPermission(passport, 'payments:read_balance')) {
      return { error: 'Not authorized to read balances', code: 'PERMISSION_DENIED' };
    }
    
    // Check account access
    if (!canAccessAccount(passport, account_id)) {
      logAudit('READ_BALANCE_DENIED', passport, { account_id, reason: 'account_not_owned' });
      return { error: 'Cannot access this account', code: 'ACCOUNT_ACCESS_DENIED' };
    }
    
    const account = accounts[account_id];
    const attestationId = await createAttestation(passport, 'payments:read_balance');
    
    logAudit('READ_BALANCE', passport, { account_id, balance: account.balance });
    
    return {
      account_id,
      balance: account.balance,
      owner: account.name,
      attestation_id: attestationId
    };
  },

  // Transfer money - requires payments:transfer:{limit}
  async transfer({ from_account, to_account, amount, memo }, passport) {
    amount = parseFloat(amount);
    
    // Check transfer limit
    const limit = getTransferLimit(passport);
    if (limit === 0) {
      logAudit('TRANSFER_DENIED', passport, { amount, reason: 'no_transfer_permission' });
      return { error: 'No transfer permission', code: 'PERMISSION_DENIED' };
    }
    
    if (amount > limit) {
      logAudit('TRANSFER_DENIED', passport, { amount, limit, reason: 'exceeds_limit' });
      return { 
        error: `Transfer amount $${amount} exceeds your limit of $${limit}`, 
        code: 'LIMIT_EXCEEDED',
        your_limit: limit,
        requested: amount
      };
    }
    
    // Check account access
    if (!canAccessAccount(passport, from_account)) {
      logAudit('TRANSFER_DENIED', passport, { from_account, reason: 'account_not_owned' });
      return { error: 'Cannot transfer from this account', code: 'ACCOUNT_ACCESS_DENIED' };
    }
    
    // Check sufficient funds
    const fromAcct = accounts[from_account];
    if (!fromAcct || fromAcct.balance < amount) {
      return { error: 'Insufficient funds', code: 'INSUFFICIENT_FUNDS' };
    }
    
    // Check destination exists
    const toAcct = accounts[to_account];
    if (!toAcct) {
      return { error: 'Destination account not found', code: 'ACCOUNT_NOT_FOUND' };
    }
    
    // Execute transfer
    fromAcct.balance -= amount;
    toAcct.balance += amount;
    
    const txn = {
      id: `txn_${Date.now()}`,
      from: from_account,
      to: to_account,
      amount,
      memo: memo || 'Transfer',
      agent: passport.identity?.agent_id,
      timestamp: new Date().toISOString()
    };
    transactions.push(txn);
    
    logAudit('TRANSFER_SUCCESS', passport, txn);
    
    // Create attestation for the transfer
    const permissionUsed = amount <= 100 ? 'payments:transfer:100' :
                          amount <= 1000 ? 'payments:transfer:1000' :
                          amount <= 10000 ? 'payments:transfer:10000' : 'payments:transfer:*';
    const attestationId = await createAttestation(passport, permissionUsed);
    
    return {
      success: true,
      transaction: txn,
      new_balance: fromAcct.balance,
      attestation_id: attestationId
    };
  },

  // Get transaction history
  async list_transactions({ account_id }, passport) {
    if (!hasPermission(passport, 'payments:read_balance')) {
      return { error: 'Not authorized', code: 'PERMISSION_DENIED' };
    }
    
    if (!canAccessAccount(passport, account_id)) {
      return { error: 'Cannot access this account', code: 'ACCOUNT_ACCESS_DENIED' };
    }
    
    const acctTxns = transactions.filter(t => t.from === account_id || t.to === account_id);
    return { transactions: acctTxns };
  }
};

// Audit log
function logAudit(event, passport, details) {
  const entry = {
    timestamp: new Date().toISOString(),
    event,
    agent_id: passport.identity?.agent_id,
    passport_id: passport.passport_id,
    ...details
  };
  console.log(`[AUDIT] ${event}:`, JSON.stringify(entry));
}

// HTTP Server
const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  if (req.url === '/health') {
    res.writeHead(200);
    res.end(JSON.stringify({ status: 'ok', server: 'api://payments.acme.com' }));
    return;
  }

  if (req.url === '/api' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { action, params, passport } = JSON.parse(body);
        
        if (!passport) {
          res.writeHead(401);
          res.end(JSON.stringify({ error: 'No passport provided' }));
          return;
        }

        const handler = handlers[action];
        if (!handler) {
          res.writeHead(404);
          res.end(JSON.stringify({ error: `Unknown action: ${action}` }));
          return;
        }

        const result = await handler(params || {}, passport);
        
        if (result.error) {
          res.writeHead(result.code === 'PERMISSION_DENIED' ? 403 : 400);
        } else {
          res.writeHead(200);
        }
        res.end(JSON.stringify(result));

      } catch (err) {
        console.error('[ERROR]', err);
        res.writeHead(400);
        res.end(JSON.stringify({ error: err.message }));
      }
    });
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not found' }));
});

const PORT = 3002;
server.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════════╗
║  💳 Payments API with Uniplex Authorization                    ║
╠════════════════════════════════════════════════════════════════╣
║  Server: api://payments.acme.com                               ║
║  Port:   ${PORT}                                                   ║
╠════════════════════════════════════════════════════════════════╣
║  Test Accounts:                                                ║
║    acct_alice  - Alice Smith  - $5,000                         ║
║    acct_bob    - Bob Jones    - $12,500                        ║
║    acct_corp   - Acme Corp    - $1,000,000                     ║
╠════════════════════════════════════════════════════════════════╣
║  Permissions:                                                  ║
║    payments:read_balance     - View balances                   ║
║    payments:transfer:100     - Transfer up to $100             ║
║    payments:transfer:1000    - Transfer up to $1,000           ║
║    payments:transfer:10000   - Transfer up to $10,000          ║
║    payments:transfer:*       - Unlimited transfers             ║
╚════════════════════════════════════════════════════════════════╝
  `);
});
