/**
 * Payments Client - High Stakes Demo
 * 
 * Demonstrates real consequences of AI authorization:
 * - Agents with different permission levels
 * - Amount limits preventing large unauthorized transfers
 * - Account isolation preventing cross-user access
 * - Full audit trail for compliance
 * 
 * Run: node client.js
 */

import { Agent } from 'uniplex';

const SERVER_URL = 'http://localhost:3002';

async function callAPI(passport, action, params) {
  const response = await fetch(`${SERVER_URL}/api`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, params, passport: passport.toDict() })
  });
  return response.json();
}

function divider(title) {
  console.log('\n' + '═'.repeat(65));
  console.log(`  ${title}`);
  console.log('═'.repeat(65) + '\n');
}

async function main() {
  console.log(`
╔════════════════════════════════════════════════════════════════╗
║  💳 Payments Demo - Why AI Authorization Matters               ║
╠════════════════════════════════════════════════════════════════╣
║  This demo shows what happens when AI agents try to:           ║
║    • Access accounts they don't own                            ║
║    • Transfer more than their limit allows                     ║
║    • Operate without proper permissions                        ║
╚════════════════════════════════════════════════════════════════╝
  `);

  // Check server
  try {
    await fetch(`${SERVER_URL}/health`);
  } catch {
    console.log('❌ Server not running! Start with: node server.js\n');
    process.exit(1);
  }

  // ═══════════════════════════════════════════════════════════════
  // SCENARIO 1: Alice's personal assistant with limited permissions
  // ═══════════════════════════════════════════════════════════════
  
  divider("SCENARIO 1: Alice's Assistant - Limited Transfer Rights");
  
  const aliceAssistant = await Agent.create('alice-assistant', {
    permissions: [
      'payments:read_balance',
      'payments:transfer:100'  // Can only transfer up to $100
    ]
  });
  
  console.log('Agent: alice-assistant');
  console.log('Owner: Alice');
  console.log('Permissions: read_balance, transfer up to $100\n');

  // ✅ Check balance - allowed
  console.log('→ Checking Alice\'s balance...');
  let result = await callAPI(aliceAssistant.passport, 'read_balance', { 
    account_id: 'acct_alice' 
  });
  if (result.balance !== undefined) {
    console.log(`  ✅ Balance: $${result.balance.toFixed(2)}`);
    console.log(`  📜 Attestation: ${result.attestation_id}\n`);
  } else {
    console.log(`  ❌ Error: ${result.error}\n`);
  }

  // ✅ Small transfer - allowed
  console.log('→ Transferring $50 to Bob...');
  result = await callAPI(aliceAssistant.passport, 'transfer', {
    from_account: 'acct_alice',
    to_account: 'acct_bob',
    amount: 50,
    memo: 'Lunch money'
  });
  if (result.success) {
    console.log(`  ✅ Transfer complete! New balance: $${result.new_balance.toFixed(2)}`);
    console.log(`  📜 Attestation: ${result.attestation_id}\n`);
  } else {
    console.log(`  ❌ Error: ${result.error}\n`);
  }

  // ❌ Large transfer - DENIED (exceeds $100 limit)
  console.log('→ Attempting $500 transfer (SHOULD FAIL)...');
  result = await callAPI(aliceAssistant.passport, 'transfer', {
    from_account: 'acct_alice',
    to_account: 'acct_bob',
    amount: 500,
    memo: 'Big payment'
  });
  if (result.error) {
    console.log(`  🚫 DENIED: ${result.error}`);
    console.log(`     Your limit: $${result.your_limit}, Requested: $${result.requested}\n`);
  }

  // ═══════════════════════════════════════════════════════════════
  // SCENARIO 2: Malicious agent trying to access wrong account
  // ═══════════════════════════════════════════════════════════════
  
  divider("SCENARIO 2: Alice's Assistant Tries to Access Bob's Account");
  
  console.log('→ Alice\'s assistant trying to check Bob\'s balance...');
  result = await callAPI(aliceAssistant.passport, 'read_balance', { 
    account_id: 'acct_bob' 
  });
  if (result.error) {
    console.log(`  🚫 DENIED: ${result.error}`);
    console.log(`     Code: ${result.code}\n`);
  }

  console.log('→ Alice\'s assistant trying to transfer FROM Bob\'s account...');
  result = await callAPI(aliceAssistant.passport, 'transfer', {
    from_account: 'acct_bob',  // Not Alice's account!
    to_account: 'acct_alice',
    amount: 50,
    memo: 'Stealing money'
  });
  if (result.error) {
    console.log(`  🚫 DENIED: ${result.error}`);
    console.log(`     Code: ${result.code}\n`);
  }

  // ═══════════════════════════════════════════════════════════════
  // SCENARIO 3: Corporate treasury agent with high limits
  // ═══════════════════════════════════════════════════════════════
  
  divider("SCENARIO 3: Corporate Treasury Agent - High Limits");
  
  const corpTreasury = await Agent.create('corp-treasury', {
    permissions: [
      'payments:read_balance',
      'payments:transfer:10000'  // Can transfer up to $10,000
    ]
  });
  
  console.log('Agent: corp-treasury');
  console.log('Owner: Acme Corp');
  console.log('Permissions: read_balance, transfer up to $10,000\n');

  // ✅ Check corp balance first
  console.log('→ Checking Acme Corp balance...');
  result = await callAPI(corpTreasury.passport, 'read_balance', { 
    account_id: 'acct_corp' 
  });
  if (result.balance !== undefined) {
    console.log(`  ✅ Balance: $${result.balance.toLocaleString()}`);
    console.log(`  📜 Attestation: ${result.attestation_id}\n`);
  }

  // ✅ Large transfer - allowed within limit
  console.log('→ Transferring $5,000 to Bob (vendor payment)...');
  result = await callAPI(corpTreasury.passport, 'transfer', {
    from_account: 'acct_corp',
    to_account: 'acct_bob',
    amount: 5000,
    memo: 'Invoice #12345'
  });
  if (result.success) {
    console.log(`  ✅ Transfer complete! New balance: $${result.new_balance.toLocaleString()}`);
    console.log(`  📜 Attestation: ${result.attestation_id}\n`);
  }

  // ❌ Huge transfer - DENIED (exceeds $10,000 limit)
  console.log('→ Attempting $50,000 transfer (SHOULD FAIL)...');
  result = await callAPI(corpTreasury.passport, 'transfer', {
    from_account: 'acct_corp',
    to_account: 'acct_bob',
    amount: 50000,
    memo: 'Big vendor payment'
  });
  if (result.error) {
    console.log(`  🚫 DENIED: ${result.error}`);
    console.log(`     Your limit: $${result.your_limit.toLocaleString()}, Requested: $${result.requested.toLocaleString()}\n`);
  }

  // ═══════════════════════════════════════════════════════════════
  // SCENARIO 4: Agent with NO transfer permissions
  // ═══════════════════════════════════════════════════════════════
  
  divider("SCENARIO 4: Read-Only Agent Tries to Transfer");
  
  const readOnlyAgent = await Agent.create('bob-viewer', {
    permissions: ['payments:read_balance']  // No transfer permission!
  });
  
  console.log('Agent: bob-viewer');
  console.log('Owner: Bob');
  console.log('Permissions: read_balance ONLY (no transfers)\n');

  // ✅ Can read balance
  console.log('→ Checking Bob\'s balance...');
  result = await callAPI(readOnlyAgent.passport, 'read_balance', { 
    account_id: 'acct_bob' 
  });
  if (result.balance !== undefined) {
    console.log(`  ✅ Balance: $${result.balance.toLocaleString()}`);
    console.log(`  📜 Attestation: ${result.attestation_id}\n`);
  }

  // ❌ Cannot transfer - no permission
  console.log('→ Attempting ANY transfer (SHOULD FAIL)...');
  result = await callAPI(readOnlyAgent.passport, 'transfer', {
    from_account: 'acct_bob',
    to_account: 'acct_alice',
    amount: 1,  // Even $1!
    memo: 'Tiny transfer'
  });
  if (result.error) {
    console.log(`  🚫 DENIED: ${result.error}`);
    console.log(`     Code: ${result.code}\n`);
  }

  // ═══════════════════════════════════════════════════════════════
  // SUMMARY
  // ═══════════════════════════════════════════════════════════════
  
  divider("WHAT UNIPLEX PREVENTED");
  
  console.log(`
  Without Uniplex, these AI agents could have:

  ❌ Alice's assistant transferring $500 (blocked: limit is $100)
  ❌ Alice's assistant accessing Bob's account (blocked: wrong owner)
  ❌ Alice's assistant stealing from Bob (blocked: wrong owner)
  ❌ Corp treasury transferring $50,000 (blocked: limit is $10,000)
  ❌ Read-only agent transferring money (blocked: no permission)

  With Uniplex:

  ✅ Every action is authorized before execution
  ✅ Permissions are scoped (read vs transfer, amount limits)
  ✅ Accounts are isolated by owner
  ✅ Every decision has a signed attestation for audit
  ✅ Compliance teams can prove exactly what was allowed

  Total prevented: $50,551 in unauthorized transfers
  `);

  console.log('═'.repeat(65));
  console.log('  Check server logs for full audit trail');
  console.log('═'.repeat(65) + '\n');
}

main().catch(console.error);
