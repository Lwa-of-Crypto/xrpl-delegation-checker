// End-to-end test on XRPL Testnet: grant → misuse → scan → revoke → re-scan.
import { ProxyAgent, setGlobalDispatcher } from 'undici';
import xrpl from 'xrpl';
import * as core from '../src/core.js';

if (process.env.HTTPS_PROXY) setGlobalDispatcher(new ProxyAgent(process.env.HTTPS_PROXY));
const rpc = core.makeRpc('testnet');
const log = (...a) => console.log(...a);
let failures = 0;
const check = (cond, msg) => { log(`${cond ? 'PASS' : 'FAIL'} ${msg}`); if (!cond) failures++; };

async function fund() {
  for (let i = 0; i < 5; i++) {
    const r = await fetch('https://faucet.altnet.rippletest.net/accounts', { method: 'POST',
      headers: { 'Content-Type': 'application/json' }, body: '{}' });
    if (r.ok) { const j = await r.json(); return xrpl.Wallet.fromSeed(j.seed); }
    await new Promise((s) => setTimeout(s, 3000));
  }
  throw new Error('faucet failed');
}

async function submit(wallet, tx, label) {
  const filled = tx.Sequence ? tx : await core.autofill(rpc, tx);
  const { tx_blob, hash } = wallet.sign(filled);
  const r = await rpc('submit', { tx_blob });
  const v = await core.waitForValidation(rpc, hash);
  log(`  ${label}: engine=${r.engine_result} final=${v.result} ${hash}`);
  return { engine: r.engine_result, final: v.result, hash, tx_blob };
}

const owner = await fund();
const helper = await fund();
const attacker = await fund();
log('owner', owner.address, '\nhelper', helper.address, '\nattacker', attacker.address);
await new Promise((s) => setTimeout(s, 5000)); // let faucet payments validate

// 1. Grant two delegations
const g1 = await submit(owner, { TransactionType: 'DelegateSet', Account: owner.address, Authorize: helper.address,
  Permissions: [{ Permission: { PermissionValue: 'AccountDomainSet' } }] }, 'grant helper AccountDomainSet');
const g2 = await submit(owner, { TransactionType: 'DelegateSet', Account: owner.address, Authorize: attacker.address,
  Permissions: [{ Permission: { PermissionValue: 'Payment' } }, { Permission: { PermissionValue: 'TrustSet' } }] },
  'grant attacker Payment+TrustSet');
check(g1.final === 'tesSUCCESS' && g2.final === 'tesSUCCESS', 'both grants validated');

// 2. Attacker uses the power: payment FROM owner TO attacker, signed by attacker
const ownerInfo = await rpc('account_info', { account: owner.address, ledger_index: 'current' });
const cur = await rpc('ledger_current', {});
const steal = await submit(attacker, { TransactionType: 'Payment', Account: owner.address, Delegate: attacker.address,
  Destination: attacker.address, Amount: '5000000', Sequence: ownerInfo.account_data.Sequence, Fee: '12',
  LastLedgerSequence: cur.ledger_current_index + 20 }, 'delegated payment 5 XRP owner→attacker');
check(steal.final === 'tesSUCCESS', 'delegate really can move the owner\'s XRP (risk is real)');

// 3. Scan
const s1 = await core.scanAccount(rpc, owner.address);
log(JSON.stringify(s1.granted.map((g) => ({ d: g.delegate, level: g.level, p: g.perms.map((p) => p.name) }))));
check(s1.granted.length === 2, 'scan finds 2 delegations');
check(s1.granted[0].delegate === attacker.address && s1.granted[0].level === 'critical', 'attacker ranked first as critical');
check(s1.activity.found.length === 1 && s1.activity.found[0].delegate === attacker.address, 'scan finds the delegated payment in history');
const s1b = await core.scanAccount(rpc, attacker.address, { history: false });
check(s1b.received.length === 1 && s1b.received[0].owner === owner.address, 'attacker side shows received power');

// 4. Decoder on the real signed grant blob
const ex = core.explainTx(core.parseSignRequest(g2.tx_blob));
check(core.overallLevel(ex) === 'critical' && ex.type === 'DelegateSet', 'decoder flags the grant blob as critical');

// 5. Revoke
const rv = await submit(owner, core.buildRevoke(owner.address, attacker.address), 'revoke attacker');
check(rv.final === 'tesSUCCESS', 'revoke validated');
const exr = core.explainTx(core.parseSignRequest(rv.tx_blob));
check(core.overallLevel(exr) === 'low', 'decoder reads revoke blob as the safe take-back');

const s2 = await core.scanAccount(rpc, owner.address, { history: false });
check(s2.granted.length === 1 && s2.granted[0].delegate === helper.address, 're-scan: attacker gone, helper remains');

// 6. Attacker tries again — must fail
const info2 = await rpc('account_info', { account: owner.address, ledger_index: 'current' });
const cur2 = await rpc('ledger_current', {});
const filled = { TransactionType: 'Payment', Account: owner.address, Delegate: attacker.address,
  Destination: attacker.address, Amount: '1000000', Sequence: info2.account_data.Sequence, Fee: '12',
  LastLedgerSequence: cur2.ledger_current_index + 20 };
const { tx_blob } = attacker.sign(filled);
const retry = await rpc('submit', { tx_blob });
log('  retry engine_result:', retry.engine_result);
check(retry.engine_result !== 'tesSUCCESS', 'after revoke the attacker can no longer pay from owner');

// 7. Owner reserve released
const before = s1.self; const after = await rpc('account_info', { account: owner.address, ledger_index: 'validated' });
log('  owner OwnerCount now', after.account_data.OwnerCount);
check(after.account_data.OwnerCount === 1, 'OwnerCount back to 1 (one 0.2 XRP reserve freed)');

// 8. Mainnet read-only sanity
const mrpc = core.makeRpc('mainnet');
const m = await core.scanAccount(mrpc, 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', { history: false });
check(m.exists === true && Array.isArray(m.granted), `mainnet scan works (genesis account, ${m.granted.length} delegations)`);

log(`\n${failures === 0 ? 'ALL PASSED' : failures + ' FAILED'}`);
process.exit(failures ? 1 : 0);
