// Offline unit tests for the security checks and decoder.
import * as core from '../src/core.js';
// Offline tests: never open a real WebSocket. (Default transport is read at call time.)
globalThis.WebSocket = undefined;

let fails = 0;
const check = (c, m) => { console.log(`${c ? 'PASS' : 'FAIL'} ${m}`); if (!c) fails++; };
const O = 'rf1XWa1W3C1X59LRX2zHz47MERqoShutF5';
const D = 'r3eLwV1LwtJCmcY6pfFvWxHgsuibViXqbo';
const good = { TransactionType: 'DelegateSet', Account: O, Authorize: D, Permissions: [], Sequence: 5, Fee: '10', LastLedgerSequence: 100 };

check(core.verifyRevokeTx(good, O, D, 1000).length === 0, 'clean revoke passes strict check');
check(core.verifyRevokeTx({ ...good, Permissions: [{ Permission: { PermissionValue: 'Payment' } }] }, O, D, 1000).some((p) => /GRANT/.test(p)), 'grant disguised as revoke is blocked');
check(core.verifyRevokeTx({ ...good, Authorize: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh' }, O, D, 1000).length > 0, 'swapped delegate is blocked');
check(core.verifyRevokeTx({ ...good, Account: D }, O, D, 1000).length > 0, 'swapped account is blocked');
check(core.verifyRevokeTx({ ...good, Fee: '2000' }, O, D, 1000).some((p) => /Fee/.test(p)), 'fee above limit is blocked');
check(core.verifyRevokeTx({ ...good, Memos: [] }, O, D, 1000).some((p) => /Unexpected/.test(p)), 'extra fields are blocked');
check(core.verifyRevokeTx({ ...good, TransactionType: 'Payment' }, O, D, 1000).length > 0, 'wrong type is blocked');

check(core.classifyPermission('Payment').level === 'critical', 'Payment = Critical');
check(core.classifyPermission('OfferCreate').level === 'high', 'OfferCreate = High');
check(core.classifyPermission('AccountDomainSet').level === 'low', 'AccountDomainSet = Low');
check(core.classifyPermission('PaymentBurn').level === 'high', 'PaymentBurn = High');

const ex = core.explainTx({ TransactionType: 'AccountDelete', Account: O, Destination: D });
check(core.overallLevel(ex) === 'critical' && ex.findings.some((f) => f.text.includes(D)), 'AccountDelete flagged Critical with destination');
check(core.overallLevel(core.explainTx(core.buildRevoke(O, D))) === 'low', 'revoke reads Low');
let threw = false; try { core.parseSignRequest('zz'); } catch { threw = true; } check(threw, 'junk input rejected');
check(core.currencyText('534F4C4F00000000000000000000000000000000') === 'SOLO', 'hex currency decoded');
check(!core.isAddress('rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTX'), 'bad checksum address rejected');

const fpA = core.delegateFingerprint([{ LedgerEntryType: 'Delegate', index: 'A', Account: O, Authorize: D, Permissions: [{ Permission: { PermissionValue: 'Payment' } }] }]);
const fpB = core.delegateFingerprint([{ LedgerEntryType: 'Delegate', index: 'A', Account: O, Authorize: D, Permissions: [{ Permission: { PermissionValue: 'TrustSet' } }] }]);
check(fpA !== fpB, 'cross-check fingerprint detects a changed permission');

// rate-limit JSON error must be retried / failed over, not treated as an answer (found by the Mainnet backtest)
{
  core.resetRpcState();
  let n = 0;
  const fake = async () => ({ ok: true, status: 200, json: async () => (n++ === 0
    ? { result: { status: 'error', error: 'slowDown', error_message: 'rate limit: units quota (2000 per 10s) exhausted, retry in ~10ms' } }
    : { result: { status: 'success', ledger_index: 5 } }) });
  const r = await core.makeRpc('mainnet', fake)('ledger', {});
  check(r.ledger_index === 5 && n === 2, 'rate-limit JSON reply is retried, then the real answer is used');
  core.resetRpcState();
  let m = 0; const hosts = new Set();
  const fake2 = async (url) => ({ ok: true, status: 200, json: async () => { m++; hosts.add(url); return { result: { status: 'error', error: 'whatever', error_message: 'rate limit: units quota exhausted, retry in ~5ms' } }; } });
  let msg = ''; try { await core.makeRpc('mainnet', fake2)('ledger', {}); } catch (e) { msg = e.message; }
  check(msg.startsWith('No ledger server could be reached') && hosts.size === 2 && m <= 12, `persistent rate limit fails over across both servers (${m} tries on ${hosts.size} servers) and reports clearly`);
  // quota awareness: a server reporting an almost-empty quota is rested; the other server is used instead
  core.resetRpcState();
  const used = [];
  const fake4 = async (url) => { used.push(url); return { ok: true, status: 200,
    headers: { get: (h) => (h === 'RateLimit-Remaining' ? (url.includes('xrplcluster') ? '5' : '1900') : h === 'RateLimit-Reset' ? '8' : null) },
    json: async () => ({ result: { status: 'success', ok: 1 } }) }; };
  const rq = core.makeRpc('mainnet', fake4);
  for (let i = 0; i < 5; i++) await rq('ping', {});
  const toCluster = used.filter((u) => u.includes('xrplcluster')).length;
  check(toCluster === 1 && used.length === 5, `a server reporting it is almost out of quota is rested and the other server takes over (${toCluster} of ${used.length} calls went to the tired server)`);
  core.resetRpcState();
  const fake3 = async () => ({ ok: true, status: 200, json: async () => ({ result: { status: 'error', error: 'actNotFound', error_message: 'Account not found.' } }) });
  let code = ''; try { await core.makeRpc('mainnet', fake3)('account_info', {}); } catch (e) { code = e.code; }
  check(code === 'actNotFound', 'a real ledger answer (account not found) is still returned immediately');
}

console.log(fails ? `${fails} FAILED` : 'ALL PASSED');
process.exit(fails ? 1 : 0);
