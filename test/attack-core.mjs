// ATTACK SUITE (core): a hostile ledger server, hostile sign requests, and fuzzing.
// Every check is phrased as "the app survives / refuses / stays honest".
import * as core from '../src/core.js';
// Offline tests: never open a real WebSocket. (Default transport is read at call time.)
globalThis.WebSocket = undefined;
import { encode } from 'ripple-binary-codec';
import { classicAddressToXAddress } from 'ripple-address-codec';

let fails = 0;
const results = [];
const check = (c, m) => { console.log(`${c ? 'PASS' : 'FAIL'} ${m}`); results.push([c, m]); if (!c) fails++; };
const O = 'rf1XWa1W3C1X59LRX2zHz47MERqoShutF5';
const D = 'r3eLwV1LwtJCmcY6pfFvWxHgsuibViXqbo';
const D2 = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';
const XADDR = classicAddressToXAddress(O, 12345, false); // computed by the codec, not typed by hand
const time = async (f) => { const t = Date.now(); const r = await f(); return [r, Date.now() - t]; };

// Build a fake JSON-RPC server: handler(method, params, callNo) -> result object
function server(handler) {
  let n = 0;
  const calls = [];
  const fetchImpl = async (url, opts) => {
    const body = JSON.parse(opts.body);
    const p = body.params[0];
    calls.push([url, body.method, p]);
    const result = await handler(body.method, p, n++, url);
    return { ok: true, status: 200, json: async () => ({ result }) };
  };
  return { fetchImpl, calls };
}
const okAccount = (extra = {}) => ({ status: 'success', account_data: { Account: O, Balance: '50000000', Sequence: 7, ...extra }, ledger_index: 100 });
const base = (objs, opts = {}) => (method, p) => {
  if (method === 'account_info') return okAccount(opts.acct);
  if (method === 'account_objects') return { status: 'success', account_objects: objs, ledger_index: 100 };
  if (method === 'account_tx') return { status: 'success', transactions: opts.txs || [] };
  return { status: 'success' };
};

// ---------------------------------------------------------------- 1. malformed / hostile Delegate objects
{
  const hostile = [
    { LedgerEntryType: 'Delegate', index: 'A1', Account: O, Authorize: D, Permissions: 'Payment' },                // not an array
    { LedgerEntryType: 'Delegate', index: 'A2', Account: O, Authorize: D2, Permissions: [null, {}, { Permission: null }, { Permission: { PermissionValue: { evil: 1 } } }] },
    { LedgerEntryType: 'Delegate', index: 'A3', Account: O, Authorize: '<img src=x onerror=alert(1)>', Permissions: [{ Permission: { PermissionValue: 'Payment' } }] },
    { LedgerEntryType: 'Delegate', index: 'A4', Account: 'rNOTREAL', Authorize: D, Permissions: [] },
    null, 42, 'string',
  ];
  let err = null; let r;
  try { r = await core.scanAccount(core.makeRpc('mainnet', server(base(hostile)).fetchImpl), O, { history: false }); } catch (e) { err = e; }
  check(!err, `hostile Delegate objects do not crash the scan${err ? ': ' + err.message : ''}`);
  if (r) {
    check(!r.granted.some((g) => !core.isAddress(g.delegate)), 'objects with a fake address are dropped, never shown');
    const all = r.granted.flatMap((g) => g.perms.map((p) => p.name));
    check(all.every((n) => typeof n === 'string' && n.length < 80), `permission names are plain short strings (${JSON.stringify(all).slice(0, 120)})`);
    const a1 = r.granted.find((g) => g.index === 'A1');
    check(!a1 || a1.perms.length === 0 || a1.perms.every((p) => p.name !== 'P'), 'a string "Permissions" field is not split into letters');
  }
}

// ---------------------------------------------------------------- 2. spoofed text: bidi / zero-width / control chars in Domain
{
  const spoof = Buffer.from('moc.elppir‮evil.io​\u0007', 'utf8').toString('hex').toUpperCase();
  const s = server((m, p) => (m === 'account_info' ? okAccount({ Domain: spoof }) : base([{ LedgerEntryType: 'Delegate', index: 'B', Account: O, Authorize: D, Permissions: [{ Permission: { PermissionValue: 'Payment' } }] }])(m, p)));
  const r = await core.scanAccount(core.makeRpc('mainnet', s.fetchImpl), O, { history: false });
  const dom = r.granted[0].delegateInfo.domain;
  check(!/[‪-‮⁦-⁩​-‏\u0000-\u001F]/.test(dom), `delegate "domain" is stripped of right-to-left/invisible tricks (${JSON.stringify(dom)})`);
}

// ---------------------------------------------------------------- 3. endless pages / stuck markers
{
  const [r1, ms1] = await time(() => core.scanAccount(core.makeRpc('mainnet', server((m, p) => {
    if (m === 'account_info') return okAccount();
    if (m === 'account_objects') return { status: 'success', account_objects: [], marker: 'SAME', ledger_index: 100 };
    return { status: 'success', transactions: [] };
  }).fetchImpl), O, { history: false }));
  check(r1.truncated === true && ms1 < 5000, `stuck account_objects marker stops (truncated, ${ms1} ms)`);

  const s = server((m) => {
    if (m === 'account_info') return okAccount();
    if (m === 'account_objects') return { status: 'success', account_objects: [], ledger_index: 100 };
    return { status: 'success', transactions: [{ hash: 'A'.repeat(64), tx_json: { Account: O, TransactionType: 'AccountSet' } }], marker: 'M' };
  });
  const [r2, ms2] = await time(() => core.scanAccount(core.makeRpc('mainnet', s.fetchImpl), O, { since: 1 }));
  const pages = s.calls.filter((c) => c[1] === 'account_tx').length;
  check(pages <= 60 && r2.activity.complete === false, `a server feeding 1 transaction per page cannot keep the scan busy forever (${pages} pages, ${ms2} ms)`);

  const big = Array.from({ length: 50000 }, (_, i) => ({ hash: 'B'.repeat(64), tx_json: { Account: O, Delegate: D, TransactionType: 'Payment', Amount: '1', Destination: D } }));
  const [r3] = await time(() => core.scanAccount(core.makeRpc('mainnet', server((m) => {
    if (m === 'account_info') return okAccount();
    if (m === 'account_objects') return { status: 'success', account_objects: [], ledger_index: 100 };
    return { status: 'success', transactions: big };
  }).fetchImpl), O, { since: 1 }));
  check(r3.activity.found.length <= 4000, `a server ignoring "limit" cannot flood the page (kept ${r3.activity.found.length})`);
}

// ---------------------------------------------------------------- 4. hostile activity fields
{
  const r = await core.scanAccount(core.makeRpc('mainnet', server((m) => {
    if (m === 'account_info') return okAccount();
    if (m === 'account_objects') return { status: 'success', account_objects: [], ledger_index: 100 };
    return { status: 'success', transactions: [
      { hash: 'javascript:alert(1)', tx_json: { Account: O, Delegate: D, TransactionType: 'Payment<svg>', Amount: 'unavailable', Destination: '"><script>' } },
      { hash: 'C'.repeat(64), tx_json: { Account: O, Delegate: '<b>', TransactionType: 'Payment', Amount: { value: '<img>', currency: 'USD', issuer: D } } },
    ] };
  }).fetchImpl), O, { since: 1 });
  const f = r.activity.found;
  check(f.every((a) => /^[0-9A-F]{64}$/.test(a.hash)), 'transaction hashes that are not real hashes are dropped (no fake links)');
  check(f.every((a) => core.isAddress(a.delegate)), 'activity rows with a fake delegate address are dropped');
}

// ---------------------------------------------------------------- 5. autofill from a hostile server
{
  const s = server((m) => {
    if (m === 'account_info') return okAccount({ Sequence: 'abc' });
    if (m === 'ledger_current') return { status: 'success', ledger_current_index: -5 };
    if (m === 'fee') return { status: 'success', drops: { open_ledger_fee: '999999999' } };
    return { status: 'success' };
  });
  let err = null; let tx;
  try { tx = await core.autofill(core.makeRpc('mainnet', s.fetchImpl), core.buildRevoke(O, D), 1000); } catch (e) { err = e; }
  check(!!err || (Number.isInteger(tx.Sequence) && tx.Sequence > 0 && tx.LastLedgerSequence > 0), `garbage Sequence / ledger index from a server is refused (${err ? err.message : JSON.stringify(tx)})`);
  if (tx) check(Number(tx.Fee) <= 1000, 'a server demanding a huge fee is capped at the user limit');
}

// ---------------------------------------------------------------- 6. lying "validated" answer
{
  const s = server((m) => (m === 'tx' ? { status: 'success', validated: true, meta: { TransactionResult: 'tesSUCCESS' }, tx_json: { TransactionType: 'DelegateSet', Account: O, Authorize: D, Permissions: [], Fee: '10' } } : { status: 'success' }));
  const probs = await core.verifyOnLedger(core.makeRpc('mainnet', s.fetchImpl), 'D'.repeat(64), O, D, 1000);
  check(Array.isArray(probs), 'ledger verification runs against what the server says');
  check(typeof core.verifyOnBothServers === 'function', 'after signing, the revoke can be confirmed on a SECOND independent server (one lying server cannot fake success)');
}

// ---------------------------------------------------------------- 7. sign-request decoder attacks
{
  // deep nesting
  let nested = { TransactionType: 'Payment', Account: O, Destination: D, Amount: '1' };
  for (let i = 0; i < 5000; i++) nested = { TransactionType: 'Batch', Account: O, RawTransactions: [{ RawTransaction: nested }] };
  let err = null; let lvl;
  try { lvl = core.overallLevel(core.explainTx(nested)); } catch (e) { err = e; }
  check(!err || !/call stack/i.test(err.message), `a batch nested 5,000 deep is handled, not a crash (${err ? err.message : lvl})`);

  // huge input
  const huge = '{"TransactionType":"Payment","Memos":[' + '{"Memo":{"MemoData":"00"}},'.repeat(200000) + '{}]}';
  let e2 = null; const t0 = Date.now();
  try { core.parseSignRequest(huge); } catch (e) { e2 = e; }
  check(!!e2 && /too (large|long|big)/i.test(e2.message), `a multi-megabyte paste is refused up front (${(huge.length / 1e6).toFixed(1)} MB, ${Date.now() - t0} ms)`);

  // weird shapes
  const weird = [
    { TransactionType: 123 }, { TransactionType: { a: 1 } }, { TransactionType: 'DelegateSet', Permissions: 'x' },
    { TransactionType: 'Batch', RawTransactions: 'x' }, { TransactionType: 'Batch', RawTransactions: [null, 1, {}] },
    { TransactionType: 'Payment', Amount: 12345 }, [], null, 'str',
  ];
  let crashes = 0;
  for (const w of weird) { try { core.explainTx(w); } catch { crashes++; } }
  check(crashes === 0, `odd-shaped transactions never crash the explainer (${crashes} crashed)`);

  // dangerous types the decoder must not wave through
  const disableMaster = core.overallLevel(core.explainTx({ TransactionType: 'AccountSet', Account: O, SetFlag: 4 }));
  check(disableMaster === 'critical', `AccountSet that DISABLES THE MASTER KEY is Critical (got ${disableMaster})`);
  const giveNft = core.overallLevel(core.explainTx({ TransactionType: 'NFTokenCreateOffer', Account: O, NFTokenID: '0'.repeat(64), Amount: '0', Flags: 1, Destination: D }));
  check(giveNft === 'critical', `selling an NFT for 0 to a set destination (giving it away) is Critical (got ${giveNft})`);
  const escrow = core.explainTx({ TransactionType: 'EscrowCreate', Account: O, Destination: D, Amount: '100000000' });
  check(core.overallLevel(escrow) !== 'medium' && escrow.findings.some((f) => f.text.includes('100')), 'EscrowCreate shows the amount and destination and is not "medium"');
  const chan = core.explainTx({ TransactionType: 'PaymentChannelCreate', Account: O, Destination: D, Amount: '100000000', PublicKey: 'ED' + '0'.repeat(64), SettleDelay: 1 });
  check(core.overallLevel(chan) === 'high', `PaymentChannelCreate is High (got ${core.overallLevel(chan)})`);
  const memo = core.explainTx({ TransactionType: 'TrustSet', Account: O, LimitAmount: { currency: 'USD', issuer: D, value: '1' },
    Memos: [{ Memo: { MemoData: Buffer.from('Claim your reward at https://evil.example').toString('hex') } }] });
  check(memo.findings.some((f) => /memo/i.test(f.text) && /link|website|https?:/i.test(f.text)), 'a memo carrying a web link is shown and warned about');
  const partial = core.explainTx({ TransactionType: 'Payment', Account: O, Destination: D, Amount: '1000000000', Flags: 131072 });
  check(partial.findings.some((f) => /partial/i.test(f.text)), 'a partial-payment flag is pointed out');
  const ticket = core.explainTx({ TransactionType: 'AccountSet', Account: O, SetFlag: 16 });
  check(core.overallLevel(ticket) !== 'low', 'AccountSet enabling clawback is not called low-risk');

  // fuzz: random hex blobs
  let fuzzCrashOutsideParse = 0;
  for (let i = 0; i < 3000; i++) {
    const len = 2 * (1 + Math.floor(Math.random() * 200));
    const hex = Array.from({ length: len }, () => '0123456789ABCDEF'[Math.floor(Math.random() * 16)]).join('');
    let tx;
    try { tx = core.parseSignRequest(hex); } catch { continue; }
    try { core.overallLevel(core.explainTx(tx)); } catch { fuzzCrashOutsideParse++; }
  }
  check(fuzzCrashOutsideParse === 0, `3,000 random blobs: anything that decodes is explained without crashing (${fuzzCrashOutsideParse} crashes)`);

  // fuzz: mutated real transactions
  const realOnes = [
    { TransactionType: 'DelegateSet', Account: O, Authorize: D, Permissions: [{ Permission: { PermissionValue: 'Payment' } }], Fee: '10', Sequence: 1 },
    { TransactionType: 'Batch', Account: O, Flags: 65536, Fee: '10', Sequence: 1, RawTransactions: [{ RawTransaction: { TransactionType: 'Payment', Account: O, Destination: D, Amount: '1', Flags: 1073741824, Fee: '0', Sequence: 2, SigningPubKey: '' } }] },
  ];
  let mutCrash = 0; let mutTried = 0;
  for (const r of realOnes) {
    const hex = encode(r);
    for (let i = 0; i < 2000; i++) {
      const pos = Math.floor(Math.random() * hex.length);
      const m = hex.slice(0, pos) + '0123456789ABCDEF'[Math.floor(Math.random() * 16)] + hex.slice(pos + 1);
      let tx; try { tx = core.parseSignRequest(m); } catch { continue; }
      mutTried++;
      try { core.overallLevel(core.explainTx(tx)); } catch { mutCrash++; }
    }
  }
  check(mutCrash === 0, `4,000 single-character corruptions of real blobs: ${mutTried} decoded, ${mutCrash} crashed the explainer`);
}

// ---------------------------------------------------------------- 7b. round two: real XRPL scam patterns
{
  const ticket = core.explainTx({ TransactionType: 'Payment', Account: O, Destination: D, Amount: '5000000', TicketSequence: 77, Sequence: 0, Fee: '12' });
  check(core.overallLevel(ticket) === 'high' && ticket.findings.some((f) => /no expiry/i.test(f.text)), 'a pre-signed ticketed transaction with no expiry is flagged (can be submitted months later)');
  const drain = core.explainTx({ TransactionType: 'AccountSet', Account: O, Fee: '25000000000', LastLedgerSequence: 9 });
  check(core.overallLevel(drain) === 'critical', `a 25,000 XRP "fee" is Critical (got ${core.overallLevel(drain)})`);
  const eleven = core.explainTx({ TransactionType: 'DelegateSet', Account: O, Authorize: D, LastLedgerSequence: 9,
    Permissions: [...Array(10).fill(0).map((_, i) => ({ Permission: { PermissionValue: 'AccountDomainSet' } })), { Permission: { PermissionValue: 'Payment' } }] });
  check(core.overallLevel(eleven) === 'critical', 'a DelegateSet listing 11 permissions (hiding Payment as #11) is Critical');
  const normal = core.explainTx({ TransactionType: 'DelegateSet', Account: O, Authorize: D, Permissions: [], Fee: '10', Sequence: 3, LastLedgerSequence: 99 });
  check(core.overallLevel(normal) === 'low', 'a normal revoke with an expiry still reads Low (no false alarm)');
  check(core.overallLevel(core.explainTx(core.buildRevoke(O, D))) === 'low', 'the bare revoke users copy into Xaman reads Low (no false alarm)');
  const signedNoExpiry = core.explainTx({ TransactionType: 'Payment', Account: O, Destination: D, Amount: '1', Sequence: 5, Fee: '12', TxnSignature: 'AB' });
  check(signedNoExpiry.findings.some((f) => /already SIGNED/.test(f.text)), 'an already-signed transaction with no expiry is flagged');
}
{
  // cancellation: an older history scan stops when asked
  let pages = 0; const signal = { aborted: false };
  const s = server((m) => { pages++; if (pages === 3) signal.aborted = true; return { status: 'success', transactions: [{ hash: 'A'.repeat(64), tx_json: { Account: O, TransactionType: 'AccountSet' } }], marker: 'M' }; });
  const r = await core.scanActivity(core.makeRpc('mainnet', s.fetchImpl), O, { since: 1, signal });
  check(r.aborted === true && pages <= 4, `an abandoned history check stops right away (${pages} pages, then stopped)`);
}

// ---------------------------------------------------------------- 8. address input tricks
{
  const zw = O.slice(0, 5) + '​' + O.slice(5);
  check(!core.isAddress(zw), 'an address with a hidden zero-width character is rejected');
  check(typeof core.cleanAddressInput === 'function' && /hidden|invisible/i.test(core.cleanAddressInput(zw).warning || ''), 'and the user is told it contained hidden characters');
  check(typeof core.cleanAddressInput === 'function' && core.cleanAddressInput(XADDR).address === O && core.cleanAddressInput(XADDR).tag === 12345, 'an X-address is converted to its classic r-address');
}

console.log(fails ? `\n${fails} FAILED of ${results.length}` : `\nALL ${results.length} PASSED`);
process.exit(fails ? 1 : 0);
