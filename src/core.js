// XRPL Delegation Checker — core logic (no UI).
// Created by Stanley Gebara · CryptoLwa (cryptolwa.io) · Open source (MIT).
// Reads public ledger data only. Never asks for, sees, or stores a secret key.
//
// Threat model: every byte that comes from a ledger server, a wallet extension or a pasted transaction
// is treated as hostile until checked. Nothing from outside is trusted for shape, type, size or content.

import { isValidClassicAddress, isValidXAddress, xAddressToClassicAddress } from 'ripple-address-codec';
import { decode as decodeBinary } from 'ripple-binary-codec';

export const NETWORKS = {
  mainnet: {
    label: 'XRPL Mainnet',
    // Main reads go to InFTF's full-history cluster (xrpl.ws is the SAME cluster under another name —
    // xrpl.org "Public Servers"; confirmed: both report the same node key). Ripple's cluster is the last-resort fallback.
    endpoints: ['https://xrplcluster.com/', 'https://xrpl.ws/', 'wss://s2.ripple.com/'],
    // Independent operators for the cross-check: answers are only compared ACROSS operators, never across
    // two names for the same cluster. WebSocket is used for Ripple and Honeycluster because their HTTPS
    // endpoints do not allow browser pages to read the answer (no CORS); WebSockets are not subject to CORS.
    operators: [
      { name: 'InFTF (xrplcluster.com)', urls: ['https://xrplcluster.com/', 'https://xrpl.ws/'] },
      { name: 'Ripple (s2/s1.ripple.com)', urls: ['wss://s2.ripple.com/', 'wss://s1.ripple.com/'] },
      { name: 'Honeycluster (honeycluster.io)', urls: ['wss://honeycluster.io/'] },
    ],
    // Ledger where PermissionDelegationV1_1 was enabled (EnableAmendment 0F48FF56…, 2026-10-08 21:29:50 UTC).
    // Read off the ledger itself. No delegated transaction can exist before it.
    delegationSince: 107524865,
    explorer: 'https://livenet.xrpl.org/transactions/',
    explorerAccount: 'https://livenet.xrpl.org/accounts/',
  },
  testnet: {
    label: 'XRPL Testnet',
    endpoints: ['https://testnet.xrpl-labs.com/'],
    operators: [{ name: 'XRPL Labs (testnet.xrpl-labs.com)', urls: ['https://testnet.xrpl-labs.com/'] }],
    delegationSince: null, // Testnet history is reset from time to time; search all of it (up to the cap).
    explorer: 'https://testnet.xrpl.org/transactions/',
    explorerAccount: 'https://testnet.xrpl.org/accounts/',
  },
};

// ---------------------------------------------------------------- limits (attack-suite findings)
export const LIMITS = Object.freeze({
  rpcDeadlineMs: 40000,      // one ledger question never takes longer than this, however busy the servers are
  secondOpinionMs: 10000,    // a cross-check question to an independent operator: quick or skipped
  objectPages: 50,           // account_objects pages
  activityMaxTx: 4000,       // transactions searched for delegate activity
  activityMaxPages: 40,      // a server feeding 1 tx per page cannot keep the scan busy forever
  activityMaxFound: 4000,    // a server ignoring "limit" cannot flood the page
  pasteMaxChars: 1_000_000,  // the sign-request checker refuses anything bigger
  batchMaxDepth: 3,          // real batches cannot nest; anything deeper is shown as suspicious, not recursed
  batchMaxInner: 50,
  permissionsPerDelegate: 10, // the ledger allows at most 10
  textMax: 200,              // any server-provided text shown on screen is cut to this length
});

// ---------------------------------------------------------------- safe helpers for hostile data
const HASH_RE = /^[0-9A-F]{64}$/i;
export const isHash = (h) => typeof h === 'string' && HASH_RE.test(h);
const isUint32 = (n) => Number.isInteger(n) && n > 0 && n <= 0xFFFFFFFF;
const asArray = (v) => (Array.isArray(v) ? v : []);

// Removes characters that can disguise text on screen: right-to-left overrides, zero-width marks,
// control characters. Then cuts the text to a sane length. Used on ALL server-provided text.
// eslint-disable-next-line no-control-regex
const DISGUISE_RE = /[\u0000-\u001F\u007F-\u009F­؜ᅟᅠ឴឵᠎​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ￰-￿]/g;
export function safeText(v, max = LIMITS.textMax) {
  if (v === undefined || v === null) return '';
  const s = (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : '').replace(DISGUISE_RE, '');
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

// ---------------------------------------------------------------- RPC
const BUSY_CODES = new Set(['slowDown', 'tooBusy', 'noNetwork', 'noCurrent', 'noClosed', 'notReady', 'notSynced', 'internal']);
const sleep = (ms) => new Promise((s) => setTimeout(s, ms));

// Shared knowledge about each public server: when it asked us to back off, and how much of its request
// quota is left. The servers publish their quota in RateLimit-* headers (readable from a web page), so the
// tool slows down BEFORE running out instead of hitting the wall. (Mainnet backtest finding, round 2.)
const SERVER = new Map(); // url -> { coolUntil, remaining, resetAt }
const serverState = (url) => { if (!SERVER.has(url)) SERVER.set(url, { coolUntil: 0, remaining: Infinity, resetAt: 0 }); return SERVER.get(url); };
export function resetRpcState() { SERVER.clear(); }
const LOW_QUOTA = 150;

function readQuota(url, res) {
  try {
    const h = res && res.headers && typeof res.headers.get === 'function' ? res.headers : null;
    if (!h) return;
    const rem = Number(h.get('RateLimit-Remaining'));
    const reset = Number(h.get('RateLimit-Reset'));
    const st = serverState(url);
    if (Number.isFinite(rem)) st.remaining = rem;
    if (Number.isFinite(reset) && reset >= 0 && reset < 3600) st.resetAt = Date.now() + reset * 1000;
  } catch { /* ignore */ }
}
const coolDown = (url, ms) => { const st = serverState(url); st.coolUntil = Math.max(st.coolUntil, Date.now() + ms); };
const readyAt = (url) => {
  const st = serverState(url);
  const quotaWait = st.remaining < LOW_QUOTA && st.resetAt > Date.now() ? st.resetAt : 0;
  return Math.max(st.coolUntil, quotaWait);
};

// One JSON-RPC-style question over a WebSocket (used for operators whose HTTPS endpoint has no CORS).
// Returns an object shaped like a fetch Response so the rest of the client treats both transports the same.
function wsRequest(url, method, params, WS, timeoutMs) {
  return new Promise((resolve, reject) => {
    let ws;
    const timer = setTimeout(() => { try { ws && ws.close(); } catch { /* ignore */ } reject(new Error(`${url} timed out`)); }, timeoutMs);
    try { ws = new WS(url); } catch (e) { clearTimeout(timer); reject(e); return; }
    ws.onopen = () => ws.send(JSON.stringify({ id: 1, command: method, api_version: 2, ...params }));
    ws.onerror = () => { clearTimeout(timer); reject(new Error(`${url} connection failed`)); };
    ws.onmessage = (ev) => {
      clearTimeout(timer);
      try { ws.close(); } catch { /* ignore */ }
      let m;
      try { m = JSON.parse(typeof ev.data === 'string' ? ev.data : String(ev.data)); } catch { reject(new Error(`${url} sent unreadable data`)); return; }
      if (!m || typeof m !== 'object') { reject(new Error(`${url} sent unreadable data`)); return; }
      const result = m.status === 'error' ? { status: 'error', error: m.error, error_message: m.error_message }
        : { ...(m.result && typeof m.result === 'object' ? m.result : {}), status: 'success' };
      resolve({ ok: true, status: 200, headers: null, json: async () => ({ result }) });
    };
  });
}

export function makeRpc(network, fetchImpl, onlyEndpoint = null, wsImpl) {
  return makeClient(onlyEndpoint ? [onlyEndpoint] : NETWORKS[network].endpoints, fetchImpl, wsImpl);
}

function makeClient(endpointList, fetchImpl = globalThis.fetch && globalThis.fetch.bind(globalThis), wsImpl = globalThis.WebSocket, deadlineMs = LIMITS.rpcDeadlineMs) {
  const endpoints = [...endpointList];
  return async function rpc(method, params = {}) {
    // Hard upper bound per question (attack-suite finding: with every server refusing, stacked retries kept a
    // scan spinning for minutes). Within it: use whichever server is ready, switch instantly when one is busy.
    const deadline = Date.now() + deadlineMs;
    const left = () => deadline - Date.now();
    let lastErr;
    for (let tries = 0; tries < 12 && left() > 0; tries++) {
      const now = Date.now();
      const url = [...endpoints].sort((x, y) => readyAt(x) - readyAt(y) || endpoints.indexOf(x) - endpoints.indexOf(y))[0];
      const wait = readyAt(url) - now;
      if (wait > 0) {
        if (wait >= left()) { lastErr = lastErr || new Error('every server asked us to wait'); break; }
        await sleep(wait);
      }
      let res;
      // Every single attempt has its own time limit, for both transports. (User report, 25 Oct 2026: a server
      // that accepted the connection but never answered left the scan on "Reading XRPL Mainnet…" forever,
      // because the deadline above is only checked between attempts.) The limit also covers reading the body.
      const attemptMs = Math.min(15000, Math.max(1000, left()));
      let attemptTimer = null;
      try {
        if (url.startsWith('wss://')) {
          if (!wsImpl) throw new Error('WebSocket not available');
          res = await wsRequest(url, method, params, wsImpl, attemptMs);
        } else {
          const ctrl = typeof AbortController === 'function' ? new AbortController() : null;
          const timedOut = new Promise((_, reject) => {
            attemptTimer = setTimeout(() => { const e = new Error(`${url} timed out`); reject(e); try { ctrl && ctrl.abort(e); } catch { /* ignore */ } }, attemptMs);
          });
          timedOut.catch(() => {}); // handled where it is awaited
          const raw = await Promise.race([fetchImpl(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ method, params: [{ api_version: 2, ...params }] }),
            ...(ctrl ? { signal: ctrl.signal } : {}),
          }), timedOut]);
          // Read the body inside the same time limit, then hand the rest of the code a ready answer.
          const body = raw && raw.ok && ![418, 429, 503].includes(raw.status) ? await Promise.race([raw.json(), timedOut]) : undefined;
          res = { ok: raw.ok, status: raw.status, headers: raw.headers, json: async () => { if (body === undefined) return raw.json(); return body; } };
        }
      } catch (netErr) {
        clearTimeout(attemptTimer);
        // A busy server's rate-limit reply often lacks CORS headers, which the browser reports as
        // "Failed to fetch". Treat it like a busy signal: rest this server, try the other.
        coolDown(url, 3000);
        lastErr = netErr;
        continue;
      }
      clearTimeout(attemptTimer);
      readQuota(url, res);
      if ([418, 429, 503].includes(res.status)) { coolDown(url, 3000); lastErr = new Error(`${url} was busy`); continue; }
      try {
        if (!res.ok) throw new Error(`${url} answered HTTP ${res.status}`);
        const body = await res.json();
        const r = body && typeof body === 'object' ? body.result : null;
        if (!r || typeof r !== 'object') throw new Error(`${url} returned no result`);
        if (r.status === 'error') {
          const msg = String(r.error_message || r.error || '');
          // Busy / rate-limited servers sometimes answer with a normal-looking JSON error
          // (Mainnet backtest: "rate limit: units quota ... retry in ~17505ms"). That is NOT an answer
          // about the account: rest this server for as long as it asked and use the other one meanwhile.
          if (BUSY_CODES.has(r.error) || /rate.?limit|slow.?down|too.?busy|quota/i.test(msg)) {
            const m = msg.match(/retry in ~?(\d+)\s*ms/i);
            coolDown(url, Math.min(m ? Number(m[1]) + 250 : 3000, 30000));
            lastErr = new Error(`${url} was busy`);
            continue;
          }
          // A real ledger answer (e.g. account not found) — do not retry elsewhere.
          const e = new Error(safeText(r.error_message || r.error));
          e.code = r.error;
          e.ledgerAnswer = true;
          throw e;
        }
        return r;
      } catch (e) {
        if (e.ledgerAnswer) throw e;
        coolDown(url, 2000);
        lastErr = e;
      }
    }
    throw new Error(`No ledger server could be reached right now (${safeText(lastErr && lastErr.message, 120) || 'timed out'}). Please try again in a minute.`);
  };
}

export function isAddress(s) {
  return typeof s === 'string' && isValidClassicAddress(s.trim());
}

// Cleans what a user pasted into the address box and explains anything suspicious.
// Returns { address, tag, warning } — address is null when it cannot be used.
export function cleanAddressInput(raw) {
  const original = String(raw || '');
  const visible = original.replace(DISGUISE_RE, '').trim();
  const hadHidden = visible !== original.trim();
  if (isValidXAddress(visible)) {
    try {
      const x = xAddressToClassicAddress(visible);
      return { address: x.classicAddress, tag: x.tag === false ? null : x.tag, xTest: x.test,
        warning: hadHidden ? 'Your paste contained hidden (invisible) characters. They were removed — check the address carefully.' : '' };
    } catch { /* fall through */ }
  }
  if (isAddress(visible)) {
    return { address: hadHidden ? null : visible, tag: null,
      warning: hadHidden ? 'This address contains hidden (invisible) characters. That is a known clipboard trick. Copy it again directly from your wallet app.' : '' };
  }
  return { address: null, tag: null,
    warning: hadHidden ? 'This contains hidden (invisible) characters and is not a valid XRPL address. Copy it again directly from your wallet app.' : '' };
}

// ---------------------------------------------------------------- permissions
// Granular permission names and wording: xrpl.org "Permission Values" reference.
const GRANULAR = {
  TrustlineAuthorize: ['medium', 'Can approve trust lines for tokens this account issues.'],
  TrustlineFreeze: ['medium', 'Can freeze individual trust lines for tokens this account issues.'],
  TrustlineUnfreeze: ['medium', 'Can unfreeze individual trust lines for tokens this account issues.'],
  AccountDomainSet: ['low', "Can change the account's Domain field."],
  AccountEmailHashSet: ['low', "Can change the account's EmailHash field."],
  AccountMessageKeySet: ['low', "Can change the account's MessageKey field."],
  AccountTransferRateSet: ['medium', 'Can change the transfer fee charged on tokens this account issues.'],
  AccountTickSizeSet: ['low', 'Can change the tick size of tokens this account issues.'],
  PaymentMint: ['high', 'Can send payments that create (mint) new tokens issued by this account.'],
  PaymentBurn: ['high', 'Can send payments that burn tokens issued by this account.'],
  MPTokenIssuanceLock: ['medium', 'Can lock balances of a Multi-Purpose Token this account issues.'],
  MPTokenIssuanceUnlock: ['medium', 'Can unlock balances of a Multi-Purpose Token this account issues.'],
};

// Transaction types that can move value out of, or tie up, the account.
const VALUE_MOVING = new Set([
  'OfferCreate', 'CheckCreate', 'CheckCash', 'EscrowCreate', 'EscrowFinish', 'EscrowCancel',
  'PaymentChannelCreate', 'PaymentChannelFund', 'PaymentChannelClaim',
  'NFTokenCreateOffer', 'NFTokenAcceptOffer', 'NFTokenBurn', 'NFTokenMint', 'NFTokenModify',
  'AMMCreate', 'AMMDeposit', 'AMMWithdraw', 'AMMBid', 'AMMDelete', 'AMMClawback', 'Clawback',
  'XChainCommit', 'XChainAccountCreateCommit', 'XChainClaim', 'TrustSet', 'DepositPreauth',
  'MPTokenAuthorize', 'MPTokenIssuanceCreate', 'MPTokenIssuanceDestroy', 'MPTokenIssuanceSet',
  'ConfidentialMPTSend', 'ConfidentialMPTConvertBack', 'ConfidentialMPTClawback',
  'SponsorshipSet', 'OfferCancel', 'CheckCancel',
]);

const RANK = { low: 1, medium: 2, high: 3, critical: 4 };
const NAME_RE = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;

export function classifyPermission(rawName) {
  // A permission name from the server is only trusted if it looks like a real identifier.
  if (typeof rawName !== 'string' || !NAME_RE.test(rawName)) {
    return { name: 'UnknownPermission', kind: 'unknown', level: 'high',
      plain: 'The server returned a permission this tool does not recognise. Treat it as dangerous and revoke if you did not set it up.' };
  }
  const name = rawName;
  if (name === 'Payment') {
    return { name, kind: 'transaction', level: 'critical',
      plain: 'Can send payments FROM this account — XRP and tokens — to anyone. This is full spending power.' };
  }
  if (GRANULAR[name]) {
    const [level, plain] = GRANULAR[name];
    return { name, kind: 'granular', level, plain };
  }
  if (VALUE_MOVING.has(name)) {
    return { name, kind: 'transaction', level: 'high',
      plain: `Can send "${name}" transactions as this account. This type can move or lock up funds.` };
  }
  return { name, kind: 'transaction', level: 'medium',
    plain: `Can send "${name}" transactions as this account.` };
}

export function worstLevel(perms) {
  return asArray(perms).reduce((w, p) => (p && RANK[p.level] > RANK[w] ? p.level : w), 'low');
}

function permissionNames(entry) {
  // Attack-suite finding: a server sending Permissions as a string or with null items crashed the scan.
  return asArray(entry && entry.Permissions)
    .slice(0, LIMITS.permissionsPerDelegate)
    .map((p) => (p && p.Permission && typeof p.Permission === 'object' ? p.Permission.PermissionValue : undefined))
    .filter((v) => v !== undefined);
}

// ---------------------------------------------------------------- scan
async function allDelegateObjects(rpc, address) {
  const out = [];
  let marker;
  let prevMarker;
  let ledger_index = 'validated';
  for (let page = 0; page < LIMITS.objectPages; page++) {
    const r = await rpc('account_objects', {
      account: address, type: 'delegate', ledger_index, limit: 200, ...(marker ? { marker } : {}),
    });
    if (isUint32(r.ledger_index)) ledger_index = r.ledger_index; // keep every page on the same ledger
    out.push(...asArray(r.account_objects).filter((o) => o && typeof o === 'object'));
    if (!r.marker) return { objects: out, ledger: ledger_index };
    if (JSON.stringify(r.marker) === JSON.stringify(prevMarker)) break; // stuck marker
    prevMarker = r.marker;
    marker = r.marker;
  }
  return { objects: out, ledger: ledger_index, truncated: true };
}

async function describeAccount(rpc, address) {
  try {
    const r = await rpc('account_info', { account: address, ledger_index: 'validated' });
    const a = r.account_data;
    if (!a || typeof a !== 'object') return { exists: null, error: 'The server returned no account data.' };
    let domain = '';
    if (typeof a.Domain === 'string' && /^[0-9A-F]{0,512}$/i.test(a.Domain) && a.Domain.length % 2 === 0) {
      try { domain = safeText(new TextDecoder().decode(hexToBytes(a.Domain)), 80); } catch { domain = ''; }
    }
    return { exists: true, domain };
  } catch (e) {
    if (e.code === 'actNotFound') return { exists: false };
    return { exists: null, error: e.message };
  }
}

async function delegatedActivity(rpc, address, { since = null, maxTx = LIMITS.activityMaxTx, onProgress, signal } = {}) {
  // Transactions that ran as this account but were signed by a delegate carry a "Delegate" field.
  // Such transactions cannot exist before the delegation amendment was enabled, so on Mainnet we search
  // every transaction since that ledger (backtest finding: a 400-transaction window missed real delegated
  // payments on busy wallets). `complete` tells the page whether the whole window was covered.
  const found = [];
  let marker;
  let seen = 0;
  let complete = false;
  for (let page = 0; page < LIMITS.activityMaxPages && seen < maxTx; page++) {
    if (signal && signal.aborted) return { found, scanned: seen, complete: false, since, aborted: true };
    const r = await rpc('account_tx', {
      account: address, ledger_index_min: since ?? -1, ledger_index_max: -1,
      limit: Math.min(400, maxTx - seen), forward: false, ...(marker ? { marker } : {}),
    });
    const txs = asArray(r.transactions).slice(0, Math.min(400, maxTx - seen)); // ignore a server that ignores "limit"
    seen += txs.length;
    for (const t of txs) {
      if (!t || typeof t !== 'object') continue;
      const tx = (t.tx_json && typeof t.tx_json === 'object' ? t.tx_json : t.tx) || {};
      const hash = t.hash || tx.hash;
      if (!tx.Delegate || tx.Account !== address) continue;
      if (!isHash(hash) || !isAddress(tx.Delegate)) continue; // attack-suite finding: fake hashes/addresses became links
      if (found.length >= LIMITS.activityMaxFound) break;
      const meta = t.meta && typeof t.meta === 'object' ? t.meta : {};
      found.push({
        hash: hash.toUpperCase(), type: safeText(tx.TransactionType, 40), delegate: tx.Delegate,
        result: safeText(meta.TransactionResult, 40),
        date: typeof t.close_time_iso === 'string' && /^\d{4}-\d\d-\d\dT/.test(t.close_time_iso) ? t.close_time_iso : null,
        amount: meta.delivered_amount !== undefined ? meta.delivered_amount : tx.Amount,
        destination: isAddress(tx.Destination) ? tx.Destination : null,
      });
    }
    if (onProgress) onProgress(seen, found.length);
    if (!r.marker || txs.length === 0) { complete = true; break; }
    marker = r.marker;
  }
  return { found, scanned: seen, complete, since };
}

// Scans the delegations first (fast). History can be requested separately so the page can show
// the important part immediately and fill the history in afterwards.
export async function scanAccount(rpc, rawAddress, { history = true, since = null, onProgress } = {}) {
  const address = String(rawAddress || '').trim();
  if (!isAddress(address)) throw new Error('That is not a valid XRPL classic address (it should start with "r").');

  const self = await describeAccount(rpc, address);
  if (self.exists === false) {
    return { address, exists: false, granted: [], received: [], activity: { found: [], scanned: 0, complete: true, since } };
  }
  if (self.exists === null) throw new Error(`Could not read the account: ${self.error}`);

  const { objects, ledger, truncated } = await allDelegateObjects(rpc, address);
  const granted = [];
  const received = [];
  const seen = new Set();
  for (const o of objects) {
    if (o.LedgerEntryType !== 'Delegate') continue;
    if (!isAddress(o.Account) || !isAddress(o.Authorize)) continue; // never render or act on malformed server data
    const k = `${o.Account}>${o.Authorize}`;
    if (seen.has(k)) continue; // the ledger keeps one entry per pair; a duplicate is server noise
    seen.add(k);
    const perms = permissionNames(o).map(classifyPermission);
    const item = { index: isHash(o.index) ? o.index : null, owner: o.Account, delegate: o.Authorize, perms,
      level: perms.length ? worstLevel(perms) : 'high' };
    if (o.Account === address) granted.push(item);
    else if (o.Authorize === address) received.push(item);
  }
  // At most 4 lookups at a time (backtest: 20 parallel lookups tripped public rate limits).
  await mapLimit(granted, 4, async (g) => { g.delegateInfo = await describeAccount(rpc, g.delegate); });
  granted.sort((a, b) => RANK[b.level] - RANK[a.level]);

  const activity = history ? await delegatedActivity(rpc, address, { since, onProgress })
    : { found: [], scanned: 0, complete: false, since, pending: true };
  return { address, exists: true, ledger, truncated: !!truncated, self, granted, received, activity };
}

export async function scanActivity(rpc, address, { since = null, onProgress, signal } = {}) {
  if (!isAddress(address)) throw new Error('Invalid address');
  return delegatedActivity(rpc, address, { since, onProgress, signal });
}

async function mapLimit(items, n, fn) {
  let i = 0;
  const workers = Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; await fn(items[k]); }
  });
  await Promise.all(workers);
}

// ---------------------------------------------------------------- security: second-server cross-check
// Reads the same account's Delegate entries from each public server independently.
// If one server lies or is stale, the lists will not match.
export function delegateFingerprint(objects) {
  return asArray(objects)
    .filter((o) => o && o.LedgerEntryType === 'Delegate')
    .map((o) => `${o.index}|${o.Account}|${o.Authorize}|${permissionNames(o).map(String).sort().join(',')}`)
    .sort()
    .join('\n');
}

// Asks two DIFFERENT operators (never two names for the same cluster). If the first independent operator
// cannot answer, the next one is used. Returns which operators answered and whether they agree.
export async function crossCheck(network, address, fetchImpl, wsImpl) {
  const ops = NETWORKS[network].operators || [];
  if (ops.length < 2) return { available: false };
  const ask = async (op) => {
    try {
      // A second opinion must be quick or skipped (attack-suite finding: two dead operators added 80 s to a scan).
      const { objects, ledger } = await allDelegateObjects(makeClient(op.urls, fetchImpl, wsImpl, LIMITS.secondOpinionMs), address);
      return { operator: op.name, ledger, fp: delegateFingerprint(objects), count: objects.length };
    } catch (e) {
      return { operator: op.name, error: e.message };
    }
  };
  const first = await ask(ops[0]);
  let second = null;
  for (const op of ops.slice(1)) { second = await ask(op); if (!second.error) break; }
  const results = [first, second].filter(Boolean);
  const ok = results.filter((r) => !r.error);
  if (ok.length < 2) return { available: true, agree: null, results };
  return { available: true, agree: ok[0].fp === ok[1].fp, results };
}

// ---------------------------------------------------------------- security: strict revoke verification
const REVOKE_KEYS = ['Account', 'Authorize', 'Fee', 'LastLedgerSequence', 'Permissions', 'Sequence', 'TransactionType'];

// Returns a list of problems. Empty list = the transaction is exactly a revoke and nothing else.
export function verifyRevokeTx(tx, owner, delegate, maxFeeDrops) {
  const problems = [];
  if (!tx || typeof tx !== 'object') return ['No transaction'];
  const keys = Object.keys(tx).sort();
  const extra = keys.filter((k) => !REVOKE_KEYS.includes(k));
  if (extra.length) problems.push(`Unexpected field(s): ${extra.map((k) => safeText(k, 30)).join(', ')}`);
  if (tx.TransactionType !== 'DelegateSet') problems.push(`Type is ${safeText(tx.TransactionType, 40)}, not DelegateSet`);
  if (tx.Account !== owner) problems.push('Account is not the scanned wallet');
  if (tx.Authorize !== delegate) problems.push('Authorize is not the delegate you chose');
  if (!Array.isArray(tx.Permissions) || tx.Permissions.length !== 0) problems.push('Permissions list is not empty — this would GRANT power, not revoke it');
  if (!isAddress(tx.Account) || !isAddress(tx.Authorize)) problems.push('Malformed address');
  if (!/^\d+$/.test(String(tx.Fee)) || Number(tx.Fee) > maxFeeDrops) problems.push(`Fee ${safeText(tx.Fee, 20)} drops is above your limit of ${maxFeeDrops}`);
  if (!isUint32(tx.Sequence)) problems.push('Sequence number from the server is not valid');
  if (!isUint32(tx.LastLedgerSequence)) problems.push('Expiry (LastLedgerSequence) from the server is not valid');
  return problems;
}

// After the wallet submits, read the transaction back from the ledger and confirm it is the one we asked for.
export async function verifyOnLedger(rpc, hash, owner, delegate, maxFeeDrops) {
  const r = await rpc('tx', { transaction: hash });
  const tx = (r.tx_json && typeof r.tx_json === 'object') ? r.tx_json : r;
  const problems = [];
  if (tx.TransactionType !== 'DelegateSet') problems.push(`Ledger shows a ${safeText(tx.TransactionType, 40)}, not a DelegateSet`);
  if (tx.Account !== owner) problems.push('Ledger shows a different sending account');
  if (tx.Authorize !== delegate) problems.push('Ledger shows a different delegate');
  if (!Array.isArray(tx.Permissions) || tx.Permissions.length !== 0) problems.push('Ledger shows permissions being GRANTED');
  if (!(Number(tx.Fee) <= maxFeeDrops)) problems.push(`Fee paid (${safeText(tx.Fee, 20)} drops) is above your limit`);
  if (r.validated !== true) problems.push('The ledger has not validated this transaction');
  return problems;
}

// Hardening: a single lying server could claim a revoke succeeded. On networks with two independent
// servers, ask BOTH: the transaction must check out on each, and the delegate must be gone on each.
export async function verifyOnBothServers(network, hash, owner, delegate, maxFeeDrops, fetchImpl, wsImpl) {
  const ops = NETWORKS[network].operators || [];
  const out = [];
  const check = async (op) => {
    const rpc = makeClient(op.urls, fetchImpl, wsImpl, LIMITS.secondOpinionMs * 2);
    try {
      const problems = await verifyOnLedger(rpc, hash, owner, delegate, maxFeeDrops);
      const { objects } = await allDelegateObjects(rpc, owner);
      const still = objects.some((o) => o && o.LedgerEntryType === 'Delegate' && o.Account === owner && o.Authorize === delegate);
      if (still) problems.push('The delegate is still listed on this server');
      return { operator: op.name, problems };
    } catch (e) {
      return { operator: op.name, error: e.message };
    }
  };
  if (ops.length) out.push(await check(ops[0]));
  for (const op of ops.slice(1)) { const r = await check(op); out.push(r); if (!r.error) break; }
  const answered = out.filter((r) => !r.error);
  const independent = answered.length;
  return { servers: out, independent, confirmed: independent >= 2 && answered.every((r) => r.problems.length === 0),
    problems: answered.flatMap((r) => r.problems.map((p) => `${r.operator}: ${p}`)) };
}

// ---------------------------------------------------------------- revoke
// An empty Permissions list deletes the Delegate entry (xrpl.org DelegateSet reference).
export function buildRevoke(owner, delegate) {
  return { TransactionType: 'DelegateSet', Account: owner, Authorize: delegate, Permissions: [] };
}

export async function autofill(rpc, tx, maxFeeDrops = 5000) {
  const [info, cur, fee] = await Promise.all([
    rpc('account_info', { account: tx.Account, ledger_index: 'current' }),
    rpc('ledger_current', {}),
    rpc('fee', {}),
  ]);
  const seq = info && info.account_data && info.account_data.Sequence;
  const curIdx = cur && cur.ledger_current_index;
  // Attack-suite finding: garbage numbers from a server used to be passed straight to the wallet.
  if (!isUint32(seq)) throw new Error('The ledger server returned an invalid account sequence number. Nothing was sent. Please try again.');
  if (!isUint32(curIdx) || curIdx + 20 > 0xFFFFFFFF) throw new Error('The ledger server returned an invalid ledger number. Nothing was sent. Please try again.');
  const drops = fee && fee.drops && typeof fee.drops === 'object' ? fee.drops : {};
  const base = Number(drops.open_ledger_fee || drops.base_fee);
  const feeDrops = Number.isFinite(base) && base > 0 ? Math.ceil(base) : 10;
  return {
    ...tx,
    Sequence: seq,
    Fee: String(Math.min(Math.max(feeDrops, 10), maxFeeDrops)), // never above the user's fee limit
    LastLedgerSequence: curIdx + 20,
  };
}

export async function waitForValidation(rpc, hash, { tries = 30, delayMs = 2000, maxMs = 90000 } = {}) {
  if (!isHash(hash)) return { validated: false };
  let lastError = null;
  const stopAt = Date.now() + maxMs; // the user hears back within ~90 s, never 20 minutes (attack-suite finding)
  for (let i = 0; i < tries && Date.now() < stopAt; i++) {
    try {
      const r = await rpc('tx', { transaction: hash });
      if (r.validated === true) return { validated: true, result: safeText(r.meta && r.meta.TransactionResult, 40) };
    } catch (e) {
      // Live-test finding: a busy server during confirmation used to end the whole check (and skip the
      // ledger verification). Server trouble is not an answer — keep polling until the tries run out.
      if (e.code !== 'txnNotFound') lastError = e;
    }
    await sleep(delayMs);
  }
  return { validated: false, unreachable: !!lastError, error: lastError ? lastError.message : null };
}

// ---------------------------------------------------------------- sign-request decoder
const TAKEOVER = {
  SetRegularKey: 'Gives another key the power to sign EVERYTHING for this account. This is how wallets get taken over.',
  SignerListSet: 'Changes who can sign for this account. A list you do not control means you lose the account.',
  AccountDelete: 'Deletes the account and sends the remaining XRP to the Destination shown.',
};

// AccountSet flag numbers (xrpl.org AccountSet reference).
const ASF = {
  1: ['medium', 'Require a destination tag on incoming payments'], 2: ['medium', 'Require authorization for trust lines'],
  3: ['medium', 'Block incoming XRP'],
  4: ['critical', 'DISABLE THE MASTER KEY. If someone else controls this account\'s regular key or signer list, they will own the account completely and you cannot get it back'],
  5: ['medium', 'Track transaction IDs'], 6: ['high', 'Permanently give up the ability to freeze tokens'], 7: ['high', 'Freeze ALL tokens this account issues'],
  8: ['medium', 'Allow default rippling'], 9: ['medium', 'Require deposit authorization'], 10: ['medium', 'Let another account mint NFTs for this account'],
  12: ['medium', 'Block incoming NFT offers'], 13: ['medium', 'Block incoming checks'], 14: ['medium', 'Block incoming payment channels'],
  15: ['medium', 'Block incoming trust lines'], 16: ['high', 'Allow this account to claw back tokens it issues (cannot be undone)'],
  17: ['medium', 'Allow trust line locking'],
};

function amountText(a) {
  if (a === undefined || a === null) return 'an unknown amount';
  if (typeof a === 'string') {
    if (!/^\d{1,20}$/.test(a)) return 'an unknown amount';
    return `${(Number(a) / 1e6).toLocaleString('en-US', { maximumFractionDigits: 6 })} XRP`;
  }
  if (typeof a !== 'object') return 'an unknown amount';
  if (a.mpt_issuance_id) return `${safeText(a.value, 40)} of MPT ${safeText(a.mpt_issuance_id, 12)}…`;
  return `${safeText(a.value, 40)} ${currencyText(a.currency)} (issuer ${safeText(a.issuer, 40)})`;
}
export { amountText };

export function currencyText(c) {
  if (typeof c !== 'string' || !c) return '';
  if (c.length === 40 && /^[0-9A-F]+$/i.test(c)) {
    const s = new TextDecoder().decode(hexToBytes(c.replace(/(00)+$/i, '')));
    return /^[\x20-\x7E]+$/.test(s) ? safeText(s, 20) : safeText(c, 40);
  }
  return safeText(c, 40);
}

function memoTexts(tx) {
  const out = [];
  for (const m of asArray(tx.Memos).slice(0, 10)) {
    const memo = m && m.Memo;
    if (!memo || typeof memo !== 'object') continue;
    for (const f of ['MemoData', 'MemoType', 'MemoFormat']) {
      const v = memo[f];
      if (typeof v === 'string' && /^[0-9A-F]*$/i.test(v) && v.length % 2 === 0 && v.length <= 4096) {
        try { out.push(safeText(new TextDecoder().decode(hexToBytes(v)), 160)); } catch { /* ignore */ }
      }
    }
  }
  return out.filter(Boolean);
}

export function parseSignRequest(text) {
  const t = String(text || '').trim();
  if (!t) throw new Error('Paste a transaction first.');
  // Attack-suite finding: a multi-megabyte paste froze the page.
  if (t.length > LIMITS.pasteMaxChars) throw new Error('That paste is too large to be a real XRPL transaction. Nothing was checked.');
  if (t.startsWith('{')) {
    const j = JSON.parse(t);
    if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error('That JSON is not a transaction object.');
    const inner = j.tx_json || j.txjson || j.transaction;
    return inner && typeof inner === 'object' ? inner : j;
  }
  if (/^[0-9A-Fa-f]+$/.test(t) && t.length % 2 === 0) return decodeBinary(t);
  throw new Error('This does not look like transaction JSON or a signed/unsigned transaction blob (hex).');
}

export function explainTx(rawTx, depth = 0) {
  const findings = [];
  const add = (level, text) => findings.push({ level, text });
  // Attack-suite findings: odd shapes and corrupted blobs used to crash the explainer.
  if (!rawTx || typeof rawTx !== 'object' || Array.isArray(rawTx)) {
    add('high', 'This is not a readable transaction. Do not sign something you cannot read.');
    return { type: 'Unreadable', account: '', findings, inner: [] };
  }
  const tx = rawTx;
  const type = typeof tx.TransactionType === 'string' ? safeText(tx.TransactionType, 40) : 'Unknown';
  const acct = safeText(tx.Account, 40);
  const flags = Number.isInteger(tx.Flags) ? tx.Flags : 0;

  if (tx.Delegate) add('high', `This would run as ${acct} but is signed by a DELEGATE (${safeText(tx.Delegate, 40)}).`);

  try {
    switch (type) {
      case 'DelegateSet': {
        const names = permissionNames(tx);
        if (Array.isArray(tx.Permissions) && tx.Permissions.length > LIMITS.permissionsPerDelegate) {
          add('critical', `Lists ${tx.Permissions.length} permissions — the ledger allows at most 10. This was built to confuse checkers. Do not sign.`);
        }
        if (!Array.isArray(tx.Permissions)) {
          add('high', 'The permission list is malformed. Do not sign.');
        } else if (names.length === 0) {
          add('low', `REVOKES every permission held by ${safeText(tx.Authorize, 40)}. This is the safe "take it back" transaction.`);
        } else {
          const perms = names.map(classifyPermission);
          const lvl = worstLevel(perms);
          add(lvl === 'low' ? 'medium' : lvl, `GRANTS ${safeText(tx.Authorize, 40)} power to act as ${acct}: ${perms.map((p) => p.name).join(', ')}.`);
          perms.forEach((p) => add(p.level, `${p.name}: ${p.plain}`));
          add('high', 'Only sign this if YOU set up this delegate on purpose and you know who controls that address.');
        }
        break;
      }
      case 'Batch': {
        const raw = asArray(tx.RawTransactions);
        const inner = raw.slice(0, LIMITS.batchMaxInner).map((r) => (r && r.RawTransaction) || r);
        add('medium', `A BATCH of ${raw.length} transaction(s) that execute together. Every one is listed below — read them all.`);
        if (raw.length > LIMITS.batchMaxInner) add('high', `Only the first ${LIMITS.batchMaxInner} are shown. A real batch holds at most 8.`);
        else if (raw.length > 8) add('high', `A real XRPL batch holds at most 8 transactions; this one claims ${raw.length}. Treat it as suspicious.`);
        const accounts = new Set(inner.map((i) => (i && typeof i === 'object' ? i.Account : undefined)).filter(Boolean));
        if (accounts.size > 1) add('high', `This batch involves ${accounts.size} different accounts: ${[...accounts].slice(0, 8).map((a) => safeText(a, 40)).join(', ')}.`);
        if (depth >= LIMITS.batchMaxDepth) {
          add('critical', 'Batches nested inside batches are not allowed on the XRP Ledger. This was built to confuse checkers. Do not sign.');
          return { type, account: acct, findings, inner: [] };
        }
        if (depth > 0) add('critical', 'A batch inside a batch is not allowed on the XRP Ledger. Do not sign.');
        return { type, account: acct, findings, inner: inner.map((i) => explainTx(i, depth + 1)) };
      }
      case 'Payment':
        add('high', `Sends ${amountText(tx.Amount ?? tx.DeliverMax)} to ${safeText(tx.Destination, 40)}${Number.isInteger(tx.DestinationTag) ? ` (tag ${tx.DestinationTag})` : ''}.`);
        if (tx.SendMax) add('medium', `Can spend up to ${amountText(tx.SendMax)} to do it.`);
        if (flags & 0x00020000) add('high', 'Partial-payment flag is on: the amount actually delivered can be far LESS than the amount shown. A common trick when someone "pays" you.');
        break;
      case 'TrustSet':
        add('medium', `Sets a trust line: limit ${amountText(tx.LimitAmount)}.`);
        break;
      case 'OfferCreate':
        add('medium', `Places a trade: pays ${amountText(tx.TakerGets)} to get ${amountText(tx.TakerPays)}. Check the price — a bad trade cannot be reversed.`);
        break;
      case 'AccountSet': {
        const set = Number.isInteger(tx.SetFlag) ? tx.SetFlag : null;
        const clr = Number.isInteger(tx.ClearFlag) ? tx.ClearFlag : null;
        if (set !== null) { const f = ASF[set] || ['medium', `Turns on account setting #${set}`]; add(f[0], `Turns ON: ${f[1]}.`); }
        if (clr !== null) { const f = ASF[clr] || ['medium', `account setting #${clr}`]; add(clr === 4 ? 'low' : 'medium', `Turns OFF: ${f[1].replace(/^DISABLE THE MASTER KEY.*/, 'master-key disable (re-enables your master key)')}.`); }
        if (typeof tx.TransferRate === 'number' && tx.TransferRate > 0) add('medium', `Changes the fee charged when the tokens you issue are transferred.`);
        if (set === null && clr === null) add('medium', 'Changes account settings.');
        break;
      }
      case 'NFTokenCreateOffer': {
        const sell = (flags & 1) === 1;
        const zero = typeof tx.Amount === 'string' && /^0+$/.test(tx.Amount);
        if (sell && zero) add('critical', `Offers to SELL an NFT for 0${tx.Destination ? ` to ${safeText(tx.Destination, 40)}` : ' to anyone'} — that is giving it away.`);
        else add('high', `${sell ? 'Offers to sell' : 'Offers to buy'} an NFT for ${amountText(tx.Amount)}${tx.Destination ? ` (only ${safeText(tx.Destination, 40)} can accept)` : ''}.`);
        add('high', 'Fake "reward" NFTs are a known XRPL scam. Only continue if you started this yourself.');
        break;
      }
      case 'NFTokenAcceptOffer':
        add('high', 'Accepts an NFT offer. The price is stored in the OFFER, not shown here — check the offer on an explorer first. Fake "reward" NFTs are a known scam.');
        break;
      case 'EscrowCreate':
        add('high', `Locks ${amountText(tx.Amount)} in escrow for ${safeText(tx.Destination, 40)}.`);
        break;
      case 'PaymentChannelCreate':
      case 'PaymentChannelFund':
        add('high', `${type === 'PaymentChannelCreate' ? 'Opens a payment channel to' : 'Adds funds to a payment channel'} ${safeText(tx.Destination || tx.Channel, 66)} with ${amountText(tx.Amount)}. The other side can claim it.`);
        break;
      case 'CheckCreate':
        add('high', `Writes a check for up to ${amountText(tx.SendMax)} that ${safeText(tx.Destination, 40)} can cash.`);
        break;
      case 'DepositPreauth':
        add('medium', 'Lets a specific account send payments to you even if you require authorization.');
        break;
      default:
        if (TAKEOVER[type]) add('critical', TAKEOVER[type]);
        else add('medium', `A "${type}" transaction from ${acct}.`);
    }
  } catch {
    add('high', 'Part of this transaction could not be read. Do not sign something you cannot read.');
  }
  if (type === 'AccountDelete') add('critical', `Remaining XRP goes to ${safeText(tx.Destination, 40)}.`);
  if (type === 'SetRegularKey' && tx.RegularKey) add('critical', `New key holder: ${safeText(tx.RegularKey, 40)}.`);

  // Signed transactions that never expire can be kept and submitted later by whoever holds them.
  if (depth === 0 && type !== 'Unreadable') {
    const hasTicket = Number.isInteger(tx.TicketSequence);
    const signed = typeof tx.TxnSignature === 'string' || (Array.isArray(tx.Signers) && tx.Signers.length > 0);
    // Unsigned JSON without an expiry is normal: the wallet adds one when you sign. The danger is a transaction
    // that is ALREADY signed (or uses a Ticket) and never expires — whoever holds it can submit it later.
    if (!Number.isInteger(tx.LastLedgerSequence) && (signed || hasTicket)) {
      add('high', hasTicket
        ? 'Uses a Ticket and has NO expiry: once signed, whoever holds it can submit it at any time — days or months later. Never sign this for someone else to "submit for you".'
        : 'This is already SIGNED and has NO expiry: whoever holds it can submit it at any time — days or months later.');
    } else if (hasTicket) {
      add('medium', 'Uses a Ticket instead of the normal sequence number, so it is not cancelled by your other transactions.');
    }
    const fee = typeof tx.Fee === 'string' && /^\d{1,20}$/.test(tx.Fee) ? Number(tx.Fee) : null;
    if (fee !== null && fee > 1000000) add('critical', `The network fee is ${(fee / 1e6).toLocaleString('en-US')} XRP. Fees are burned forever; a normal fee is 0.00001 XRP. This drains your wallet.`);
    else if (fee !== null && fee > 10000) add('high', `The network fee is ${(fee / 1e6).toLocaleString('en-US')} XRP — far above the normal 0.00001 XRP.`);
    if (Array.isArray(tx.Signers) && tx.Signers.length) add('medium', `Already carries ${tx.Signers.length} multi-signature(s). Check who the signers are.`);
  }

  const memos = memoTexts(tx);
  if (memos.length) {
    const linky = memos.some((m) => /https?:\/\/|www\.|\.[a-z]{2,}\//i.test(m));
    add(linky ? 'high' : 'low', `Memo text: “${memos.join(' | ')}”${linky ? ' — it contains a web link. Links in memos are a common scam; never follow them.' : ''}`);
  }
  return { type, account: acct, findings, inner: [] };
}

export function overallLevel(explained) {
  let worst = 'low';
  const stack = [explained];
  while (stack.length) {
    const e = stack.pop();
    if (!e) continue;
    for (const f of asArray(e.findings)) if (RANK[f.level] > RANK[worst]) worst = f.level;
    for (const i of asArray(e.inner)) stack.push(i);
  }
  return worst;
}

// ---------------------------------------------------------------- utils
export function hexToBytes(hex) {
  const out = new Uint8Array(Math.floor(hex.length / 2));
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16) || 0;
  return out;
}
