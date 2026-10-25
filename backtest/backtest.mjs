// BACKTEST: run the tool's own code against every real delegation on XRPL Mainnet and grade it
// against three independent answers:
//   A) ground truth  — every Delegate object from a full ledger_data sweep (backtest/ground-truth.py)
//   B) history replay — each owner's real DelegateSet transactions replayed in order from account_tx
//   C) raw blobs      — each real DelegateSet / delegated transaction fetched in binary and decoded
import { ProxyAgent, setGlobalDispatcher } from 'undici';
import { readFileSync, writeFileSync } from 'fs';
import * as core from '../src/core.js';

if (process.env.HTTPS_PROXY) setGlobalDispatcher(new ProxyAgent(process.env.HTTPS_PROXY));
const rpc = core.makeRpc('mainnet');
const sleep = (ms) => new Promise((s) => setTimeout(s, ms));
const gt = JSON.parse(readFileSync('backtest/ground-truth-mainnet.json', 'utf8'));
const out = { ground_truth_ledger: gt.ledger, sweep_calls: gt.calls, delegate_objects: gt.objects.length, owners: [], delegates: [], decoder: [], summary: {} };
const key = (d, perms) => `${d}:${[...perms].sort().join(',')}`;
const permsOf = (o) => (o.Permissions || []).map((p) => p.Permission.PermissionValue);

// expected from ground truth
const byOwner = new Map(); const byDelegate = new Map();
for (const o of gt.objects) {
  if (!byOwner.has(o.Account)) byOwner.set(o.Account, new Set());
  byOwner.get(o.Account).add(key(o.Authorize, permsOf(o)));
  if (!byDelegate.has(o.Authorize)) byDelegate.set(o.Authorize, new Set());
  byDelegate.get(o.Authorize).add(key(o.Account, permsOf(o)));
}
console.log(`ground truth @ ledger ${gt.ledger}: ${gt.objects.length} delegations, ${byOwner.size} owners, ${byDelegate.size} delegates`);

async function fullHistory(account) {
  const txs = []; let marker;
  for (let i = 0; i < 100; i++) {
    const r = await rpc('account_tx', { account, ledger_index_min: -1, ledger_index_max: -1, limit: 400, forward: true, ...(marker ? { marker } : {}) });
    txs.push(...(r.transactions || []));
    if (!r.marker) break;
    marker = r.marker;
    await sleep(250);
  }
  return txs;
}

let ok = 0, bad = 0, explained = 0;
const allPermNames = new Set();
const delegatedTxSamples = [];
for (const [owner, expected] of byOwner) {
  const row = { owner };
  try {
    // 1) the tool
    const t0 = Date.now();
    const scan = await core.scanAccount(rpc, owner, { since: core.NETWORKS.mainnet.delegationSince });
    row.scan_ms = Date.now() - t0;
    const got = new Set(scan.granted.map((g) => key(g.delegate, g.perms.map((p) => p.name))));
    scan.granted.forEach((g) => g.perms.forEach((p) => allPermNames.add(p.name)));
    row.tool = [...got]; row.truth = [...expected]; row.tool_ledger = scan.ledger;
    row.tool_activity_found = scan.activity.found.length; row.tool_activity_scanned = scan.activity.scanned;

    // 2) independent history replay
    const hist = await fullHistory(owner);
    const replay = new Map();
    let delegatedSent = 0; let lastDelegateSetLedger = 0;
    for (const t of hist) {
      const tx = t.tx_json || t.tx; const res = t.meta && t.meta.TransactionResult;
      if (tx.Account === owner && tx.Delegate) { delegatedSent++; if (delegatedTxSamples.length < 15) delegatedTxSamples.push(t.hash); }
      if (tx.TransactionType !== 'DelegateSet' || tx.Account !== owner || res !== 'tesSUCCESS') continue;
      lastDelegateSetLedger = Math.max(lastDelegateSetLedger, t.ledger_index || 0);
      const p = permsOf(tx);
      if (p.length === 0) replay.delete(tx.Authorize); else replay.set(tx.Authorize, p);
      if (out.decoder.length < 60) out.decoder.push({ hash: t.hash, authorize: tx.Authorize, perms: p });
    }
    const replayed = new Set([...replay].map(([d, p]) => key(d, p)));
    row.replay = [...replayed]; row.history_tx = hist.length; row.delegated_tx_total = delegatedSent;

    const eq = (a, b) => a.size === b.size && [...a].every((x) => b.has(x));
    row.tool_vs_truth = eq(got, expected); row.tool_vs_replay = eq(got, replayed); row.truth_vs_replay = eq(expected, replayed);
    row.tool_activity_complete = scan.activity.complete;
    // Graded: when the tool says it checked everything, its count must equal the replay exactly;
    // when it says it did not, it must not over-count and must not claim completeness.
    row.activity_ok = scan.activity.complete ? scan.activity.found.length === delegatedSent : scan.activity.found.length <= delegatedSent;
    if (row.tool_vs_truth && row.tool_vs_replay && row.activity_ok) ok++;
    else if (lastDelegateSetLedger > gt.ledger && row.tool_vs_replay) { explained++; row.note = 'state changed after the ground-truth ledger; tool matches the newer history'; }
    else bad++;
  } catch (e) { row.error = e.message; bad++; }
  out.owners.push(row);
  process.stdout.write(`${row.tool_vs_truth && row.tool_vs_replay && row.activity_ok ? 'PASS' : row.note ? 'MOVED' : 'FAIL'} ${owner} truth=${expected.size} tool=${(row.tool || []).length} replay=${(row.replay || []).length} delegatedTx=${row.delegated_tx_total ?? '?'} toolFound=${row.tool_activity_found ?? '?'} complete=${row.tool_activity_complete} ${row.error || ''}\n`);
  await sleep(1500);
}

// delegate side (received power)
let dOk = 0, dBad = 0;
for (const [delegate, expected] of byDelegate) {
  try {
    const s = await core.scanAccount(rpc, delegate, { history: false });
    const got = new Set(s.received.map((g) => key(g.owner, g.perms.map((p) => p.name))));
    const pass = got.size === expected.size && [...got].every((x) => expected.has(x));
    pass ? dOk++ : dBad++;
    out.delegates.push({ delegate, pass, tool: [...got], truth: [...expected] });
  } catch (e) { dBad++; out.delegates.push({ delegate, error: e.message }); }
  await sleep(300);
}

// decoder on the real signed blobs
let decOk = 0, decBad = 0;
for (const d of out.decoder) {
  try {
    const r = await rpc('tx', { transaction: d.hash, binary: true });
    const blob = r.tx_blob || r.tx;
    const tx = core.parseSignRequest(blob);
    const ex = core.explainTx(tx);
    const lvl = core.overallLevel(ex);
    const decodedPerms = (tx.Permissions || []).map((p) => p.Permission.PermissionValue);
    const permsMatch = JSON.stringify(decodedPerms) === JSON.stringify(d.perms) && tx.Authorize === d.authorize;
    const expectLvl = d.perms.length === 0 ? 'low' : core.worstLevel(d.perms.map(core.classifyPermission));
    const verdictOk = d.perms.length === 0 ? lvl === 'low' : core.overallLevel(ex) === (expectLvl === 'low' ? 'high' : expectLvl === 'medium' ? 'high' : expectLvl);
    d.decoded_ok = permsMatch; d.verdict = lvl; d.verdict_ok = verdictOk;
    permsMatch && verdictOk ? decOk++ : decBad++;
  } catch (e) { d.error = e.message; decBad++; }
  await sleep(200);
}

const known = new Set(['Payment']);
out.summary = {
  owners_checked: byOwner.size, owners_exact_match: ok, owners_changed_after_snapshot: explained, owners_mismatch: bad,
  delegates_checked: byDelegate.size, delegates_exact_match: dOk, delegates_mismatch: dBad,
  real_blobs_decoded: out.decoder.length, decoder_correct: decOk, decoder_wrong: decBad,
  permission_names_seen: [...allPermNames].sort(),
  delegated_tx_samples: delegatedTxSamples,
};
writeFileSync('backtest/backtest-result--2026-10-19.json', JSON.stringify(out, null, 1));
console.log('\nSUMMARY', JSON.stringify(out.summary, null, 1));
