// A server that accepts the request but never answers must not freeze the scan (user report, 25 Oct 2026).
import * as core from '../src/core.js';
let fails = 0;
const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) fails++; };
const never = () => new Promise(() => {});
const answer = (result) => ({ ok: true, status: 200, headers: { get: () => null }, json: async () => ({ result: { status: 'success', ...result } }) });

// 1) First server hangs, second answers: the scan moves on after the per-attempt limit.
{
  core.resetRpcState();
  const seen = [];
  const fetchImpl = (url, opts) => { seen.push(url); if (url.includes('xrplcluster')) return never(); return Promise.resolve(answer({ ledger_index: 7 })); };
  const rpc = core.makeRpc('mainnet', fetchImpl, null, undefined);
  const t0 = Date.now();
  const r = await rpc('ledger', {});
  const s = (Date.now() - t0) / 1000;
  ok(r.ledger_index === 7, `a hanging first server is abandoned and the second server's answer is used (${s.toFixed(1)}s)`);
  ok(s >= 14 && s < 20, 'the hanging attempt is cut off at about 15 seconds');
}
// 2) A server that sends headers but never finishes the body is also cut off.
{
  core.resetRpcState();
  const fetchImpl = (url) => url.includes('xrplcluster')
    ? Promise.resolve({ ok: true, status: 200, headers: { get: () => null }, json: never })
    : Promise.resolve(answer({ ledger_index: 9 }));
  const rpc = core.makeRpc('mainnet', fetchImpl, null, undefined);
  const r = await rpc('ledger', {});
  ok(r.ledger_index === 9, 'a server that never finishes sending its answer is abandoned too');
}
// 3) Every server hangs: the question ends with a clear error inside the 40-second deadline.
{
  core.resetRpcState();
  const rpc = core.makeRpc('mainnet', () => never(), null, class { constructor() {} close() {} });
  const t0 = Date.now();
  let msg = '';
  try { await rpc('ledger', {}); } catch (e) { msg = e.message; }
  const s = (Date.now() - t0) / 1000;
  ok(/No ledger server could be reached/.test(msg), `with every server hanging, the user gets a clear error (${s.toFixed(1)}s)`);
  ok(s <= 46, 'and it arrives within the 40-second deadline (plus one last attempt)');
}
// 4) The abort signal reaches fetch, so the browser actually drops the stuck connection.
{
  core.resetRpcState();
  let aborted = false;
  const fetchImpl = (url, opts) => { if (url.includes('xrplcluster')) { opts.signal && opts.signal.addEventListener('abort', () => { aborted = true; }); return never(); } return Promise.resolve(answer({ ledger_index: 1 })); };
  await core.makeRpc('mainnet', fetchImpl, null, undefined)('ledger', {});
  ok(aborted, 'the stuck connection is actually cancelled, not just ignored');
}
console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED');
process.exit(fails ? 1 : 0);
