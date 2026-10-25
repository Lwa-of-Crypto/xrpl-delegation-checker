// ATTACK SUITE (browser): the real page in Chromium, with every ledger server replaced by a hostile one.
// No live network: page.route() answers every XRPL request, so each attack is exact and repeatable.
import { chromium } from 'playwright';
import http from 'http';
import { readFileSync } from 'fs';

const html = readFileSync('test-build/index.html');
const server = http.createServer((q, r) => { r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); r.end(html); }).listen(8771);
let fails = 0; let total = 0;
const check = (c, m) => { total++; console.log(`${c ? 'PASS' : 'FAIL'} ${m}`); if (!c) fails++; };
const sleep = (ms) => new Promise((s) => setTimeout(s, ms));

const O = 'rf1XWa1W3C1X59LRX2zHz47MERqoShutF5';
const D = 'r3eLwV1LwtJCmcY6pfFvWxHgsuibViXqbo';
const D2 = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';
const XSS = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script><svg onload="window.__pwned=3">"\'><a href="javascript:window.__pwned=4">x</a>';
const hex = (s) => Buffer.from(s, 'utf8').toString('hex').toUpperCase();

const browser = await chromium.launch();

// handler(url, method, params) -> result  (or {__http: status} / {__abort:true} / {__delay: ms, ...})
async function openWith(handler, { storage } = {}) {
  const ctx = await browser.newContext({ viewport: { width: 1200, height: 900 } });
  if (storage) await ctx.addInitScript((s) => { try { localStorage.setItem('xdc.settings.v1', s); } catch {} }, storage);
  const page = await ctx.newPage();
  const errors = []; const dialogs = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('dialog', (d) => { dialogs.push(d.message()); d.dismiss(); });
  await page.route(/xrplcluster\.com|xrpl\.ws|xrpl-labs\.com/, async (route) => {
    const req = route.request();
    if (req.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: { 'access-control-allow-origin': '*', 'access-control-allow-headers': '*' } });
    const body = JSON.parse(req.postData() || '{}');
    const res = await handler(req.url(), body.method, (body.params || [{}])[0]);
    if (res && res.__abort) return route.abort();
    if (res && res.__delay) await sleep(res.__delay);
    if (res && res.__http) return route.fulfill({ status: res.__http, headers: { 'access-control-allow-origin': '*' }, body: 'busy' });
    return route.fulfill({ status: 200, headers: { 'access-control-allow-origin': '*', 'content-type': 'application/json' }, body: JSON.stringify({ result: { status: 'success', ...res } }) });
  });
  // Ripple / Honeycluster answer over WebSocket: fake those too, with the same hostile handler.
  await page.routeWebSocket(/ripple\.com|honeycluster\.io/, (ws) => {
    ws.onMessage(async (raw) => {
      let m; try { m = JSON.parse(raw); } catch { return; }
      const { id, command, ...params } = m;
      const res = await handler(ws.url(), command, params);
      if (res && (res.__abort || res.__http)) { ws.close(); return; }
      if (res && res.__delay) await sleep(res.__delay);
      ws.send(JSON.stringify({ id, type: 'response', status: 'success', result: res || {} }));
    });
  });
  await page.goto('http://localhost:8771/');
  return { ctx, page, errors, dialogs };
}
async function scan(page, addr) {
  await page.fill('#addr', addr);
  await page.click('#scan-btn');
  await page.waitForFunction(() => { const r = document.querySelector('#results'); return r && !r.querySelector('.loading') && r.querySelector('.banner'); }, null, { timeout: 60000 });
  return page.textContent('#results');
}
const injected = (page) => page.evaluate(() => ({
  pwned: window.__pwned,
  bad: document.querySelectorAll('#results img, #results script, #results svg:not(.mark), #results iframe, #results [onerror], #results [onload], #results a[href^="javascript"], #check-out img, #check-out script, #check-out a[href^="javascript"], #revoke-body img, #revoke-body script').length,
}));

const evilLedger = (url, m, p) => {
  if (m === 'account_info') return { account_data: { Account: p.account, Balance: '1', Sequence: 5, Domain: hex(XSS) }, ledger_index: 9 };
  if (m === 'account_objects') return { ledger_index: 9, account_objects: [
    { LedgerEntryType: 'Delegate', index: XSS, Account: O, Authorize: D, Permissions: [{ Permission: { PermissionValue: XSS } }, { Permission: { PermissionValue: 'Payment' } }] },
    { LedgerEntryType: 'Delegate', index: 'Z', Account: O, Authorize: XSS, Permissions: [{ Permission: { PermissionValue: 'Payment' } }] },
  ] };
  if (m === 'account_tx') return { transactions: [
    { hash: 'javascript:window.__pwned=9', close_time_iso: XSS, meta: { TransactionResult: XSS, delivered_amount: { value: XSS, currency: XSS, issuer: D } }, tx_json: { Account: O, Delegate: D, TransactionType: XSS, Destination: XSS } },
    { hash: 'E'.repeat(64), close_time_iso: '2026-10-10T00:00:00Z', meta: { TransactionResult: 'tesSUCCESS', delivered_amount: 'unavailable' }, tx_json: { Account: O, Delegate: D, TransactionType: 'Payment', Destination: D } },
  ] };
  if (m === 'ledger_data' || m === 'tx') return {};
  return {};
};

// ---------------------------------------------------------------- A. script injection from a hostile server
{
  const { ctx, page, errors, dialogs } = await openWith(evilLedger);
  const txt = await scan(page, O);
  const inj = await injected(page);
  check(!inj.pwned && inj.bad === 0 && dialogs.length === 0, `hostile server cannot inject code or elements (pwned=${inj.pwned}, injected elements=${inj.bad})`);
  check(!txt.includes('NaN'), 'an "unavailable" amount is not shown as NaN');
  check(errors.length === 0, `no page crash on hostile data${errors.length ? ': ' + errors[0] : ''}`);
  await ctx.close();
}

// ---------------------------------------------------------------- B. the two Mainnet servers disagree (one is lying)
{
  const { ctx, page } = await openWith((url, m, p) => {
    if (m === 'account_info') return { account_data: { Account: p.account, Balance: '1', Sequence: 5 }, ledger_index: 9 };
    if (m === 'account_objects') return /xrplcluster|xrpl\.ws/.test(url)
      ? { ledger_index: 9, account_objects: [] }
      : { ledger_index: 9, account_objects: [{ LedgerEntryType: 'Delegate', index: 'X', Account: O, Authorize: D, Permissions: [{ Permission: { PermissionValue: 'Payment' } }] }] };
    if (m === 'account_tx') return { transactions: [] };
    return {};
  });
  const txt = await scan(page, O);
  check(/independent operators disagree/i.test(txt) && /InFTF/.test(txt) && /Ripple/.test(txt), 'a lying operator is exposed: "Two independent operators disagree" names InFTF and Ripple');
  check(!/No one has delegated power/.test(txt) || /disagree/.test(txt), 'the page never shows an all-clear without the disagreement warning next to it');
  await ctx.close();
}

// ---------------------------------------------------------------- B2. Ripple down → Honeycluster is used as the second opinion
{
  const seen = new Set();
  const { ctx, page } = await openWith((url, m, p) => {
    if (/ripple\.com/.test(url)) return { __abort: true };
    seen.add(new URL(url).host);
    if (m === 'account_info') return { account_data: { Account: p.account, Balance: '1', Sequence: 5 }, ledger_index: 9 };
    if (m === 'account_objects') return { ledger_index: 9, account_objects: [] };
    if (m === 'account_tx') return { transactions: [] };
    return {};
  });
  const txt = await scan(page, O);
  check(/independent operators agree/i.test(txt) && /Honeycluster/.test(txt), 'when Ripple is down, Honeycluster steps in as the independent second opinion');
  await ctx.close();
}
// ---------------------------------------------------------------- B3. the alias is never counted as a second opinion
{
  const { ctx, page } = await openWith((url, m, p) => {
    if (/ripple\.com|honeycluster/.test(url)) return { __abort: true };
    if (m === 'account_info') return { account_data: { Account: p.account, Balance: '1', Sequence: 5 }, ledger_index: 9 };
    if (m === 'account_objects') return { ledger_index: 9, account_objects: [] };
    if (m === 'account_tx') return { transactions: [] };
    return {};
  });
  const txt = await scan(page, O);
  check(/Only one operator answered/i.test(txt) && !/operators agree/i.test(txt), 'xrplcluster.com + xrpl.ws (same cluster) are NEVER presented as two independent sources');
  await ctx.close();
}

// ---------------------------------------------------------------- C. every server down / rate-limit storm
{
  const { ctx, page, errors } = await openWith(() => ({ __http: 429 }));
  const t0 = Date.now();
  const txt = await scan(page, O);
  check(/Could not complete the scan|could be reached/i.test(txt), `all servers refusing → clear error, not a hang (${((Date.now() - t0) / 1000).toFixed(0)} s)`);
  check(!(await page.isDisabled('#scan-btn')), 'Scan button is usable again after the failure');
  check(errors.length === 0, 'no page crash when every server is down');
  await ctx.close();
}

// ---------------------------------------------------------------- D. tampered saved settings
{
  const tampered = JSON.stringify({ maxFee: 99999999, autoLockMin: 0.0001, watchMin: 0.0001, watch: true, strictVerify: 'false', ledgerVerify: 0, persist: true });
  const { ctx, page } = await openWith(evilLedger, { storage: tampered });
  const s = await page.evaluate(() => ({ ...window.__xdc.settings }));
  check(s.maxFee <= 5000, `a tampered fee limit (99,999,999 drops) is refused (now ${s.maxFee})`);
  check(s.watchMin >= 5, `a tampered Watch interval that would hammer the servers is refused (now ${s.watchMin} min)`);
  check(s.autoLockMin >= 2, `a tampered auto-disconnect time is refused (now ${s.autoLockMin} min)`);
  check(s.strictVerify === true && s.ledgerVerify === true, 'safety switches cannot be turned off by a wrong-typed stored value');
  await ctx.close();
}

// ---------------------------------------------------------------- E. revoke races: double-click, network switch mid-revoke, hostile autofill
{
  let submits = 0;
  const { ctx, page } = await openWith((url, m, p) => {
    if (m === 'account_info') return { account_data: { Account: p.account, Balance: '50000000', Sequence: 5 }, ledger_index: 9 };
    if (m === 'account_objects') return { ledger_index: 9, account_objects: [{ LedgerEntryType: 'Delegate', index: 'X', Account: O, Authorize: D, Permissions: [{ Permission: { PermissionValue: 'Payment' } }] }] };
    if (m === 'account_tx') return { transactions: [] };
    if (m === 'ledger_current') return { ledger_current_index: 100 };
    if (m === 'fee') return { drops: { open_ledger_fee: '10' } };
    if (m === 'tx') return { validated: true, meta: { TransactionResult: 'tesSUCCESS' }, tx_json: { TransactionType: 'DelegateSet', Account: O, Authorize: D, Permissions: [], Fee: '10' } };
    return {};
  });
  await scan(page, O);
  await page.evaluate((o) => {
    window.__xdc.state.wallet = { id: 'gem', address: o };
    window.__xdc.WALLETS.gem.network = async () => 'mainnet';
    window.__xdc.WALLETS.gem.signAndSubmit = async () => { window.__submits = (window.__submits || 0) + 1; await new Promise((r) => setTimeout(r, 800)); return 'A'.repeat(64); };
  }, O);
  await page.click('button.card-revoke');
  await page.waitForSelector('#revoke-body pre.json');
  await page.evaluate(() => { const b = document.querySelector('#revoke-go'); b.click(); b.click(); b.click(); });
  await sleep(300);
  // network switch while the revoke is in flight
  const switchBlocked = await page.evaluate(() => { document.querySelector('.net [data-net=testnet]').click(); return window.__xdc.state.network; });
  await page.waitForFunction(() => /Revoked|Not confirmed|WARNING|waiting for full confirmation/.test(document.querySelector('#revoke-body').textContent), null, { timeout: 60000 });
  submits = await page.evaluate(() => window.__submits);
  const outcome = await page.textContent('#revoke-body');
  check(/waiting for full confirmation/i.test(outcome) && !/^\s*Revoked/.test(outcome), 'when servers still list the delegate after a "successful" revoke, the page does NOT claim it is revoked');
  check(submits === 1, `triple-clicking "Sign" sends exactly one transaction (sent ${submits})`);
  check(switchBlocked === 'mainnet', `the network cannot be switched while a revoke is in flight (now "${switchBlocked}")`);
  await ctx.close();
}
{
  const { ctx, page } = await openWith((url, m, p) => {
    if (m === 'account_info') return { account_data: { Account: p.account, Balance: '50000000', Sequence: 'NaN' }, ledger_index: 9 };
    if (m === 'account_objects') return { ledger_index: 9, account_objects: [{ LedgerEntryType: 'Delegate', index: 'X', Account: O, Authorize: D, Permissions: [{ Permission: { PermissionValue: 'Payment' } }] }] };
    if (m === 'account_tx') return { transactions: [] };
    if (m === 'ledger_current') return { ledger_current_index: 'x' };
    if (m === 'fee') return { drops: { open_ledger_fee: '10' } };
    return {};
  });
  await scan(page, O);
  await page.evaluate((o) => { window.__xdc.state.wallet = { id: 'gem', address: o }; window.__xdc.WALLETS.gem.network = async () => 'mainnet'; }, O);
  await page.click('button.card-revoke');
  await page.waitForSelector('#revoke-dialog[open]');
  await sleep(1500);
  const body = await page.textContent('#revoke-body');
  check(!(await page.isVisible('#revoke-go')) && /could not prepare|blocked|invalid/i.test(body), `garbage sequence numbers from a server never reach the wallet ("${body.slice(0, 90)}…")`);
  await ctx.close();
}

// ---------------------------------------------------------------- E2. servers die DURING confirmation of a dishonest wallet's transaction
{
  let down = true;
  const { ctx, page } = await openWith((url, m, p) => {
    if (m === 'tx' && down) return { __abort: true };
    if (m === 'account_info') return { account_data: { Account: p.account, Balance: '50000000', Sequence: 5 }, ledger_index: 9 };
    if (m === 'account_objects') return { ledger_index: 9, account_objects: [{ LedgerEntryType: 'Delegate', index: 'X', Account: O, Authorize: D, Permissions: [{ Permission: { PermissionValue: 'Payment' } }] }] };
    if (m === 'account_tx') return { transactions: [] };
    if (m === 'ledger_current') return { ledger_current_index: 100 };
    if (m === 'fee') return { drops: { open_ledger_fee: '10' } };
    // the wallet secretly signed a GRANT to someone else
    if (m === 'tx') return { validated: true, meta: { TransactionResult: 'tesSUCCESS' }, tx_json: { TransactionType: 'DelegateSet', Account: O, Authorize: D2, Permissions: [{ Permission: { PermissionValue: 'Payment' } }], Fee: '10' } };
    return {};
  });
  await scan(page, O);
  await page.evaluate((o) => {
    window.__xdc.state.wallet = { id: 'gem', address: o };
    window.__xdc.WALLETS.gem.network = async () => 'mainnet';
    window.__xdc.WALLETS.gem.signAndSubmit = async () => 'B'.repeat(64);
  }, O);
  await page.click('button.card-revoke');
  await page.waitForSelector('#revoke-body pre.json');
  await page.click('#revoke-go');
  await page.waitForFunction(() => /Do NOT sign again|WARNING|Revoked/.test(document.querySelector('#revoke-body').textContent), null, { timeout: 200000 });
  const mid = await page.textContent('#revoke-body');
  check(/Do NOT sign again/.test(mid) && await page.isHidden('#revoke-go'), 'servers down during confirmation → "Sent — do NOT sign again", and Sign is NOT offered again');
  check(await page.isVisible('#recheck'), 'a "Check again" button keeps the verification alive');
  down = false;
  await page.click('#recheck');
  await page.waitForFunction(() => /WARNING|Revoked|Do NOT sign again/.test(document.querySelector('#revoke-body').textContent) && !document.querySelector('#revoke-body .loading'), null, { timeout: 120000 });
  const fin = await page.textContent('#revoke-body');
  check(/WARNING/.test(fin) && /different delegate/.test(fin), 'once servers recover, the dishonest wallet is still caught (verification was not skipped)');
  await ctx.close();
}

// ---------------------------------------------------------------- F. Watch mode must keep watching the wallet it started with
{
  const { ctx, page } = await openWith((url, m, p) => {
    if (m === 'account_info') return { account_data: { Account: p.account, Balance: '1', Sequence: 5 }, ledger_index: 9 };
    if (m === 'account_objects') return { ledger_index: 9, account_objects: [] };
    if (m === 'account_tx') return { transactions: [] };
    return {};
  });
  await scan(page, O);
  await page.evaluate(() => { window.__xdc.settings.watch = true; });
  await page.fill('#addr', D2); // user starts typing another address but does not scan
  const watched = await page.evaluate(() => (window.__xdc.state.watchAddress || window.__xdc.state.last && window.__xdc.state.last.address));
  check(watched === O, `Watch mode stays on the scanned wallet, not whatever is typed in the box (watching ${watched === O ? 'the scanned wallet' : watched})`);
  await ctx.close();
}

// ---------------------------------------------------------------- G. input tricks
{
  const { ctx, page } = await openWith((url, m, p) => {
    if (m === 'account_info') return { account_data: { Account: p.account, Balance: '1', Sequence: 5 }, ledger_index: 9 };
    if (m === 'account_objects') return { ledger_index: 9, account_objects: [] };
    if (m === 'account_tx') return { transactions: [] };
    return {};
  });
  await page.fill('#addr', O.slice(0, 6) + '​' + O.slice(6));
  await page.click('#scan-btn');
  const t1 = await page.textContent('#results');
  check(/hidden|invisible/i.test(t1), 'an address with a hidden character tells the user exactly that');
  const maxlen = await page.getAttribute('#addr', 'maxlength');
  check(maxlen && Number(maxlen) <= 120, `address box has a length limit (${maxlen})`);
  await page.click('#t2');
  await page.fill('#sign-input', 'A'.repeat(3_000_000));
  await page.click('#check-form .btn');
  check(/too (large|long|big)/i.test(await page.textContent('#check-out')), 'a 3 MB paste into the checker is refused, not frozen on');
  await ctx.close();
}

// ---------------------------------------------------------------- H. pre-sign checker cannot be used to inject either
{
  const { ctx, page } = await openWith(evilLedger);
  await page.click('#t2');
  await page.fill('#sign-input', JSON.stringify({ TransactionType: XSS, Account: XSS, Destination: XSS, Amount: { value: XSS, currency: XSS, issuer: XSS },
    Memos: [{ Memo: { MemoData: hex(XSS) } }], RawTransactions: [{ RawTransaction: { TransactionType: XSS } }] }));
  await page.click('#check-form .btn');
  const inj = await injected(page);
  check(!inj.pwned && inj.bad === 0, `a hostile transaction pasted into the checker cannot inject code (pwned=${inj.pwned}, elements=${inj.bad})`);
  await ctx.close();
}

await browser.close(); server.close();
console.log(fails ? `\n${fails} FAILED of ${total}` : `\nALL ${total} PASSED`);
process.exit(fails ? 1 : 0);
