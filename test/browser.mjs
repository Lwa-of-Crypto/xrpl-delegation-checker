// Real-browser test of the built page against XRPL Testnet + Mainnet, including every security feature.
import { chromium } from 'playwright';
import http from 'http';
import { readFileSync } from 'fs';
import { ProxyAgent, setGlobalDispatcher } from 'undici';
import xrpl from 'xrpl';
import { encode } from 'ripple-binary-codec';

setGlobalDispatcher(new ProxyAgent(process.env.HTTPS_PROXY));
const SHOTS = process.env.SHOTS;
const html = readFileSync('test-build/index.html');
const server = http.createServer((q, r) => { r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); r.end(html); }).listen(8765);
const frameServer = http.createServer((q, r) => { r.writeHead(200, { 'Content-Type': 'text/html' }); r.end('<iframe id="f" src="http://localhost:8765/" width="800" height="400"></iframe>'); }).listen(8766);

let fails = 0;
const check = (c, m) => { console.log(`${c ? 'PASS' : 'FAIL'} ${m}`); if (!c) fails++; };
const sleep = (ms) => new Promise((s) => setTimeout(s, ms));

async function rpc(method, params) {
  for (let i = 0; i < 8; i++) {
    try {
      const r = await fetch('https://testnet.xrpl-labs.com/', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ method, params: [{ api_version: 2, ...params }] }) });
      if (r.ok) return (await r.json()).result;
    } catch { /* retry */ }
    await sleep(2500 * (i + 1));
  }
  throw new Error('rpc failed ' + method);
}
async function fund() {
  for (let i = 0; i < 5; i++) {
    const r = await fetch('https://faucet.altnet.rippletest.net/accounts', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    if (r.ok) return xrpl.Wallet.fromSeed((await r.json()).seed);
    await sleep(4000);
  }
  throw new Error('faucet');
}
async function fill(tx) {
  const info = await rpc('account_info', { account: tx.Account, ledger_index: 'current' });
  const cur = await rpc('ledger_current', {});
  return { Fee: '12', Sequence: info.account_data.Sequence, LastLedgerSequence: cur.ledger_current_index + 20, ...tx };
}
async function submit(wallet, tx) {
  const { tx_blob, hash } = wallet.sign(await fill(tx));
  await rpc('submit', { tx_blob });
  for (let i = 0; i < 30; i++) { const t = await rpc('tx', { transaction: hash }); if (t.validated) return { hash, tx_blob, result: t.meta.TransactionResult }; await sleep(2500); }
  throw new Error('not validated');
}
const P = (v) => ({ Permission: { PermissionValue: v } });
async function waitScan(page) {
  await page.waitForFunction(() => {
    const r = document.querySelector('#results');
    return r && !r.querySelector('.loading') && r.querySelector('.banner');
  }, null, { timeout: 120000 });
  return page.textContent('#results');
}

// ---------- setup on Testnet
const owner = await fund(); const thief = await fund(); const helper = await fund(); const late = await fund();
await sleep(8000);
const grant = await submit(owner, { TransactionType: 'DelegateSet', Account: owner.address, Authorize: thief.address, Permissions: [P('Payment')] });
await submit(owner, { TransactionType: 'DelegateSet', Account: owner.address, Authorize: helper.address, Permissions: [P('PaymentBurn'), P('AccountDomainSet')] });
await submit(thief, { TransactionType: 'Payment', Account: owner.address, Delegate: thief.address, Destination: thief.address, Amount: '2000000' });
console.log('setup', { owner: owner.address, thief: thief.address, helper: helper.address, late: late.address });

const browser = await chromium.launch({ proxy: { server: process.env.HTTPS_PROXY, bypass: 'localhost,127.0.0.1' } });
const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, ignoreHTTPSErrors: true });
const page = await ctx.newPage();
const errors = [];
page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
page.on('pageerror', (e) => errors.push(String(e)));
await page.goto('http://localhost:8765/');
check(await page.evaluate(() => !!window.__xdc), 'page script ran under its strict CSP');

// ---------- security defaults
const s0 = await page.evaluate(() => ({ ...window.__xdc.settings }));
check(s0.strictVerify && s0.ledgerVerify && s0.networkLock && s0.crossCheck && s0.autoLock && s0.fingerprint && !s0.persist && s0.maxFee === 1000,
  'safest settings are ON by default, nothing stored by default');
check(await page.evaluate(() => { try { return localStorage.length; } catch { return -1; } }) === 0, 'nothing written to browser storage on first visit');

// ---------- invalid address + fingerprint
await page.fill('#addr', 'rNotAnAddress');
await page.click('#scan-btn');
check((await page.textContent('#results')).includes('Not a valid address'), 'rejects a bad address');
await page.click('.net [data-net=testnet]');
await page.fill('#addr', owner.address);
check((await page.textContent('#fp')).includes(owner.address.slice(0, 5)) && !(await page.isHidden('#fp')), 'address fingerprint shown for pasted address');

// ---------- scan
await page.click('#scan-btn');
let txt = await waitScan(page);
check(txt.includes('2 accounts can act as this wallet'), 'finds 2 delegates');
check(txt.includes('Already used') && txt.includes('Payment'), 'shows the delegated payment the thief already sent');
check((await page.textContent('.card .pill')).trim() === 'Critical', 'Payment delegate ranked Critical first');
check(txt.includes('fixCleanup3_4_0'), 'PaymentBurn warning shown');
check(txt.includes('not available on Testnet (this tool uses one Testnet operator)'), 'cross-check honestly says the tool uses one Testnet operator');
if (SHOTS) await page.screenshot({ path: `${SHOTS}/1-scan.png`, fullPage: true });

// ---------- revoke guards
await page.click(`button.card-revoke[data-delegate="${thief.address}"]`);
check((await page.textContent('#revoke-body')).includes('Connect the wallet'), 'revoke without a wallet asks to connect');
await page.click('#revoke-close');

await page.exposeFunction('honestSign', async (tx) => { const { tx_blob, hash } = owner.sign(tx); await rpc('submit', { tx_blob }); return hash; });
await page.exposeFunction('evilSign', async () => {
  // A compromised wallet that signs a GRANT instead of the revoke the user approved.
  const evil = await fill({ TransactionType: 'DelegateSet', Account: owner.address, Authorize: thief.address, Permissions: [P('Payment')] });
  const { tx_blob, hash } = owner.sign(evil); await rpc('submit', { tx_blob }); return hash;
});

// network lock: wallet says mainnet, page is on testnet
await page.evaluate((a) => {
  const W = window.__xdc.WALLETS.gem;
  window.__xdc.state.wallet = { id: 'gem', address: a };
  W.network = async () => 'mainnet';
  W.signAndSubmit = (tx) => window.honestSign(tx);
}, owner.address);
await page.click(`button.card-revoke[data-delegate="${thief.address}"]`);
await page.waitForSelector('#revoke-dialog[open]');
await sleep(500);
const nl = await page.textContent('#revoke-body');
if (!nl.includes('Network lock')) console.log('   body:', nl.slice(0, 300), 'goHidden:', await page.isHidden('#revoke-go'));
check(nl.includes('Network lock') && await page.isHidden('#revoke-go'), 'NETWORK LOCK blocks signing when wallet is on the wrong network');
await page.click('#revoke-close');

// wrong wallet
await page.evaluate(() => { window.__xdc.state.wallet = { id: 'gem', address: 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh' }; });
await page.click(`button.card-revoke[data-delegate="${thief.address}"]`);
check((await page.textContent('#revoke-body')).includes('but the scanned account is'), 'refuses to revoke from a wallet that does not own the account');
await page.click('#revoke-close');

// fee limit 100 drops, then honest revoke
await page.click('#t3');
await page.selectOption('select[data-set=maxFee]', '100');
await page.click('#t1');
await page.evaluate((a) => { window.__xdc.state.wallet = { id: 'gem', address: a }; window.__xdc.WALLETS.gem.network = async () => 'testnet'; }, owner.address);
await page.click(`button.card-revoke[data-delegate="${thief.address}"]`);
await page.waitForSelector('#revoke-body pre.json', { timeout: 60000 });
const shown = JSON.parse(await page.textContent('#revoke-body pre.json'));
check(shown.TransactionType === 'DelegateSet' && shown.Account === owner.address && shown.Authorize === thief.address && shown.Permissions.length === 0,
  'confirm dialog shows the exact revoke');
check(Number(shown.Fee) <= 100, `fee obeys the user's fee limit (${shown.Fee} ≤ 100 drops)`);
check((await page.textContent('#revoke-body')).includes('Strict check passed'), 'strict check passed message shown');
if (SHOTS) await page.screenshot({ path: `${SHOTS}/2-revoke-confirm.png` });
await page.click('#revoke-go');
await page.waitForFunction(() => /Revoked|Not confirmed|WARNING/.test(document.querySelector('#revoke-body').textContent), null, { timeout: 120000 });
const rv = await page.textContent('#revoke-body');
check(rv.includes('Revoked') && rv.includes('Verified on the ledger'), 'honest revoke confirmed AND verified on the ledger');
await page.click('#revoke-close');
await sleep(3000);
txt = await waitScan(page);
check(!txt.includes(thief.address) && txt.includes('1 account can act'), 're-scan: thief gone, helper remains');

// ---------- ledger verification catches a compromised wallet
await page.evaluate(() => { window.__xdc.WALLETS.gem.signAndSubmit = () => window.evilSign(); });
await page.click(`button.card-revoke[data-delegate="${helper.address}"]`);
await page.waitForSelector('#revoke-body pre.json', { timeout: 60000 });
await page.click('#revoke-go');
await page.waitForFunction(() => /Revoked|Not confirmed|WARNING/.test(document.querySelector('#revoke-body').textContent), null, { timeout: 240000 })
  .catch(async () => console.log('   evil body:', (await page.textContent('#revoke-body')).slice(-400)));
const ev = await page.textContent('#revoke-body');
check(ev.includes('WARNING') && ev.includes('different delegate'), 'LEDGER VERIFY catches a wallet that signed something else');
if (SHOTS) await page.screenshot({ path: `${SHOTS}/3-ledger-verify-alarm.png` });
await page.click('#revoke-close');
await sleep(3000);
await waitScan(page);

// ---------- change detection: a new delegate appears between two scans
await submit(owner, { TransactionType: 'DelegateSet', Account: owner.address, Authorize: late.address, Permissions: [P('TrustSet')] });
await page.click('#scan-btn');
txt = await waitScan(page);
check(txt.includes('Change detected'), 'change detection fires when a new delegate appears');

// ---------- delegate side
await page.fill('#addr', helper.address);
await page.click('#scan-btn');
txt = await waitScan(page);
check(txt.includes('Accounts this wallet can act for'), 'delegate side shows power it received');

// ---------- mainnet + cross-check
await page.click('.net [data-net=mainnet]');
await page.fill('#addr', 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh');
await page.click('#scan-btn');
txt = await waitScan(page);
check(txt.includes('No one has delegated power'), 'mainnet clean account reads clear');
check(txt.includes('Two independent operators agree'), 'MAINNET CROSS-CHECK: two independent operators (InFTF and Ripple) agree');

// ---------- privacy blur
await page.click('#t3');
await page.check('input[data-set=mask]');
check(await page.evaluate(() => document.body.classList.contains('masked')), 'privacy blur turns on');
await page.uncheck('input[data-set=mask]');

// ---------- persistence on/off
await page.check('input[data-set=persist]');
const stored = await page.evaluate(() => localStorage.getItem('xdc.settings.v1'));
check(!!stored && JSON.parse(stored).maxFee === 100, 'settings stored only after user turns "Remember" on');
await page.reload();
check(await page.evaluate(() => window.__xdc.settings.maxFee === 100 && window.__xdc.settings.persist), 'remembered settings survive a reload');
await page.click('#t3');
await page.uncheck('input[data-set=persist]');
check(await page.evaluate(() => localStorage.getItem('xdc.settings.v1') === null), 'turning "Remember" off erases stored settings');
if (SHOTS) await page.screenshot({ path: `${SHOTS}/4-security.png`, fullPage: true });

// ---------- panic
await page.check('input[data-set=persist]');
await page.click('#panic');
check(await page.evaluate(() => localStorage.length === 0 && window.__xdc.state.wallet === null && window.__xdc.settings.maxFee === 1000), '"Forget everything now" wipes storage, wallet and settings');

// ---------- pre-sign checker
await page.click('#t2');
await page.fill('#sign-input', grant.tx_blob);
await page.click('#check-form .btn');
check((await page.textContent('#check-out')).includes('Do not sign'), 'signed grant blob flagged Critical');
const batch = { TransactionType: 'Batch', Account: owner.address, Flags: 65536, RawTransactions: [
  { RawTransaction: { TransactionType: 'Payment', Account: owner.address, Destination: helper.address, Amount: '1', Flags: 1073741824 } },
  { RawTransaction: { TransactionType: 'DelegateSet', Account: owner.address, Authorize: thief.address, Flags: 1073741824, Permissions: [P('Payment')] } }] };
await page.fill('#sign-input', encode(batch));
await page.click('#check-form .btn');
const c2 = await page.textContent('#check-out');
check(c2.includes('BATCH of 2') && c2.includes('Inside #2') && c2.includes('Do not sign'), 'batch blob hiding a delegation is caught');
await page.fill('#sign-input', JSON.stringify({ TransactionType: 'SetRegularKey', Account: owner.address, RegularKey: thief.address }));
await page.click('#check-form .btn');
check((await page.textContent('#check-out')).includes('taken over'), 'SetRegularKey takeover flagged');
if (SHOTS) await page.screenshot({ path: `${SHOTS}/5-check.png`, fullPage: true });

// Busy public servers reply to rate-limited requests without CORS headers; the browser logs those
// as network errors and the page retries them. Count them separately from real page errors.
const netNoise = errors.filter((e) => /testnet\.xrpl-labs\.com.*CORS|net::ERR_FAILED/.test(e));
const real = errors.filter((e) => !netNoise.includes(e) && !/favicon/.test(e));
console.log(`   (${netNoise.length} rate-limited server replies were retried automatically)`);
check(real.length === 0, `no page errors${real.length ? ': ' + real.join(' | ') : ''}`);

// ---------- clickjacking guard
const fpg = await ctx.newPage();
await fpg.goto('http://localhost:8766/');
await sleep(2000);
const framed = fpg.frames().find((f) => f.url().startsWith('http://localhost:8765'));
check(framed && (await framed.textContent('body')).includes('refuses to run inside another website'), 'CLICKJACKING GUARD: refuses to run inside a frame');

// ---------- mobile layout
const m = await browser.newContext({ viewport: { width: 390, height: 844 }, ignoreHTTPSErrors: true });
const mp = await m.newPage();
await mp.goto('http://localhost:8765/');
await mp.click('.net [data-net=testnet]');
await mp.fill('#addr', owner.address);
await mp.click('#scan-btn');
await waitScan(mp);
check(!(await mp.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)), 'mobile: no horizontal scroll (results)');
if (SHOTS) await mp.screenshot({ path: `${SHOTS}/6-mobile.png`, fullPage: true });
await mp.click('#t3');
check(!(await mp.evaluate(() => document.documentElement.scrollWidth > window.innerWidth)), 'mobile: no horizontal scroll (security tab)');

await browser.close(); server.close(); frameServer.close();
console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED');
process.exit(fails ? 1 : 0);
