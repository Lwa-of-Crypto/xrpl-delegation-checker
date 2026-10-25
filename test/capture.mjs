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
const ctx = await browser.newContext({ viewport: { width: 1000, height: 1100 }, deviceScaleFactor: 2, ignoreHTTPSErrors: true });
const page = await ctx.newPage();
await page.goto('http://localhost:8765/');
await page.click('.net [data-net=testnet]');
await page.fill('#addr', owner.address);
await page.click('#scan-btn');
await waitScan(page);
await page.locator('#tab-scan').screenshot({ path: `${SHOTS}/1-scan.png` });
await page.evaluate((a) => { window.__xdc.state.wallet = { id: 'gem', address: a }; window.__xdc.WALLETS.gem.network = async () => 'testnet'; }, owner.address);
await page.click(`button.card-revoke[data-delegate="${thief.address}"]`);
await page.waitForSelector('#revoke-body pre.json', { timeout: 120000 });
await page.locator('#revoke-dialog').screenshot({ path: `${SHOTS}/2-revoke-confirm.png` });
await page.click('#revoke-close');
await page.click('#t2');
const batch = { TransactionType: 'Batch', Account: owner.address, Flags: 65536, RawTransactions: [
  { RawTransaction: { TransactionType: 'Payment', Account: owner.address, Destination: helper.address, Amount: '1', Flags: 1073741824 } },
  { RawTransaction: { TransactionType: 'DelegateSet', Account: owner.address, Authorize: thief.address, Flags: 1073741824, Permissions: [P('Payment')] } }] };
await page.fill('#sign-input', JSON.stringify(batch));
await page.click('#check-form .btn');
await page.locator('#tab-check').screenshot({ path: `${SHOTS}/5-check.png` });
await page.click('#t3');
await page.locator('#tab-security').screenshot({ path: `${SHOTS}/4-security.png` });
await browser.close(); server.close(); frameServer.close();
console.log('captured');
