// Real end-to-end: published wallet extension + release build of the tool, Testnet.
import { chromium } from 'playwright';
import { readFileSync } from 'fs';
import http from 'http';
const S = process.env.S, W = process.env.WALLET; // gem | crossmark
const dir = `${S}/crx/${W}`;
const { owner, delegate } = JSON.parse(readFileSync(`${S}/ext/accts.json`));
const html = readFileSync(process.env.TOOL);
const srv = http.createServer((q, r) => { r.writeHead(200, { 'content-type': 'text/html' }); r.end(html); }).listen(8765);
const ctx = await chromium.launchPersistentContext(`${S}/ext/profile-${W}`, { headless: false, viewport: { width: 1200, height: 900 }, args: [`--disable-extensions-except=${dir}`, `--load-extension=${dir}`] });
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);
let n = 0;
const snap = async (p, tag) => { const f = `${S}/ext/${W}-e2e-${String(++n).padStart(2,'0')}-${tag}.png`; await p.screenshot({ path: f }).catch(()=>{}); log('shot', f.split('/').pop(), '|', (await p.innerText('body').catch(()=>'')).replace(/\s+/g, ' ').slice(0, 500)); };
const prep = await import(`./${W}-prep.mjs`);
let auto = false;
ctx.on('page', async (p) => { log('NEW PAGE', p.url().slice(0, 160)); if (!auto || !p.url().startsWith('chrome-extension://')) return;
  try { await p.waitForLoadState(); await p.waitForTimeout(3000); await snap(p, 'popup'); await prep.approve(p, 'any', log); await p.waitForTimeout(6000); if (!p.isClosed()) await snap(p, 'popup-after'); } catch (e) { log('popup handler error', e.message); } });
await (await import(`./${W}-prep.mjs`)).default(ctx, S, snap, log);
const tool = await ctx.newPage(); tool.on('console', m => { if (m.type()==='error') log('console', m.text()); });
await tool.goto('http://localhost:8765/'); await tool.waitForTimeout(1500);
await tool.click('.net [data-net="testnet"]');
if (process.env.NOLOCK) { await tool.getByRole('tab', { name: 'Security' }).click(); await tool.locator('[data-set=networkLock]').evaluate(e => e.click()); log('networkLock now', await tool.locator('[data-set=networkLock]').isChecked()); await tool.getByRole('tab', { name: 'Check a wallet' }).click(); }
await tool.fill('#addr', owner.address); await tool.click('#scan-btn');
await tool.waitForSelector('.card-revoke', { timeout: 60000 }); await snap(tool, 'scanned');
auto = true;
await tool.click(`[data-wallet="${W}"]`);
for (let i=0;i<30;i++){ const t = await tool.innerText('#wallet-status').catch(()=>''); if (i%5===0) log('wallet-status:', t); if (/Connected:/.test(t)) break; await tool.waitForTimeout(2000); } await snap(tool, 'connected');
await tool.click('.card-revoke');
await tool.waitForSelector('#revoke-go:not([hidden])', { timeout: 60000 }).catch(() => log('sign button never appeared'));
await snap(tool, 'confirm');
await tool.click('#revoke-go').catch(e => log('revoke-go click failed', e.message));
await tool.waitForTimeout(40000); await snap(tool, 'result'); log('DIALOG:', (await tool.innerText('#revoke-body').catch(()=>'')).replace(/\s+/g,' ').slice(-700));
const r = await fetch('https://testnet.xrpl-labs.com/', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ method: 'account_objects', params: [{ account: owner.address, type: 'delegate', ledger_index: 'validated' }] }) }).then(r => r.json());
log('LEDGER: delegate objects still on owner =', r.result.account_objects?.length);
await ctx.close(); srv.close();
