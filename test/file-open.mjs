// Opens the RELEASE file straight from disk (file://), the way someone who downloads it will.
import { chromium } from 'playwright';
import { readdirSync } from 'fs';
const f = readdirSync('dist').filter((x) => x.endsWith('.html')).sort().pop();
const b = await chromium.launch({ proxy: { server: process.env.HTTPS_PROXY } });
const p = await (await b.newContext({ ignoreHTTPSErrors: true })).newPage();
const errs = []; p.on('pageerror', (e) => errs.push(String(e)));
await p.goto('file://' + process.cwd() + '/dist/' + f);
await p.fill('#addr', 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh');
await p.click('#scan-btn');
await p.waitForFunction(() => { const r = document.querySelector('#results'); return r && !r.querySelector('.loading') && r.querySelector('.banner'); }, null, { timeout: 120000 });
const t = await p.textContent('#results');
console.log(t.includes('No one has delegated power') ? 'PASS release works opened from disk (file://), Mainnet scan' : 'FAIL ' + t.slice(0, 200));
console.log(t.includes('Two independent operators agree') ? 'PASS cross-check works from disk' : 'FAIL cross-check from disk: ' + t.slice(0, 160));
console.log(errs.length ? 'FAIL ' + errs.join('|') : 'PASS no page errors from disk');
await b.close();
