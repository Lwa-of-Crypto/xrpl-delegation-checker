// Smoke test of the exact RELEASE file (no test hooks): loads under CSP, scans Mainnet, cross-check agrees.
import { chromium } from 'playwright';
import http from 'http'; import { readFileSync, readdirSync } from 'fs';
const f = readdirSync('dist').filter((x) => x.endsWith('.html')).sort().pop();
const html = readFileSync('dist/' + f);
const srv = http.createServer((q, r) => { r.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); r.end(html); }).listen(8767);
const b = await chromium.launch({ proxy: { server: process.env.HTTPS_PROXY, bypass: 'localhost' } });
const p = await (await b.newContext({ ignoreHTTPSErrors: true })).newPage();
const errs = []; p.on('pageerror', (e) => errs.push(String(e))); p.on('console', (m) => { if (m.type() === 'error') errs.push(m.text()); });
await p.goto('http://localhost:8767/');
const hooks = await p.evaluate(() => typeof window.__xdc);
await p.fill('#addr', 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh');
await p.click('#scan-btn');
await p.waitForFunction(() => { const r = document.querySelector('#results'); return r && !r.querySelector('.loading') && r.querySelector('.banner'); }, null, { timeout: 90000 });
const t = await p.textContent('#results');
console.log(f);
console.log(hooks === 'undefined' ? 'PASS no test hooks in release' : 'FAIL test hooks present');
console.log(t.includes('No one has delegated power') ? 'PASS release scans Mainnet' : 'FAIL scan: ' + t.slice(0, 200));
console.log(t.includes('Two independent operators agree') ? 'PASS release cross-check agrees' : 'FAIL cross-check');
// Regression (real-wallet test, 24 Oct 2026): the 1.0.3 release loaded the Crossmark SDK wrongly and every
// click said "Cannot read properties of undefined". With no extension installed, both buttons must say so plainly.
await p.click('[data-wallet="crossmark"]'); await p.waitForTimeout(1500);
const cm = await p.textContent('#wallet-status');
console.log(cm.includes('Crossmark is not installed') ? 'PASS Crossmark button works in release' : 'FAIL Crossmark button: ' + cm);
await p.click('[data-wallet="gem"]'); await p.waitForTimeout(6000);
const gm = await p.textContent('#wallet-status');
console.log(gm.includes('GemWallet is not installed') ? 'PASS GemWallet button works in release' : 'FAIL GemWallet button: ' + gm);
// Fact-check finding: a protection switched off in stored settings must be announced on load.
await p.evaluate(() => localStorage.setItem('xdc.settings.v1', JSON.stringify({ strictVerify: false, networkLock: false, persist: true })));
await p.reload(); await p.waitForTimeout(800);
const warn = await p.textContent('#wallet-status');
console.log(/switched OFF: Strict transaction check, Network lock/.test(warn) ? 'PASS stored protections that are OFF are announced on load' : 'FAIL no warning: ' + warn);
await p.evaluate(() => localStorage.clear());
console.log(errs.length ? 'FAIL errors: ' + errs.join(' | ') : 'PASS no page errors');
await b.close(); srv.close();
