// Phones and tablets: the release file must work in mobile browsers (user report, 25 Oct 2026: on Android
// Chrome and iOS Safari, Scan did nothing, because the Crossmark SDK throws on any property read on mobile
// and that stopped the whole page script). Runs every device in Chromium, and in WebKit when it is installed.
import { chromium, webkit, devices } from 'playwright';
import { readFileSync, readdirSync } from 'fs'; import http from 'http';
const f = process.argv[2] || 'dist/' + readdirSync('dist').filter((x) => x.endsWith('.html')).sort().pop();
let fails = 0; const check = (c, m) => { console.log(`${c ? 'PASS' : 'FAIL'} ${m}`); if (!c) fails++; };
const html = readFileSync(f); const srv = http.createServer((q, r) => { r.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }); r.end(html); }).listen(8771);
const engines = [['chromium', chromium]];
try { const b = await webkit.launch(); await b.close(); engines.push(['webkit', webkit]); } catch { console.log('(WebKit not installed: running the iPhone/iPad profiles in Chromium only)'); }
for (const [ename, eng] of engines) {
  for (const d of ['Pixel 7', 'Galaxy S9+', 'iPhone 13', 'iPad (gen 7)']) {
    const b = await eng.launch(); const ctx = await b.newContext({ ...devices[d] }); const p = await ctx.newPage();
    const errs = []; p.on('pageerror', (e) => errs.push(e.message));
    await p.goto('http://localhost:8771/');
    await p.tap('#addr'); await p.fill('#addr', 'not-an-address'); await p.tap('#scan-btn');
    const bad = await p.waitForFunction(() => /Not a valid address/.test(document.getElementById('results').innerText), null, { timeout: 5000 }).then(() => true).catch(() => false);
    check(bad, `${ename} · ${d}: Scan responds (invalid address is explained)`);
    await p.fill('#addr', 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh'); await p.tap('#scan-btn');
    const done = await p.waitForFunction(() => /delegated power|Could not complete|operator/.test(document.getElementById('results').innerText), null, { timeout: 60000 }).then(() => true).catch(() => false);
    check(done, `${ename} · ${d}: a live Mainnet scan shows a result`);
    await p.tap('button:has-text("Crossmark")');
    const cm = await p.waitForFunction(() => /desktop browser extension/.test(document.body.innerText), null, { timeout: 5000 }).then(() => true).catch(() => false);
    check(cm, `${ename} · ${d}: Crossmark button explains it is desktop-only`);
    check(errs.length === 0, `${ename} · ${d}: no page errors${errs.length ? ' (' + errs.join(' | ').slice(0, 200) + ')' : ''}`);
    await b.close();
  }
}
srv.close();
console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED');
process.exit(fails ? 1 : 0);
