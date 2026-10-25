export default async function (ctx, S, snap, log) {
  let [sw] = ctx.serviceWorkers(); if (!sw) sw = await ctx.waitForEvent('serviceworker');
  const id = sw.url().split('/')[2];
  const pg = await ctx.newPage(); await pg.goto(`chrome-extension://${id}/popup.html`); await pg.waitForTimeout(3000);
  if (/UNLOCK/.test(await pg.innerText('body')) && !/WELCOME BACK \| JADE|BALANCE/.test((await pg.innerText('body')).replace(/\n/g,' | '))) log('locked at prep');
  await snap(pg, 'cm-home'); await pg.close();
}
export async function approve(p, what, log) {
  for (let round = 0; round < 6 && !p.isClosed(); round++) {
    const t = (await p.innerText('body').catch(() => '')).replace(/\s+/g, ' ');
    log(`popup[${round}]:`, t.slice(0, 1200));
    const exact = async (txt) => { const re = new RegExp('^\\s*' + txt + '\\s*$', 'i'); let el = p.getByRole('button', { name: re }).last(); if (!(await el.count().catch(() => 0))) el = p.getByText(re).last(); if (!(await el.count().catch(() => 0))) return false; try { await el.click({ timeout: 4000 }); log('clicked', txt); return true; } catch { log('click failed', txt); return false; } };
    let ok = false;
    if (/ENTER PASSWORD/.test(t)) { await p.mouse.click(600, 250); await p.keyboard.type('TestPass2026!x', { delay: 40 }); await p.waitForTimeout(500); await p.mouse.click(600, 698); log('typed password + ENTER'); ok = true; await p.waitForTimeout(8000); }
    else if (/ARE YOU SURE\?/.test(t)) { await p.getByText(/Acknowledge warning/i).last().click({ timeout: 3000 }).catch(() => log('no ack box')); await p.waitForTimeout(600); ok = await exact('PROCEED'); }
    else if (/GRANT ACCESS/.test(t)) ok = await exact('GRANT ACCESS');
    else if (/SIGNIN/.test(t)) { await p.getByText(/^r[1-9A-HJ-NP-Za-km-z]{8,}/).first().click({ timeout: 3000 }).catch(() => log('no account row')); await p.waitForTimeout(800); ok = await exact('CONFIRM'); }
    else if (/CONFIRM/.test(t)) ok = await exact('CONFIRM');
    if (!ok) break;
    await p.waitForTimeout(4000);
    await p.screenshot({ path: `${process.env.S}/ext/crossmark-popup-${Date.now()}.png` }).catch(() => {});
  }
}
