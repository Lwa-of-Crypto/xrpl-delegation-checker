export default async function (ctx, S, snap, log) {
  let [sw] = ctx.serviceWorkers(); if (!sw) sw = await ctx.waitForEvent('serviceworker');
  const id = sw.url().split('/')[2];
  const pg = await ctx.newPage(); await pg.goto(`chrome-extension://${id}/index.html`); await pg.waitForTimeout(2000);
  await pg.fill('input[type=password]', 'TestPass-2026!x'); await pg.getByRole('button', { name: /unlock/i }).click(); await pg.waitForTimeout(2500);
  await pg.getByText('Mainnet', { exact: true }).first().click().catch(()=>{}); await pg.waitForTimeout(800);
  await pg.getByText('XRPL Labs Testnet').first().click(); await pg.waitForTimeout(4000);
  await snap(pg, 'gem-home'); await pg.close();
}
export async function approve(p, what, log) {
  if (await p.locator('input[type=password]').count()) { await p.fill('input[type=password]', 'TestPass-2026!x'); await p.getByRole('button', { name: /unlock/i }).click(); await p.waitForTimeout(3500); log('popup unlocked:', (await p.innerText('body')).replace(/\s+/g,' ').slice(0,600)); await p.screenshot({ path: process.env.S + '/ext/gem-popup-' + what + '.png' }); }
  const names = /^(share|connect|accept|confirm|allow|submit|sign)/i;
  const btns = await p.getByRole('button').allInnerTexts(); log('popup buttons:', btns.join(' / '));
  const b = p.getByRole('button', { name: names }).last(); if (await b.count()) { await b.click(); log('clicked approve'); } else log('NO APPROVE BUTTON');
}
