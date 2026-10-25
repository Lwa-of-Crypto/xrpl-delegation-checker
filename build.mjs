// Builds the single self-contained HTML file.
import { build } from 'esbuild';
import { readFileSync, writeFileSync, mkdirSync } from 'fs';
import { createHash } from 'crypto';

const VERSION = '1.0.4';
const DATE = '2026-10-24';

const TEST = process.argv.includes('--test');
const res = await build({
  entryPoints: ['src/main.js'], bundle: true, format: 'iife', platform: 'browser', target: 'es2020',
  minify: true, write: false, legalComments: 'none', define: { 'process.env.NODE_ENV': '"production"', global: 'globalThis', __TEST_BUILD__: String(TEST) },
  inject: ['src/shims.js'],
});
let js = res.outputFiles[0].text;
js = js.replace(/<\/script/gi, '<\\/script');
const hash = createHash('sha256').update(js, 'utf8').digest('base64');
const html = readFileSync('src/template.html', 'utf8')
  .replace('__SCRIPT_HASH__', `sha256-${hash}`)
  .replace('__VERSION__', `${VERSION} · ${DATE}`)
  .replace('__BUNDLE__', () => js);
mkdirSync('dist', { recursive: true });
const out = TEST ? 'test-build/index.html' : `dist/xrpl-delegation-checker--${DATE}.html`;
mkdirSync('test-build', { recursive: true });
writeFileSync(out, html);
console.log(out, (html.length / 1024).toFixed(0) + ' KB', 'sha256-' + hash);

if (!TEST) {
  // Server security headers (Cloudflare Pages / Netlify "_headers" format). These add the protections
  // a <meta> tag cannot: frame-ancestors, HSTS, nosniff, and a locked-down permissions policy.
  const csp = `default-src 'none'; script-src 'sha256-${hash}'; style-src 'unsafe-inline'; img-src data:; ` +
    "connect-src https://xrplcluster.com https://xrpl.ws https://testnet.xrpl-labs.com https://faucet.altnet.rippletest.net wss://s1.ripple.com wss://s2.ripple.com wss://honeycluster.io; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
  const headers = `# Security headers for the XRPL Delegation Checker (version ${VERSION} · ${DATE}).
# Cloudflare Pages / Netlify: merge these lines into your site's _headers file.
# Change the path line below (it starts with /tools/) if you host the page somewhere else.
# The script hash below matches THIS build only — rebuild the headers with every new version.
/tools/xrpl-delegation-checker/*
  Content-Security-Policy: ${csp}
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Resource-Policy: same-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=(), clipboard-read=()
`;
  mkdirSync('release', { recursive: true });
  writeFileSync(`release/_headers--${DATE}.txt`, headers);
  const fileHash = createHash('sha256').update(html).digest('hex');
  writeFileSync(`release/SHA256SUMS--${DATE}.txt`, `${fileHash}  xrpl-delegation-checker--${DATE}.html\n`);
  console.log('file sha256', fileHash);
}
