// XRPL Delegation Checker — page logic.
// Created by Stanley Gebara · CryptoLwa (cryptolwa.io) · Open source (MIT).
import * as core from './core.js';
import * as lab from './lab.js';
import * as Gem from '@gemwallet/api';
import * as crossmarkModule from '@crossmarkio/sdk';

// The Crossmark SDK ships as a UMD bundle. Depending on how the bundler treats CommonJS ("type": "module"
// or not), the SDK object is the module itself, its .default, or its .default.default. Pick whichever one
// actually has the SDK on it, so the build setting can never silently break the Crossmark button again
// (real-wallet test finding, v1.0.3: the release build got the wrapper object and every click failed).
//
// On phones and tablets the SDK object throws "Crossmark only available from desktop" the moment ANY of its
// properties is read. Reading it unguarded here stopped the whole page script on Android and iOS, so Scan did
// nothing at all (user report, 25 Oct 2026). Every read is guarded; the page works without Crossmark.
let crossmark = null;
let crossmarkUnavailable = '';
for (const pick of [(m) => m, (m) => m.default, (m) => m.default && m.default.default]) {
  try {
    const m = pick(crossmarkModule);
    if (m && m.sync && m.methods) { crossmark = m; break; }
  } catch (e) {
    crossmarkUnavailable = String((e && e.message) || e || 'unavailable');
  }
}
const CROSSMARK_DESKTOP_ONLY = 'Crossmark is a desktop browser extension, so it cannot connect on a phone or tablet. Scanning works here. To revoke, use Crossmark or GemWallet on a desktop browser, or copy the transaction and sign it elsewhere.';

// ================================================================ ALWAYS-ON: clickjacking guard
// This page must never run inside someone else's frame (a hidden frame could trick clicks).
if (window.top !== window.self) {
  document.documentElement.innerHTML = '<body style="font:16px system-ui;padding:24px">This tool refuses to run inside another website. Open it directly in its own tab.</body>';
  throw new Error('framed');
}

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const short = (a) => (a ? `${a.slice(0, 6)}…${a.slice(-5)}` : '');
const addr = (a) => `<code class="sensitive" tabindex="0">${esc(a)}</code>`;
const addrShort = (a) => `<code class="sensitive" tabindex="0">${esc(short(a))}</code>`;

// ================================================================ USER SECURITY SETTINGS
const DEFAULTS = Object.freeze({
  crossCheck: true,    // compare answers from two independent ledger servers
  strictVerify: true,  // check the revoke transaction field-by-field before the wallet sees it
  ledgerVerify: true,  // after signing, read the transaction back from the ledger and confirm it
  networkLock: true,   // refuse to sign if the wallet is on a different network than the page
  maxFee: 1000,        // fee limit in drops (1,000 drops = 0.001 XRP)
  autoLock: true,      // forget the connected wallet after inactivity
  autoLockMin: 5,
  fingerprint: true,   // show the first/last characters of a pasted address to beat clipboard swaps
  mask: false,         // blur addresses on screen (screen sharing / streaming)
  watch: false,        // re-scan automatically and alert on any change
  watchMin: 10,
  notify: false,       // use browser notifications for watch alerts
  persist: false,      // remember these settings on this device
});
const STORE_KEY = 'xdc.settings.v1';

// Only these exact values are ever accepted for the numeric settings (attack-suite finding: a tampered
// stored value such as a 99,999,999-drop fee limit or a 0.0001-minute Watch timer used to be accepted).
const ALLOWED = Object.freeze({ maxFee: [100, 1000, 5000], autoLockMin: [2, 5, 15], watchMin: [5, 10, 30] });
function validSetting(k, v) {
  if (!(k in DEFAULTS)) return false;
  if (ALLOWED[k]) return ALLOWED[k].includes(v);
  return typeof v === 'boolean' && typeof DEFAULTS[k] === 'boolean';
}

function loadSettings() {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (raw && raw.length < 2000) {
      const saved = JSON.parse(raw);
      const s = { ...DEFAULTS };
      if (saved && typeof saved === 'object') for (const k of Object.keys(DEFAULTS)) if (validSetting(k, saved[k])) s[k] = saved[k];
      s.persist = true;
      return s;
    }
  } catch { /* storage blocked or corrupted — use defaults */ }
  return { ...DEFAULTS };
}
const settings = loadSettings();
// Fact-check finding (24 Oct 2026): a stored true/false value is accepted, so anything that can write this
// browser's storage could switch a protection off. We cannot prevent that from inside the page, so we make it
// impossible to miss: any safety switch that loads as OFF from storage is announced the moment the page opens.
const SAFETY_SWITCHES = { strictVerify: 'Strict transaction check', ledgerVerify: 'Verify on the ledger after signing', networkLock: 'Network lock', crossCheck: 'Second-operator cross-check', fingerprint: 'Address fingerprint' };
const loadedOff = settings.persist ? Object.keys(SAFETY_SWITCHES).filter((k) => DEFAULTS[k] === true && settings[k] === false) : [];

function saveSettings() {
  try {
    if (settings.persist) localStorage.setItem(STORE_KEY, JSON.stringify(settings));
    else localStorage.removeItem(STORE_KEY);
  } catch { /* storage blocked */ }
}

const SETTINGS_UI = [
  { group: 'Protect what you sign' },
  { key: 'strictVerify', title: 'Strict transaction check', body: 'Before your wallet opens, the page checks the revoke transaction field by field: right type, right account, right delegate, empty permission list, fee under your limit. Anything else is blocked.' },
  { key: 'ledgerVerify', title: 'Verify on the ledger after signing', body: 'After your wallet submits, the page reads the transaction back from the XRP Ledger and confirms it is exactly the revoke you approved. If not, you get a loud warning.' },
  { key: 'networkLock', title: 'Network lock', body: 'Refuses to sign if your wallet is set to a different network than this page (for example, wallet on Testnet while the page shows Mainnet).' },
  { key: 'maxFee', title: 'Fee limit', type: 'select', options: [[100, '0.0001 XRP'], [1000, '0.001 XRP'], [5000, '0.005 XRP']], body: 'The most this page will ever ask your wallet to pay in network fees. Normal fee is 0.00001 XRP.' },
  { group: 'Protect what you see' },
  { key: 'crossCheck', title: 'Second-operator cross-check', body: 'Asks two DIFFERENT companies\' public ledger servers (InFTF and Ripple, or Honeycluster as a backup) the same question and warns you if their answers differ. After a revoke, both must confirm it. Mainnet only.' },
  { key: 'fingerprint', title: 'Address fingerprint', body: 'When you paste an address, its first and last five characters are shown large so you can compare them with your wallet. This defeats clipboard malware that swaps addresses.' },
  { key: 'mask', title: 'Privacy blur', body: 'Blurs every address on screen until you hover or tap it. Use when screen sharing or streaming.' },
  { group: 'Protect your session' },
  { key: 'autoLock', title: 'Auto-disconnect wallet', body: 'Forgets the connected wallet after a few minutes without activity, so an unattended screen cannot be used to sign.', extra: { key: 'autoLockMin', options: [[2, '2 min'], [5, '5 min'], [15, '15 min']] } },
  { key: 'watch', title: 'Watch mode', body: 'While this tab stays open, re-checks the last scanned wallet on a timer and alerts you the moment a new delegate appears or one changes.', extra: { key: 'watchMin', options: [[5, 'every 5 min'], [10, 'every 10 min'], [30, 'every 30 min']] } },
  { key: 'notify', title: 'Browser notifications for Watch mode', body: 'Shows a system notification when Watch mode finds a change, even if this tab is in the background. Your browser will ask permission.' },
  { key: 'persist', title: 'Remember these settings on this device', body: 'Off by default: nothing is stored. Turn on to keep your choices in this browser only. Turning it off erases them.' },
];

function renderSettings() {
  $('#settings').innerHTML = SETTINGS_UI.map((s) => {
    if (s.group) return `<h3 class="set-group">${esc(s.group)}</h3>`;
    const control = s.type === 'select'
      ? `<select data-set="${s.key}" aria-label="${esc(s.title)}">${s.options.map(([v, l]) => `<option value="${v}" ${settings[s.key] === v ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>`
      : `<label class="switch"><input type="checkbox" role="switch" data-set="${s.key}" ${settings[s.key] ? 'checked' : ''} aria-label="${esc(s.title)}"><span aria-hidden="true"></span></label>`;
    const extra = s.extra ? `<select data-set="${s.extra.key}" aria-label="${esc(s.title)} timing">${s.extra.options.map(([v, l]) => `<option value="${v}" ${settings[s.extra.key] === v ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>` : '';
    return `<div class="setting"><div><strong>${esc(s.title)}</strong><p>${esc(s.body)}</p>${extra}</div>${control}</div>`;
  }).join('') + `<div class="set-actions"><button class="btn ghost" type="button" id="reset-safe">Reset to safest defaults</button>
    <button class="btn revoke" type="button" id="panic">Forget everything now</button></div>
    <p class="hint">Always on, cannot be turned off: no secret keys ever requested, no server of our own, no trackers, strict Content-Security-Policy, refuses to run inside another site's frame, all ledger text escaped before display.</p>`;
  document.querySelectorAll('[data-set]').forEach((el) => el.addEventListener('change', onSettingChange));
  $('#reset-safe').addEventListener('click', () => { Object.assign(settings, DEFAULTS, { persist: settings.persist }); applySettings(); renderSettings(); flashSaved('Safest defaults restored.'); });
  $('#panic').addEventListener('click', panic);
}

async function onSettingChange(ev) {
  const el = ev.target;
  const key = el.dataset.set;
  const v = el.type === 'checkbox' ? el.checked : Number(el.value);
  if (!validSetting(key, v)) { renderSettings(); return; }
  settings[key] = v;
  if (key === 'notify' && settings.notify) {
    if (!('Notification' in window)) { settings.notify = false; el.checked = false; flashSaved('This browser does not support notifications.'); }
    else if (Notification.permission !== 'granted') {
      const p = await Notification.requestPermission().catch(() => 'denied');
      if (p !== 'granted') { settings.notify = false; el.checked = false; flashSaved('Notifications were not allowed by the browser.'); }
    }
  }
  applySettings();
  flashSaved(settings.persist ? 'Saved on this device.' : 'Applied for this visit (not stored).');
}

function flashSaved(msg) {
  const el = $('#set-status');
  el.textContent = msg;
  clearTimeout(flashSaved.t);
  flashSaved.t = setTimeout(() => { el.textContent = ''; }, 3500);
}

function applySettings() {
  document.body.classList.toggle('masked', settings.mask);
  saveSettings();
  scheduleWatch();
  updateFingerprint();
}

function panic() {
  try { localStorage.removeItem(STORE_KEY); sessionStorage.clear(); } catch { /* ignore */ }
  Object.assign(settings, DEFAULTS);
  leaveLab();
  state.wallet = null;
  state.last = null;
  state.watchFp = null;
  state.watchAddress = null;
  state.scanToken++;
  state.lastActivityHtml = ''; state.lastActivityFor = null;
  if (state.activitySignal) state.activitySignal.aborted = true;
  clearInterval(state.watchTimer);
  $('#addr').value = '';
  $('#sign-input').value = '';
  $('#results').innerHTML = '';
  $('#check-out').innerHTML = '';
  setWalletStatus('Disconnected. Everything this page knew has been forgotten.', false, false);
  applySettings();
  renderSettings();
  flashSaved('Everything forgotten. Close the tab to be completely sure.');
}

// ================================================================ STATE
const state = { network: 'mainnet', rpc: core.makeRpc('mainnet'), wallet: null, last: null,
  lastActivity: Date.now(), watchTimer: null, watchFp: null, watchAddress: null,
  busy: false,      // a revoke is in flight: network switching is locked (attack-suite finding)
  scanToken: 0,     // every scan gets a number; answers from an older scan are thrown away
  activitySignal: null, lastActivityHtml: '', lastActivityFor: null,
  labBusy: false };

// ---------------------------------------------------------------- network
document.querySelectorAll('.net [data-net]').forEach((b) => b.addEventListener('click', () => {
  if (state.busy) { flashNet('Finish or close the revoke first. The network cannot change while a transaction is in flight.'); return; }
  if (b.dataset.net === state.network) return;
  state.network = b.dataset.net;
  state.rpc = core.makeRpc(state.network);
  state.scanToken++;
  document.querySelectorAll('.net [data-net]').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
  document.body.dataset.net = state.network;
  $('#results').innerHTML = '';
  state.last = null;
  state.watchFp = null;
  state.watchAddress = null;
  leaveLab();
}));
function flashNet(msg) {
  const el = $('.testnet-flag');
  const old = el.textContent;
  el.textContent = msg; el.style.display = 'block';
  setTimeout(() => { el.textContent = old; el.style.display = ''; }, 4000);
}

// ---------------------------------------------------------------- tabs
document.querySelectorAll('[role=tab]').forEach((t) => t.addEventListener('click', () => {
  document.querySelectorAll('[role=tab]').forEach((x) => x.setAttribute('aria-selected', String(x === t)));
  document.querySelectorAll('[role=tabpanel]').forEach((p) => { p.hidden = p.id !== t.getAttribute('aria-controls'); });
}));

// ================================================================ WALLETS
const WALLETS = {
  crossmark: {
    name: 'Crossmark',
    async connect() {
      if (!crossmark) throw new Error(crossmarkUnavailable ? CROSSMARK_DESKTOP_ONLY : 'The Crossmark connector failed to load. Please report this.');
      if (!crossmark.sync.isInstalled()) throw new Error('Crossmark is not installed in this browser.');
      const r = await crossmark.methods.signInAndWait();
      const address = r && r.response && r.response.data && r.response.data.address;
      if (!core.isAddress(address || '')) throw new Error('Crossmark did not return a valid address.');
      return address;
    },
    async network() {
      if (!crossmark) return null;
      let n;
      try { n = crossmark.sync.getNetwork(); } catch { return null; }
      if (!n) return null;
      if (n.protocol && String(n.protocol).toLowerCase() !== 'xrpl') return `other:${n.protocol}`;
      return String(n.type || '').toLowerCase() || null;
    },
    async signAndSubmit(tx) {
      if (!crossmark) throw new Error(CROSSMARK_DESKTOP_ONLY);
      const r = await crossmark.methods.signAndSubmitAndWait(tx);
      const hash = findHash(r);
      if (!hash) {
        const said = findErrorText(r);
        throw new Error(said ? `Crossmark did not send it: ${said}` : 'Crossmark did not send the transaction (it was rejected or failed inside the wallet). Nothing was sent.');
      }
      return hash;
    },
  },
  gem: {
    name: 'GemWallet',
    async connect() {
      const inst = await Gem.isInstalled();
      if (!inst || !inst.result || !inst.result.isInstalled) throw new Error('GemWallet is not installed in this browser.');
      const r = await Gem.getAddress();
      if (!r || r.type === 'reject' || !r.result || !core.isAddress(r.result.address || '')) throw new Error('GemWallet connection was refused.');
      return r.result.address;
    },
    async network() {
      const r = await Gem.getNetwork();
      if (!r || !r.result) return null;
      if (r.result.chain && r.result.chain !== 'XRPL') return `other:${r.result.chain}`;
      return String(r.result.network || '').toLowerCase() || null;
    },
    async signAndSubmit(tx) {
      const r = await Gem.submitTransaction({ transaction: tx });
      if (!r || r.type === 'reject' || !r.result || !r.result.hash) throw new Error('GemWallet did not submit the transaction (was it rejected?).');
      return r.result.hash;
    },
  },
};

// Testnet Practice Lab "wallet": signs only for the lab's own throwaway owner account, only on Testnet.
WALLETS.practice = lab.practiceWallet(() => state.network, () => state.rpc);

// Pull a short error message out of a wallet's reply, if it gave one.
function findErrorText(obj, depth = 0) {
  if (!obj || depth > 6 || typeof obj !== 'object') return null;
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string' && /error|message|reason/i.test(k) && v.trim()) return core.safeText(v, 200);
    const f = findErrorText(v, depth + 1);
    if (f) return f;
  }
  return null;
}

function findHash(obj, depth = 0) {
  if (!obj || depth > 6 || typeof obj !== 'object') return null;
  for (const [k, v] of Object.entries(obj)) {
    if (k === 'hash' && typeof v === 'string' && /^[0-9A-F]{64}$/i.test(v)) return v;
    const f = findHash(v, depth + 1);
    if (f) return f;
  }
  return null;
}

document.querySelectorAll('[data-wallet]').forEach((b) => b.addEventListener('click', async () => {
  const w = WALLETS[b.dataset.wallet];
  setWalletStatus(`Opening ${w.name}…`);
  try {
    const address = await w.connect();
    state.wallet = { id: b.dataset.wallet, address };
    state.lastActivity = Date.now();
    setWalletStatus(`Connected: ${w.name} · ${addr(address)} <button type="button" class="linkish" id="disconnect">Disconnect</button>`, true);
    $('#disconnect').addEventListener('click', () => { state.wallet = null; setWalletStatus('Disconnected.'); });
    $('#addr').value = address;
    updateFingerprint();
  } catch (e) {
    state.wallet = null;
    setWalletStatus(esc(e.message), false, true);
  }
}));

function setWalletStatus(html, ok = false, err = false) {
  const el = $('#wallet-status');
  el.innerHTML = html;
  el.className = `wallet-status ${ok ? 'ok' : ''} ${err ? 'err' : ''}`;
}

// ---------------------------------------------------------------- auto-disconnect
['pointerdown', 'keydown', 'scroll'].forEach((ev) => window.addEventListener(ev, () => { state.lastActivity = Date.now(); }, { passive: true }));
setInterval(() => {
  if (settings.autoLock && state.wallet && Date.now() - state.lastActivity > settings.autoLockMin * 60000) {
    state.wallet = null;
    setWalletStatus(`Wallet disconnected after ${settings.autoLockMin} minutes without activity (Security setting).`);
  }
}, 15000);

// ---------------------------------------------------------------- address fingerprint
function updateFingerprint() {
  const c = core.cleanAddressInput($('#addr').value);
  const el = $('#fp');
  if (!settings.fingerprint || !c.address) { el.hidden = true; return; }
  const v = c.address;
  el.hidden = false;
  el.innerHTML = `Check against your wallet: <b class="fp-part">${esc(v.slice(0, 5))}</b><span class="fp-mid">${esc(v.slice(5, -5))}</span><b class="fp-part">${esc(v.slice(-5))}</b>`;
}
$('#addr').addEventListener('input', updateFingerprint);

// ================================================================ SCAN
$('#scan-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const c = core.cleanAddressInput($('#addr').value);
  if (!c.address) {
    $('#results').innerHTML = banner('err', c.warning ? 'Hidden characters found' : 'Not a valid address',
      esc(c.warning || 'An XRPL address starts with "r" and is 25–35 characters long. Check for a missing or extra character.'));
    return;
  }
  const note = [];
  if (c.warning) note.push(c.warning);
  if (c.tag !== null && c.tag !== undefined) note.push(`You pasted an X-address. It was converted to ${c.address} (destination tag ${c.tag} — tags do not matter for delegation).`);
  if (c.xTest === true && state.network === 'mainnet') note.push('That X-address is marked as a TEST-network address, but the page is on Mainnet.');
  await runScan({ quiet: false, address: c.address, note: note.join(' ') });
});

async function runScan({ quiet, address, note = '' }) {
  const out = $('#results');
  if (!core.isAddress(address || '')) return;
  const token = ++state.scanToken;
  if (state.activitySignal) state.activitySignal.aborted = true; // stop any older history check (attack-suite finding)
  const net = state.network;
  const rpc = state.rpc;
  const since = core.NETWORKS[net].delegationSince;
  if (!quiet) out.innerHTML = `<div class="loading"><span class="spin" aria-hidden="true"></span>Reading ${esc(core.NETWORKS[net].label)}…</div>`;
  $('#scan-btn').disabled = true;
  try {
    // Phase 1 (fast): who holds power right now, checked against a second server.
    const [r, cc] = await Promise.all([
      core.scanAccount(rpc, address, { history: false, since }),
      settings.crossCheck ? core.crossCheck(net, address) : Promise.resolve(null),
    ]);
    if (token !== state.scanToken) return; // a newer scan or a network switch happened meanwhile
    const fp = r.granted.map((g) => `${g.delegate}:${g.perms.map((p) => p.name).sort().join(',')}`).sort().join('|');
    const changed = state.watchAddress === address && state.watchFp !== null && fp !== state.watchFp;
    state.last = r;
    state.watchFp = fp;
    state.watchAddress = address;
    out.innerHTML = (note ? banner('warn', 'Please note', esc(note)) : '')
      + (changed ? banner('danger', 'Change detected', `The delegates on this wallet changed at ${esc(new Date().toLocaleTimeString())}. Review the list below now.`) : '')
      + renderCrossCheck(cc) + renderScan(r) + '<div id="activity-slot"></div>' + renderWatchStatus();
    bindRevokeButtons();
    if (changed) alertChange(address);
    $('#scan-btn').disabled = false;

    // Phase 2 (can be slow on busy wallets): what delegates have already done. Shown with live progress.
    // A quiet Watch-mode check reuses the last history when nothing changed, instead of re-reading thousands of transactions.
    if (r.exists && quiet && !changed && state.lastActivityFor === `${net}:${address}` && state.lastActivityHtml) {
      $('#activity-slot').innerHTML = state.lastActivityHtml;
    } else if (r.exists) {
      const slot = $('#activity-slot');
      const signal = { aborted: false };
      state.activitySignal = signal;
      slot.innerHTML = '<p class="loading cc"><span class="spin" aria-hidden="true"></span>Checking whether a delegate has already used this wallet…</p>';
      try {
        const act = await core.scanActivity(rpc, address, { since, signal, onProgress: (seen, found) => {
          if (token === state.scanToken && slot.isConnected) slot.innerHTML = `<p class="loading cc"><span class="spin" aria-hidden="true"></span>Checked ${seen.toLocaleString()} transactions so far · ${found.toLocaleString()} sent by a delegate…</p>`;
        } });
        if (token !== state.scanToken || !slot.isConnected || act.aborted) return;
        r.activity = act;
        slot.innerHTML = renderActivity(r);
        state.lastActivityHtml = slot.innerHTML;
        state.lastActivityFor = `${net}:${address}`;
      } catch (e) {
        if (token === state.scanToken && slot.isConnected) slot.innerHTML = banner('warn', 'Could not finish the history check', `${esc(e.message)} The list of delegates above is still correct.`);
      }
    }
  } catch (e) {
    if (token === state.scanToken) out.innerHTML = banner('err', 'Could not complete the scan', esc(e.message));
  } finally {
    if (token === state.scanToken) $('#scan-btn').disabled = false;
  }
}

function renderCrossCheck(cc) {
  if (!cc) return '';
  if (!cc.available) return '<p class="muted cc">Second-operator cross-check: not available on Testnet (this tool uses one Testnet operator).</p>';
  const who = (r) => esc(r.operator);
  if (cc.agree === null) return banner('warn', 'Only one operator answered', `The result could not be double-checked by a second, independent server operator this time (${cc.results.map((r) => `${who(r)}: ${r.error ? 'no answer' : 'answered'}`).join(' · ')}). Scan again in a minute.`);
  if (cc.agree) return `<p class="muted cc ok">✓ Two independent operators agree: ${cc.results.map(who).join(' and ')}.</p>`;
  return banner('danger', 'Two independent operators disagree', `${cc.results.map(who).join(' and ')} returned different delegate lists for this wallet. One may be out of date or tampered with. Wait a minute and scan again; if it persists, check the account on an explorer you trust. ${cc.results.map((r) => `${who(r)}: ${r.error ? 'error' : esc(r.count) + ' entries @ ledger ' + esc(r.ledger)}`).join(' · ')}`);
}

const LEVEL_TEXT = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
const lvl = (l) => (LEVEL_TEXT[l] ? l : 'high'); // only known level names ever reach a class attribute

function banner(kind, title, body) {
  return `<div class="banner ${kind}" role="status"><strong>${title}</strong><p>${body}</p></div>`;
}

function renderScan(r) {
  const net = core.NETWORKS[state.network];
  if (!r.exists) {
    return banner('neutral', 'This account does not exist on this network',
      `No account ${addr(r.address)} on ${esc(net.label)}. If you expected one, check the network switch above.`);
  }
  let html = '';
  const n = r.granted.length;
  if (n === 0) {
    html += banner('ok', 'No one has delegated power over this account',
      `Checked at validated ledger ${esc(r.ledger)}. No Delegate entries name ${addrShort(r.address)} as the owner.`);
  } else {
    const worst = lvl(r.granted[0].level);
    html += banner(worst === 'critical' || worst === 'high' ? 'danger' : 'warn',
      `${n} account${n > 1 ? 's' : ''} can act as this wallet`,
      `Worst permission found: <b>${LEVEL_TEXT[worst]}</b>. If you did not set ${n > 1 ? 'these' : 'this'} up yourself, revoke ${n > 1 ? 'them' : 'it'} now. Checked at validated ledger ${esc(r.ledger)}.`);
  }
  if (r.truncated) html += banner('warn', 'Very large account', 'Only the first pages of ledger objects were read. Results may be incomplete.');

  if (n) {
    html += `<section class="block"><h3>Who can act as this wallet</h3>${r.granted.map((g) => `
      <article class="card lvl-${lvl(g.level)}">
        <header>
          <span class="pill lvl-${lvl(g.level)}">${LEVEL_TEXT[lvl(g.level)]}</span>
          <div class="who"><span class="label">Delegate</span>
            <a href="${net.explorerAccount}${esc(g.delegate)}" target="_blank" rel="noopener noreferrer">${addr(g.delegate)}</a>
            ${g.delegateInfo && g.delegateInfo.domain ? `<span class="muted">claims domain: ${esc(g.delegateInfo.domain)} (unverified — anyone can type any domain)</span>` : ''}
            ${g.delegateInfo && g.delegateInfo.exists === false ? '<span class="muted">this address is not an active account</span>' : ''}
          </div>
        </header>
        ${g.perms.length ? '' : '<p class="err">The server sent this delegation without a readable permission list. Treat it as dangerous.</p>'}
        <ul class="perms">${g.perms.map((p) => `<li><span class="pill small lvl-${lvl(p.level)}">${esc(p.name)}</span><span>${esc(p.plain)}</span>${p.name === 'PaymentBurn' ? '<em class="note">xrpl.org advises not delegating PaymentBurn until the fixCleanup3_4_0 amendment is enabled.</em>' : ''}</li>`).join('')}</ul>
        <footer><button class="btn revoke card-revoke" data-delegate="${esc(g.delegate)}">Revoke all of this delegate's power</button>
        <span class="muted">Costs a network fee of about 0.00001 XRP and frees 0.2 XRP of your reserve.</span></footer>
      </article>`).join('')}</section>`;
  }

  if (r.received.length) {
    html += `<section class="block"><h3>Accounts this wallet can act for</h3><p class="sub">Other owners gave this address power. Only they can revoke it.</p>
      <ul class="received">${r.received.map((g) => `<li>${addr(g.owner)} → ${g.perms.map((p) => `<span class="pill small lvl-${lvl(p.level)}">${esc(p.name)}</span>`).join(' ')}</li>`).join('')}</ul></section>`;
  }
  return html;
}

function renderActivity(r) {
  // Always say how far back the "already used" check went (backtest finding: silence must never look like "never used").
  const net = core.NETWORKS[state.network];
  const act = r.activity;
  const coverage = act.complete
    ? (act.since ? `Checked every one of this wallet's ${act.scanned.toLocaleString()} transactions since delegation went live (8 Oct 2026).`
                 : `Checked all ${act.scanned.toLocaleString()} transactions in this network's history.`)
    : `Checked the most recent ${act.scanned.toLocaleString()} transactions only. This wallet is very busy, so older delegated transactions may not be listed — check it on a block explorer too.`;
  if (act.found.length) {
    const SHOW = 50;
    return `<section class="block"><h3>Already used: ${act.complete ? '' : 'at least '}${act.found.length.toLocaleString()} transaction${act.found.length > 1 ? 's' : ''} a delegate sent as this account</h3>
      <p class="sub">${esc(coverage)}${act.found.length > SHOW ? ` Showing the newest ${SHOW}.` : ''}</p><ul class="activity">${
      act.found.slice(0, SHOW).map((a) => `<li class="lvl-${a.type === 'Payment' ? 'critical' : 'high'}">
        <span class="tx-type">${esc(a.type || 'Transaction')}</span>
        <span>by ${addrShort(a.delegate)}${a.destination ? ` → ${addrShort(a.destination)}` : ''}${a.amount !== undefined && a.amount !== null ? ` · ${esc(core.amountText(a.amount))}` : ''}</span>
        <span class="muted">${esc(a.result || '')}${a.date ? ' · ' + esc(a.date.slice(0, 10)) : ''}</span>
        <a href="${net.explorer}${esc(a.hash)}" target="_blank" rel="noopener noreferrer">view</a></li>`).join('')}</ul></section>`;
  }
  return r.granted.length || act.scanned ? `<p class="muted cc">No transactions sent by a delegate were found. ${esc(coverage)}</p>` : '';
}

function bindRevokeButtons() {
  document.querySelectorAll('button.card-revoke').forEach((b) => b.addEventListener('click', () => startRevoke(b.dataset.delegate)));
}

// ---------------------------------------------------------------- watch mode
function renderWatchStatus() {
  if (!settings.watch || !state.watchAddress) return '';
  return `<p class="muted watch">● Watch mode on: re-checking ${addrShort(state.watchAddress)} every ${settings.watchMin} min while this tab is open. Last check ${esc(new Date().toLocaleTimeString())}.</p>`;
}

function scheduleWatch() {
  clearInterval(state.watchTimer);
  state.watchTimer = null;
  if (!settings.watch) return;
  // Watches the wallet that was SCANNED, never whatever happens to be typed in the box (attack-suite finding).
  state.watchTimer = setInterval(() => {
    if (state.watchAddress && !state.busy) runScan({ quiet: true, address: state.watchAddress });
  }, settings.watchMin * 60000);
}

function alertChange(address) {
  const original = document.title.replace(/^⚠ DELEGATES CHANGED$/, 'XRPL Delegation Checker');
  let n = 0;
  clearInterval(alertChange.t);
  alertChange.t = setInterval(() => {
    document.title = n++ % 2 ? original : '⚠ DELEGATES CHANGED';
    if (n > 20 || document.hasFocus()) { clearInterval(alertChange.t); document.title = original; }
  }, 1000);
  if (settings.notify && 'Notification' in window && Notification.permission === 'granted') {
    try { new Notification('XRPL Delegation Checker', { body: `Delegates changed on ${short(address)}. Open the tab and review now.` }); } catch { /* ignore */ }
  }
}

// ================================================================ REVOKE
// For people who sign elsewhere (Xaman, hardware wallets, multi-sign): the bare revoke, which their own
// wallet fills in and shows them before signing.
// Turns a wallet's error into plain English. The important case (real-wallet test finding, 24 Oct 2026):
// a wallet whose built-in XRPL library predates the DelegateSet transaction refuses to build it
// ("Invalid field TransactionType: DelegateSet"). Nothing is sent in that case, so we say so and offer
// the copy-and-sign route instead of a raw error.
function walletErrorHtml(e, walletId, owner, delegate) {
  const msg = String((e && e.message) || e || 'Unknown error');
  const name = (WALLETS[walletId] && WALLETS[walletId].name) || 'Your wallet';
  if (/DelegateSet|Invalid field TransactionType|PermissionValue|Permissions/i.test(msg)) {
    return `<div class="err" id="rv-err"><p><b>${esc(name)} cannot sign this type of transaction yet.</b> Its built-in XRP Ledger library is older than the DelegateSet transaction (added to the ledger on 8 October 2026). <b>Nothing was sent</b> and nothing changed.</p>
      <p>Wallet said: <code>${esc(msg.slice(0, 160))}</code></p>
      <p>Copy the transaction below and sign it in a wallet or XRPL library that supports DelegateSet. On Testnet, the Practice Lab lets you practise the whole revoke without a wallet.</p></div>${copyBlock(owner, delegate)}`;
  }
  return `<p class="err" id="rv-err">${esc(msg.slice(0, 300))}</p>`;
}

function copyBlock(owner, delegate) {
  const bare = JSON.stringify(core.buildRevoke(owner, delegate), null, 2);
  return `<details class="copy"><summary>Sign the revoke somewhere else (another wallet, multi-sign or an XRPL library)</summary>
    <p class="muted">Copy this and sign it with a wallet or XRPL library you trust that supports DelegateSet. It removes every permission held by ${addrShort(delegate)}. The signer adds the fee and sequence number. (Tested 24 October 2026: Crossmark 0.2.19 and GemWallet 3.8.2 cannot sign DelegateSet yet.)</p>
    <pre class="json" id="copy-json">${esc(bare)}</pre>
    <button type="button" class="btn ghost" id="copy-btn">Copy transaction</button> <span class="muted" id="copy-ok"></span></details>`;
}
function bindCopy() {
  const b = $('#copy-btn');
  if (!b) return;
  b.addEventListener('click', async () => {
    const text = $('#copy-json').textContent;
    try { await navigator.clipboard.writeText(text); $('#copy-ok').textContent = 'Copied. Paste it into your wallet and check it before signing.'; }
    catch { const r = document.createRange(); r.selectNodeContents($('#copy-json')); const s = getSelection(); s.removeAllRanges(); s.addRange(r); $('#copy-ok').textContent = 'Selected — press Ctrl+C / Cmd+C.'; }
  });
}

async function confirmRevoke({ hash, net, rpc, owner, delegate, body }) {
  const netInfo = core.NETWORKS[net];
  const link = `<a href="${netInfo.explorer}${esc(hash)}" target="_blank" rel="noopener noreferrer">See the transaction</a>`;
  body.innerHTML = `<p class="loading"><span class="spin" aria-hidden="true"></span>Submitted <code>${esc(short(hash))}</code>. Waiting for the ledger to confirm…</p>`;
  const v = await core.waitForValidation(rpc, hash);
  if (!v.validated) {
    body.innerHTML = banner('warn', 'Sent — not confirmed yet. Do NOT sign again.',
      `Your wallet submitted transaction <code>${esc(short(hash))}</code>, but ${v.unreachable ? 'the ledger servers are busy right now' : 'the ledger has not confirmed it yet'}, so it has not been verified. ${link}.`)
      + '<p><button type="button" class="btn ghost" id="recheck">Check again</button></p>';
    $('#recheck').addEventListener('click', () => confirmRevoke({ hash, net, rpc, owner, delegate, body }));
    return;
  }
  let problems = [];
  let twoOps = false;
  try {
    if (settings.ledgerVerify) {
      if (settings.crossCheck && (netInfo.operators || []).length > 1) {
        // Hardening: one lying server cannot fake a successful revoke — two independent operators must confirm it.
        const both = await core.verifyOnBothServers(net, hash, owner, delegate, settings.maxFee);
        problems = both.problems;
        twoOps = both.confirmed;
        if (!both.confirmed && !problems.length) problems = ['A second, independent server operator could not confirm the revoke yet. Scan again in a minute to be sure.'];
      } else {
        problems = await core.verifyOnLedger(rpc, hash, owner, delegate, settings.maxFee);
      }
    }
  } catch (e) {
    body.innerHTML = banner('warn', 'Confirmed, but not verified yet. Do NOT sign again.',
      `The ledger confirmed transaction <code>${esc(short(hash))}</code> (${esc(v.result)}), but the check that it is exactly the revoke you approved could not run (${esc(e.message)}). ${link}.`)
      + '<p><button type="button" class="btn ghost" id="recheck">Check again</button></p>';
    $('#recheck').addEventListener('click', () => confirmRevoke({ hash, net, rpc, owner, delegate, body }));
    return;
  }
  if (problems.length && v.result === 'tesSUCCESS' && problems.every((p) => /could not confirm|still listed/.test(p))) {
    body.innerHTML = banner('warn', 'Revoke sent — waiting for full confirmation', `${problems.map(esc).join('; ')} ${link}.`);
  } else if (problems.length) {
    body.innerHTML = banner('danger', 'WARNING: the ledger shows a different transaction',
      `What was signed does not match what you approved: ${problems.map(esc).join('; ')}. Stop using this wallet extension, move your funds to a fresh wallet, and scan again. ${link}.`);
  } else if (v.result === 'tesSUCCESS') {
    body.innerHTML = banner('ok', 'Revoked', `${addr(delegate)} no longer has any power over this account.${settings.ledgerVerify ? (twoOps ? ' Verified on the ledger by two independent server operators.' : ' Verified on the ledger.') : ''} ${link}.`);
  } else {
    body.innerHTML = banner('err', 'Not confirmed', `Result: ${esc(v.result || 'unknown')}. ${link} and scan again.`);
  }
  if (state.network === net) runScan({ quiet: false, address: owner });
}

async function startRevoke(delegate) {
  if (state.busy) return;
  const owner = state.last && state.last.address;
  // Freeze the network and server for the whole flow (attack-suite finding: switching network mid-revoke
  // made the page wait for the transaction on the wrong network).
  const net = state.network;
  const rpc = state.rpc;
  const dlg = $('#revoke-dialog');
  const body = $('#revoke-body');
  const go = $('#revoke-go');
  const stop = (html) => { body.innerHTML = html; go.hidden = true; go.onclick = null; if (!dlg.open) dlg.showModal(); bindCopy(); };
  go.onclick = null; // never leave a previous transaction attached to the button

  if (!core.isAddress(delegate || '') || !core.isAddress(owner || '')) return stop('<p class="err">Address check failed. Scan again.</p>');
  if (!state.wallet) return stop(`<p>Connect the wallet that owns ${addr(owner)} first (Crossmark or GemWallet, top of the page). Only the owner can revoke.</p>${copyBlock(owner, delegate)}`);
  if (state.wallet.address !== owner) {
    return stop(`<p>Your connected wallet is ${addr(state.wallet.address)}, but the scanned account is ${addr(owner)}. Connect the owner's wallet, or scan your connected address.</p>${copyBlock(owner, delegate)}`);
  }
  const walletId = state.wallet.id;

  if (settings.networkLock) {
    let wn = null;
    try { wn = await WALLETS[walletId].network(); } catch { wn = null; }
    if (wn !== net) {
      return stop(`<p class="err"><b>Network lock:</b> your wallet reports <b>${esc(wn || 'unknown')}</b> but this page is on <b>${esc(net)}</b>. Switch one of them so they match, then try again. (You can turn this check off in Security, but it protects you from signing on the wrong network.)</p>`);
    }
  }

  let tx;
  try {
    tx = await core.autofill(rpc, core.buildRevoke(owner, delegate), settings.maxFee);
  } catch (e) {
    return stop(`<p class="err">Could not prepare the transaction: ${esc(e.message)}</p>`);
  }
  if (settings.strictVerify) {
    const problems = core.verifyRevokeTx(tx, owner, delegate, settings.maxFee);
    if (problems.length) return stop(`<p class="err"><b>Strict check blocked this transaction:</b></p><ul>${problems.map((p) => `<li>${esc(p)}</li>`).join('')}</ul>`);
  }
  Object.freeze(tx);

  const practice = walletId === 'practice';
  go.textContent = practice ? 'Sign with the practice key' : 'Sign with my wallet';
  body.innerHTML = `<p>${practice ? 'The Practice Lab will sign this with its throwaway Testnet key.' : 'Your wallet will ask you to sign this transaction.'} It removes <b>every</b> permission held by ${addr(delegate)}. Nothing else changes.</p>
    <pre class="json">${esc(JSON.stringify(tx, null, 2))}</pre>
    <ul class="checks">
      ${settings.strictVerify ? '<li>✓ Strict check passed: DelegateSet, your account, this delegate, empty permissions, fee within your limit.</li>' : '<li class="warn-t">Strict check is OFF.</li>'}
      ${settings.networkLock ? `<li>✓ Wallet is on ${esc(net)}.</li>` : '<li class="warn-t">Network lock is OFF.</li>'}
    </ul>
    <p class="muted">${practice ? 'In a real wallet you would now check' : 'In your wallet, confirm'} the type is <b>DelegateSet</b>, Authorize ends in <b>${esc(delegate.slice(-5))}</b>, and nothing else is being changed.</p>`;
  go.hidden = false;
  go.disabled = false;
  let fired = false;
  go.onclick = async () => {
    if (fired) return; // one click = one transaction, however fast the clicks come (attack-suite check)
    fired = true;
    go.disabled = true;
    state.busy = true;
    body.insertAdjacentHTML('beforeend', '<p class="loading" id="rv-wait"><span class="spin" aria-hidden="true"></span>Waiting for your wallet…</p>');
    let hash;
    try {
      hash = await WALLETS[walletId].signAndSubmit(tx);
      if (!core.isHash(String(hash))) throw new Error('The wallet returned something that is not a transaction hash.');
    } catch (e) {
      // Nothing was submitted (or the wallet said so): it is safe to offer "Sign" again.
      const w = $('#rv-wait'); if (w) w.remove();
      const old = $('#rv-err'); if (old) old.remove();
      body.querySelectorAll('details.copy').forEach((d) => d.remove());
      body.insertAdjacentHTML('beforeend', walletErrorHtml(e, walletId, owner, delegate));
      bindCopy();
      fired = false;
      go.disabled = false;
      state.busy = false;
      return;
    }
    // From here on a transaction EXISTS. "Sign" is never offered again for it (live-test finding: a server
    // outage during confirmation used to re-enable the button and skip the ledger check).
    go.hidden = true;
    await confirmRevoke({ hash, net, rpc, owner, delegate, body });
    state.busy = false;
  };
  dlg.showModal();
}
$('#revoke-close').addEventListener('click', () => { if (!state.busy) $('#revoke-go').onclick = null; $('#revoke-dialog').close(); });

// ================================================================ PRE-SIGN CHECK
$('#check-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  const out = $('#check-out');
  try {
    const tx = core.parseSignRequest($('#sign-input').value);
    const ex = core.explainTx(tx);
    const lvl = core.overallLevel(ex);
    const verdict = {
      critical: ['danger', 'Do not sign unless you are 100% sure', 'This can hand over your wallet or its funds.'],
      high: ['danger', 'Read every line before signing', 'This moves funds or grants power over your account.'],
      medium: ['warn', 'Check the details', 'Make sure this is what you meant to do.'],
      low: ['ok', 'Low risk', 'Nothing here moves funds or grants power.'],
    }[lvl];
    out.innerHTML = banner(verdict[0], verdict[1], verdict[2]) + renderExplain(ex);
  } catch (e) {
    out.innerHTML = banner('err', 'Could not read that', esc(e.message));
  }
});

function renderExplain(ex) {
  return `<article class="explain"><h4>${esc(ex.type)} <span class="muted">from <code class="sensitive" tabindex="0">${esc(ex.account || '?')}</code></span></h4>
    <ul>${ex.findings.map((f) => `<li><span class="pill small lvl-${f.level}">${LEVEL_TEXT[f.level]}</span> ${esc(f.text)}</li>`).join('')}</ul>
    ${ex.inner.length ? `<div class="inner">${ex.inner.map((i, k) => `<div class="inner-n">Inside #${k + 1}</div>${renderExplain(i)}`).join('')}</div>` : ''}</article>`;
}

// ================================================================ TESTNET PRACTICE LAB
function labLog(html, cls = '') { $('#lab-log').insertAdjacentHTML('beforeend', `<p class="${cls}">${html}</p>`); }
function labButtons() {
  const st = lab.labState();
  const has = !!st.owner;
  $('#lab-create').disabled = state.labBusy;
  ['#lab-grant', '#lab-spend', '#lab-prove'].forEach((id) => { $(id).disabled = state.labBusy || !has; });
}
function leaveLab() {
  lab.wipe();
  if (state.wallet && state.wallet.id === 'practice') { state.wallet = null; setWalletStatus('Practice Lab closed. Its throwaway keys were forgotten.'); }
  const log = $('#lab-log'); if (log) log.innerHTML = '';
  state.labBusy = false;
  if ($('#lab-create')) labButtons();
}
async function labRun(fn) {
  if (state.labBusy || state.busy) return;
  if (state.network !== 'testnet') { labLog('Switch the page to Testnet first.', 'err'); return; }
  state.labBusy = true; labButtons();
  try { await fn(); } catch (e) { labLog(esc(e.message), 'err'); }
  state.labBusy = false; labButtons();
}
function labResult(r, okText) {
  const link = r.hash ? ` <a href="${core.NETWORKS.testnet.explorer}${esc(r.hash)}" target="_blank" rel="noopener noreferrer">See it on the Testnet explorer</a>` : '';
  return r.validated && r.result === 'tesSUCCESS' ? `✓ ${okText}${link}` : `Result: <b>${esc(r.result || r.prelim || 'not confirmed')}</b>.${link}`;
}
$('#lab-create').addEventListener('click', () => labRun(async () => {
  $('#lab-log').innerHTML = '';
  const st = await lab.createAccounts(state.network, state.rpc, fetch, (m) => labLog(esc(m), 'muted'));
  labLog(`✓ Practice owner: ${addr(st.owner)}<br>✓ Practice helper: ${addr(st.helper)}<br>Both were funded by the official Testnet faucet. Their keys exist only in this tab.`, 'ok-t');
  state.wallet = { id: 'practice', address: st.owner };
  state.lastActivity = Date.now();
  setWalletStatus(`Connected: Practice Lab (Testnet) · ${addr(st.owner)}`, true);
  $('#addr').value = st.owner; updateFingerprint();
  await runScan({ quiet: false, address: st.owner, note: '' });
}));
$('#lab-grant').addEventListener('click', () => labRun(async () => {
  labLog('Owner is signing a DelegateSet that gives the helper <b>Payment</b> and <b>TrustSet</b> power…', 'muted');
  const r = await lab.grant(state.network, state.rpc, settings.maxFee);
  labLog(labResult(r, 'The helper now holds Payment and TrustSet power over the owner. The scan below should show it as Critical.'), r.result === 'tesSUCCESS' ? 'ok-t' : 'err');
  await runScan({ quiet: false, address: lab.labState().owner, note: '' });
}));
$('#lab-spend').addEventListener('click', () => labRun(async () => {
  labLog('The helper is sending 1 XRP out of the owner\'s account, signed only by the helper…', 'muted');
  const r = await lab.helperSpends(state.network, state.rpc, settings.maxFee);
  labLog(labResult(r, 'The helper moved 1 XRP out of the owner\'s account without the owner signing anything. This is exactly what a thief would do.'), r.result === 'tesSUCCESS' ? 'warn-t' : 'err');
  await runScan({ quiet: false, address: lab.labState().owner, note: '' });
}));
$('#lab-prove').addEventListener('click', () => labRun(async () => {
  labLog('The helper is trying to send 1 XRP out of the owner\'s account again…', 'muted');
  const r = await lab.helperSpends(state.network, state.rpc, settings.maxFee);
  const code = r.result || r.prelim;
  if (code === 'terNO_DELEGATE_PERMISSION') labLog(`✓ Refused by the ledger: <b>terNO_DELEGATE_PERMISSION</b>. The revoke worked. The helper has no power left.`, 'ok-t');
  else if (r.validated && code === 'tesSUCCESS') labLog('The payment went through, so the helper still has power. Revoke it with the red button on the card below, then try this step again.', 'err');
  else labLog(`Result: <b>${esc(code || 'not confirmed')}</b>.`, 'err');
}));
labButtons();

// ================================================================ START
renderSettings();
applySettings();
if (loadedOff.length) {
  setWalletStatus(`<b>Warning:</b> settings saved in this browser have these protections switched OFF: ${loadedOff.map((k) => esc(SAFETY_SWITCHES[k])).join(', ')}. If you did not do that yourself, open Security and press <b>Reset to safest defaults</b>.`, false, true);
}

// Test builds only (removed from the release file by the build script).
if (__TEST_BUILD__) window.__xdc = { core, state, settings, WALLETS };
