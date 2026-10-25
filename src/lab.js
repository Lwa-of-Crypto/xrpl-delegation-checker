// XRPL Delegation Checker — Testnet Practice Lab.
// Created by Stanley Gebara · CryptoLwa (cryptolwa.io) · Open source (MIT).
//
// Why this exists: on 24 October 2026 neither Crossmark (0.2.19) nor GemWallet (3.8.2) could sign a
// DelegateSet transaction (both: "Invalid field TransactionType: DelegateSet"). So the only way for the
// community to practise the whole grant → scan → revoke → verify cycle is with throwaway Testnet accounts.
//
// Hard rules, enforced in code, not just in the text:
//   - Testnet only. Every network call goes to the Testnet server or the official Testnet faucet.
//   - The practice keys come from the faucet, live only in this tab's memory, are never stored, never
//     shown, and are wiped when the page leaves Testnet or "Forget everything" is pressed.
//   - The lab can only sign for the two accounts it created. It can never sign for any other address.
import { deriveKeypair, deriveAddress, sign as kpSign } from 'ripple-keypairs';
import { encode, encodeForSigning } from 'ripple-binary-codec';
import { sha512 } from '@xrplf/isomorphic/sha512';
import * as core from './core.js';

export const FAUCET_URL = 'https://faucet.altnet.rippletest.net/accounts';

const lab = { owner: null, helper: null }; // { address, publicKey, privateKey }

export function labState() {
  return { owner: lab.owner && lab.owner.address, helper: lab.helper && lab.helper.address };
}
export function wipe() { lab.owner = null; lab.helper = null; }
export function isLabAccount(address) {
  return !!address && ((lab.owner && lab.owner.address === address) || (lab.helper && lab.helper.address === address));
}

function keysFromSeed(seed) {
  if (typeof seed !== 'string' || seed.length > 64) throw new Error('The faucet returned an unusable practice key.');
  const kp = deriveKeypair(seed);
  return { address: deriveAddress(kp.publicKey), publicKey: kp.publicKey, privateKey: kp.privateKey };
}

const hexOf = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();

// Same steps as xrpl.js Wallet.sign: add SigningPubKey, sign the signing encoding, encode, hash.
export function signWith(keys, tx) {
  const t = { ...tx, SigningPubKey: keys.publicKey };
  t.TxnSignature = kpSign(encodeForSigning(t), keys.privateKey);
  const blob = encode(t);
  const prefixed = core.hexToBytes('54584E00' + blob); // "TXN\0" transaction-id prefix
  return { tx_blob: blob, hash: hexOf(sha512(prefixed).slice(0, 32)) };
}

async function fund(fetchImpl) {
  let last = null;
  for (let i = 0; i < 4; i++) {
    try {
      const r = await fetchImpl(FAUCET_URL, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
      if (r.ok) {
        const j = await r.json();
        const keys = keysFromSeed(j && j.seed);
        const said = j && j.account && (j.account.classicAddress || j.account.address);
        if (said && said !== keys.address) throw new Error('The faucet key and address do not match.');
        return keys;
      }
      last = new Error(`The Testnet faucet answered ${r.status}.`);
    } catch (e) { last = e; }
    await new Promise((s) => setTimeout(s, 2500));
  }
  throw new Error(`Could not get practice accounts from the Testnet faucet. ${last ? last.message : ''} Try again in a minute.`);
}

async function waitForAccount(rpc, address, maxMs = 60000) {
  const stop = Date.now() + maxMs;
  while (Date.now() < stop) {
    try { const r = await rpc('account_info', { account: address, ledger_index: 'validated' }); if (r && r.account_data) return true; } catch { /* not yet */ }
    await new Promise((s) => setTimeout(s, 2500));
  }
  throw new Error('The practice account did not appear on Testnet within a minute. Try again.');
}

function assertTestnet(network) {
  if (network !== 'testnet') throw new Error('The Practice Lab only works on Testnet.');
}

async function submitSigned(rpc, keys, tx, maxFee) {
  const filled = await core.autofill(rpc, tx, maxFee);
  const { tx_blob, hash } = signWith(keys, filled);
  const r = await rpc('submit', { tx_blob });
  const prelim = core.safeText(r && r.engine_result, 40);
  return { hash, prelim, tx: filled };
}

// Step 1: two fresh, funded practice accounts.
export async function createAccounts(network, rpc, fetchImpl = fetch, onStep = () => {}) {
  assertTestnet(network);
  wipe();
  onStep('Asking the Testnet faucet for two practice accounts…');
  const [owner, helper] = await Promise.all([fund(fetchImpl), fund(fetchImpl)]);
  onStep('Waiting for Testnet to create them…');
  await Promise.all([waitForAccount(rpc, owner.address), waitForAccount(rpc, helper.address)]);
  lab.owner = owner; lab.helper = helper;
  return labState();
}

// Step 2: the owner gives the helper Payment + TrustSet power (what a scam site would ask for).
export async function grant(network, rpc, maxFee) {
  assertTestnet(network);
  if (!lab.owner || !lab.helper) throw new Error('Create the practice accounts first.');
  const tx = { TransactionType: 'DelegateSet', Account: lab.owner.address, Authorize: lab.helper.address,
    Permissions: [{ Permission: { PermissionValue: 'Payment' } }, { Permission: { PermissionValue: 'TrustSet' } }] };
  const s = await submitSigned(rpc, lab.owner, tx, maxFee);
  const v = await core.waitForValidation(rpc, s.hash);
  return { ...s, ...v };
}

// Step 3 (and the final proof): the helper tries to send 1 XRP out of the owner's account.
export async function helperSpends(network, rpc, maxFee) {
  assertTestnet(network);
  if (!lab.owner || !lab.helper) throw new Error('Create the practice accounts first.');
  const tx = { TransactionType: 'Payment', Account: lab.owner.address, Delegate: lab.helper.address,
    Destination: lab.helper.address, Amount: '1000000' };
  // Sequence and fee belong to the owner's account; the helper signs.
  const filled = await core.autofill(rpc, tx, maxFee);
  const { tx_blob, hash } = signWith(lab.helper, filled);
  const r = await rpc('submit', { tx_blob });
  const prelim = core.safeText(r && r.engine_result, 40);
  if (/^te[cfmlr]|^tem|^tef|^tel|^ter/.test(prelim) && prelim !== 'terQUEUED') return { hash, prelim, validated: false, result: prelim };
  const v = await core.waitForValidation(rpc, hash);
  return { hash, prelim, ...v };
}

// A "wallet" for the revoke dialog that signs only for the practice owner, only on Testnet.
export function practiceWallet(getNetwork, getRpc) {
  return {
    name: 'Practice Lab (Testnet)',
    async connect() { if (!lab.owner) throw new Error('Create the practice accounts first.'); return lab.owner.address; },
    async network() { return getNetwork() === 'testnet' ? 'testnet' : null; },
    async signAndSubmit(tx) {
      assertTestnet(getNetwork());
      if (!lab.owner || tx.Account !== lab.owner.address) throw new Error('The Practice Lab can only sign for its own practice account.');
      const { tx_blob, hash } = signWith(lab.owner, tx);
      const r = await getRpc()('submit', { tx_blob });
      const prelim = core.safeText(r && r.engine_result, 40);
      if (/^(tem|tef|tel)/.test(prelim)) throw new Error(`Testnet refused the transaction (${prelim}). Nothing changed.`);
      return hash;
    },
  };
}
