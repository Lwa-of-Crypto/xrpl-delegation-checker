# XRPL Delegation Checker

**See which accounts can act as your XRP Ledger wallet, and take that power back with one signature.**

A free, open-source community tool by Stanley Gebara · [CryptoLwa](https://cryptolwa.io).

> This is my gift back to the community that got me interested in crypto.

---

## Why it exists

On 8 October 2026, at 21:29:50 UTC, the XRP Ledger enabled the `PermissionDelegationV1_1` amendment in ledger 107,524,865 (read from the ledger itself). Since then, an account can sign one `DelegateSet` transaction that lets *another* account send transactions as it. Businesses use this to split duties without sharing keys.

The same feature is a new way to get robbed. If a phishing site tricks someone into signing a `DelegateSet` that grants `Payment`, the attacker keeps that power until the owner revokes it. In our own Testnet test, a delegate holding `Payment` moved 5 XRP out of the owner's account. After the owner revoked it, the attacker's next attempt was refused by the ledger with `terNO_DELEGATE_PERMISSION`.

## What it does

| Feature | What it does |
|---|---|
| **Check a wallet** | Lists every account holding delegated power over an address, with each permission in plain English and ranked Critical / High / Medium / Low. Also shows what delegates have *already* done as that account, always with how far back it looked, and the accounts this address can act for. Accepts X-addresses and catches pasted addresses with hidden characters. |
| **Revoke** | Builds a `DelegateSet` with an empty `Permissions` list, which deletes the delegation, checks it field by field, hands it to the connected wallet, then verifies on the ledger that the delegate is gone. It can also be copied to sign elsewhere. See *Wallet support* below. |
| **Practice Lab** (Testnet only) | Two throwaway Testnet accounts from the official faucet: grant a delegation, see it, let the delegate spend, revoke it through the normal revoke window, and prove the ledger now refuses the delegate (`terNO_DELEGATE_PERMISSION`). Keys live only in the tab and are wiped on leaving Testnet. |
| **Check before you sign** | Decodes a transaction (JSON or hex blob), including every transaction inside a `Batch`, and explains it before the user signs it anywhere. It recognises key-handover, master-key disabling, NFT give-aways, fee drains, pre-signed transactions with no expiry, links in memos and partial payments. Runs fully offline. |

## Wallet support (measured 24 October 2026)

We drove the real, current extensions from the Chrome Web Store through connect and revoke on Testnet (`test/wallet-e2e/`).

| Wallet | Connect | Reports network | Signs `DelegateSet` |
|---|---|---|---|
| Crossmark 0.2.19 | Works | Works | **No** — "Invalid field TransactionType: DelegateSet" |
| GemWallet 3.8.2 | Works | Works | **No** — same message |

Both extensions bundle XRPL libraries older than `DelegateSet` (GemWallet: xrpl 3.1.0 / ripple-binary-codec 2.1.0; neither extension's code contains the type). Nothing is sent. The tool now says so in plain English and offers the copy-and-sign route. Checking works for everyone; revoking needs a signer that supports `DelegateSet` (for example current xrpl.js — 5.3.0 is used and tested here).

## Mainnet backtest

See `backtest/`. We sweep the whole XRP Ledger state with `ledger_data` to find every delegation that exists. Then we run the tool on every one of those wallets and grade it against three independent answers:

1. the full-state sweep
2. a replay of each wallet's own `DelegateSet` history
3. every real `DelegateSet` blob, decoded

Final run, on the exact release code: on 19 October 2026 two full sweeps, three hours apart (ledgers 107,769,897 and 107,773,208), both found **31 delegations over 10 owner wallets**, and 28 of the 31 include `Payment`.

| Check | Result |
|---|---|
| Owner wallets: tool = full-state sweep = replay of the wallet's own history | 10 / 10 |
| Delegate wallets: reverse view matches | 31 / 31 |
| Real signed `DelegateSet` blobs decoded with correct delegate, permissions and danger level | 33 / 33 |
| "Already used" count equals the true number of delegate-signed transactions | 9 / 9 exact; the 10th wallet had sent about 33,400 and the tool reported "at least 3,981" and said it stopped early |

Slowest real-wallet scan: 15 s. Results: `backtest-result--2026-10-19.json`.

## Real-wallet testing (24 October 2026)

- **Bug found and fixed:** in the 1.0.3 release file the Crossmark button failed on every click ("Cannot read properties of undefined (reading 'isInstalled')"). The release tree's `"type": "module"` made esbuild import the Crossmark UMD bundle's wrapper instead of the SDK; the tests had used a build without that setting. 1.0.4 resolves the SDK object robustly, all tests now run from the release tree, and `release-smoke.mjs` checks both wallet buttons in the exact release file.
- **Raw wallet errors** (and a spinner left running) are replaced by a plain-English message that confirms nothing was sent.
- The copy-and-sign note no longer claims Xaman or hardware wallets can sign it; that was never verified.
- An independent fact-check of the manual against the code found that a stored *true/false* setting could switch a protection off if something wrote to the browser's storage. A page cannot prevent that, so 1.0.4 now warns in red on load whenever a saved setting has a protection switched off (tested in `release-smoke.mjs`).

## How we tried to break it

`test/attack-core.mjs` (35 checks) and `test/attack-browser.mjs` (26 checks, real Chromium, every ledger server replaced by a hostile one). Everything they found was fixed:

- **Hostile server data:**
  - malformed entries crashed a scan
  - fake addresses and fake transaction hashes became links
  - right-to-left and invisible characters let a delegate's "domain" look like `ripple.com`
  - a server feeding one transaction per page kept a scan going for 4,000 requests, and a server ignoring the page limit could push 50,000 rows into the page
  - garbage sequence numbers were passed to the wallet
- **Availability:**
  - every server down left the page spinning for more than a minute; now a clear error in 40 s at worst
  - rate-limit replies dressed as normal errors were treated as answers; the client now reads each server's published quota (`RateLimit-*` headers), slows down before running out, and fails over
  - two dead second-opinion operators held a scan for more than 60 s; now each is skipped after 10 s
- **Honesty of the cross-check:** `xrplcluster.com` and `xrpl.ws` are the **same cluster** (xrpl.org lists `xrpl.ws` as an alias, and both report the same node key). Comparing them proved nothing. The cross-check now compares **different operators**: InFTF vs Ripple, with Honeycluster as backup. A revoke must be confirmed by both.
- **Revoke confirmation (found live on Testnet):** a server outage while confirming could skip the ledger check and re-enable "Sign" after the transaction was already sent. Now a sent transaction is never re-offered, confirmation is capped at about 90 s, and verification is retried ("Check again") until it can run. A dishonest wallet is still caught after the outage.
- **Page logic:**
  - tampered saved settings (a 99,999,999-drop fee limit, a 0.0001-minute Watch timer) were accepted; now only exact offered values are
  - the network could be switched mid-revoke
  - Watch mode watched whatever was typed in the box
  - old history checks kept running after a new scan
  - a missing amount showed as "NaN"
- **Pre-sign checker:**
  - a batch nested 5,000 deep crashed it, and corrupted real blobs crashed it 9 times in 3,267
  - there was no size limit (a 5.4 MB paste was accepted); anything over 1 million characters is now refused
  - "disable master key" was rated Medium
  - NFT give-aways, escrows, payment channels, memo links, partial payments, no-expiry pre-signed transactions, fee drains and 11-permission DelegateSets were not called out
- **Supply chain:** the release is now built from a lockfile-pinned install, so it rebuilds **byte-for-byte**.

Two weaknesses were found by the Mainnet backtest and fixed earlier:
1. A rate-limit JSON reply ended a scan instead of failing over.
2. The history check looked at only 400 transactions and missed 7 real delegated transactions on one wallet.

## Security

**Always on:**
- no secret keys requested (the Testnet Practice Lab uses only throwaway faucet keys, Testnet only)
- no server of our own, no trackers, no third-party scripts (one self-contained file)
- strict Content-Security-Policy locked to one script hash and the listed ledger servers
- refuses to run inside another site's frame
- all ledger text cleaned and escaped
- hard time limits on every server question
- exact-value validation of saved settings
- one click = one transaction
- network locked during a revoke

**User switches** (in the *Security* tab, safest choice on by default):

| Switch | Default |
|---|---|
| Strict transaction check before the wallet opens | On |
| Verify on the ledger after signing (by two independent operators on Mainnet) | On |
| Network lock (wallet and page must be on the same network) | On |
| Fee limit (0.0001 / 0.001 / 0.005 XRP) | 0.001 XRP |
| Second-operator cross-check (Mainnet) | On |
| Address fingerprint (defeats clipboard swaps) | On |
| Privacy blur for screen sharing | Off |
| Auto-disconnect wallet after inactivity | On (5 min) |
| Watch mode (re-scan on a timer, alert on change) | Off |
| Browser notifications for Watch mode | Off |
| Remember settings on this device | Off (nothing stored) |
| **Forget everything now** button | — |

## Network access

Only public servers listed on xrpl.org's "Public Servers" page:

- **Mainnet, main reads:** `https://xrplcluster.com` (alias `https://xrpl.ws`), operated by InFTF
- **Mainnet, independent second opinion:** `wss://s2.ripple.com` / `wss://s1.ripple.com` (Ripple), then `wss://honeycluster.io` (Honeycluster). These are reached over WebSocket because their HTTPS endpoints send no CORS header.
- **Testnet:** `https://testnet.xrpl-labs.com`, plus the official faucet `https://faucet.altnet.rippletest.net` for the Practice Lab

## Hosting your own copy

The ready-built file, its security headers, checksum and the user manual are in `release/`.

1. Upload `release/xrpl-delegation-checker--2026-10-24.html` to any static host, for example as `/tools/xrpl-delegation-checker/index.html`.
2. Add the lines from `_headers--2026-10-24.txt` to your host's headers config, and edit the path line (it starts with `/tools/`) to match.
3. Check your copy matches: `sha256sum` it and compare with `SHA256SUMS--2026-10-24.txt`.

## Rebuild it yourself (reproducible)

```
npm ci              # exact versions from package-lock.json
node build.mjs      # writes dist/xrpl-delegation-checker--2026-10-24.html
sha256sum dist/*.html   # matches SHA256SUMS--2026-10-24.txt
```

Tests (always from this folder, so tests and release use the same settings): `node build.mjs --test`, then bundle and run `test/unit.mjs`, `test/attack-core.mjs` and `test/lab-live.mjs` with esbuild, and run `test/attack-browser.mjs`, `test/browser.mjs` (live Testnet + Mainnet), `test/lab-browser.mjs <release file>`, `test/release-smoke.mjs` and `test/file-open.mjs` with Playwright Chromium. `test/wallet-e2e/` drives the real wallet extensions (see its README).

Results for 1.0.4: unit all passed · attack-core 35/35 · attack-browser 26/26 · browser (live) 35/35 · lab-live all passed · lab-browser all passed · release-smoke and file-open all passed.

## Disclaimer

Independent community tool. Not affiliated with Ripple, the XRPL Foundation, InFTF, Honeycluster, XRPL Labs, Crossmark or GemWallet. Educational and informational only, not financial advice. Always confirm what you sign inside your own wallet.

## License

MIT, © 2026 Stanley Gebara · CryptoLwa
