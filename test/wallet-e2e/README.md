# Real wallet extension tests

These scripts drive the **real** Crossmark and GemWallet browser extensions (downloaded from the Chrome Web Store) through connect and revoke on the XRPL Testnet, against a build of the tool.

Run on 24 October 2026 with Crossmark 0.2.19 and GemWallet 3.8.2:

- Connect: works in both.
- Network report: works in both (GemWallet on a custom network reports "custom", which the Network lock correctly blocks).
- Signing the revoke (`DelegateSet`): **refused by both** with "Invalid field TransactionType: DelegateSet". Nothing was sent; the Delegate entry stayed on the ledger. The tool shows a plain-English explanation and the copy-and-sign route.

How to run (needs Xvfb, Playwright Chromium and the unpacked extensions):

1. `OUT=<dir>/accts.json node setup-accounts.mjs` creates a funded Testnet owner and delegate and grants the delegation (uses xrpl.js).
2. Unpack each extension's .crx into `<S>/crx/gem` and `<S>/crx/crossmark`, then import the owner seed into each wallet once (persistent profiles in `<S>/ext/profile-<wallet>`), and select a Testnet network that your machine can reach.
3. `S=<dir> WALLET=crossmark TOOL=<tool.html> xvfb-run -a node e2e.mjs` (add `NOLOCK=1` for GemWallet on a custom network).

The popup helpers (`*-prep.mjs`) click through each wallet's own approval screens; they depend on those wallets' current layouts and may need updating when the wallets change.
