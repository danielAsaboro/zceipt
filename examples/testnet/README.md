# A real receipt on the Zcash public testnet

Transaction `571de6e4cc96b64c0d849cc172905449011b195e521532d78fe9c29a149e0e73`, an Ironwood
payment of 0.01 TAZ with the memo "Invoice 42: two coffees", mined at testnet height
4,500,997 (after the testnet upgrade that brought Ironwood, NU6.3, activated at 4,465,026; librustzcash calls it NU7). The sender wallet was funded by the Valar testnet
faucet.

Verify it against the chain:

    zceipt verify @examples/testnet/receipt-link.txt --expect-address "$(cat examples/testnet/merchant.ua)"

Or open the verifier page with `#` followed by the contents of `receipt-link.txt` after its `#`.
With its `h=` block hint, the page fetches the payment among its block's transactions from
`zcash-testnet.chainsafe.dev` over grpc-web.

`tx.hex` holds the raw transaction bytes, so the page's offline mode can verify it with no
network access.

## An exchange deposit across the ZIP 320 TEX two-step

`deposit-receipt.txt` proves a real testnet deposit of 0.002 TAZ to the TEX address in
`merchant.tex`. The contributor wallet paid it in two transactions mined in block 4,502,928:
`cfb97544…` (shielded Ironwood spend to a one-time transparent address) and `ee624215…` (that
address to the TEX). The receipt is for the first one and signs `tex-deposit:` and `second-tx:`
lines; verifiers check the spend proof and that the second transaction spends the first and pays
the TEX.

    zceipt verify @examples/testnet/deposit-receipt.txt

It links the sender's shielded funds to the exchange deposit, so share it only with the exchange.

## Every proof on the testnet: `proofs/`

Made by `scripts/e2e-testnet.sh`'s steps on 2026-10-25 from throwaway testnet wallets (a payer with
accounts 0 and 1, a second wallet, a merchant), checked offline by
`crates/zceipt-cli/tests/testnet_adversarial.rs` and `packages/zceipt/test/testnet-proofs.test.js`:

| File | What |
|---|---|
| `claim.txt` | A claim in `airdrop-testnet` at block 4,539,360 (domain `airdrop-testnet`, floor 0.01 TAZ) |
| `tagA.txt`, `tagB.txt`, `tagC.txt`, `tagS.txt` | Payer tags in `round-testnet` for four real payments: A and B by account 0 (same tag), C by account 1, S by a second wallet |
| `sib.txt` | The sibling-account proof for accounts 0 and 1: its tags are those of A and C |
| `income.txt` | Merchant income across A, C and S |
| `dv.txt`, `shop.key`, `other.key` | A receipt for one verifier (the shop's key) and a key that must refuse it |
| `dg.txt`, `dg2.txt`, `dg-expired.txt`, `dg-wrong-payee.txt` | A delegated receipt, and three the policy refuses |
| `frost/` | A 2-of-3 FROST receipt for payment A with its policy proof and the published commitment |
| `tx{A,B,C,S}.hex`, `height*`, `txid*` | The four payments, so all of it checks offline |
