# A real receipt on the Zcash public testnet (NU7)

Transaction `571de6e4cc96b64c0d849cc172905449011b195e521532d78fe9c29a149e0e73`, an Ironwood
payment of 0.01 TAZ with the memo "Invoice 42: two coffees", mined at testnet height
4,500,997 (after NU7 activated at 4,465,026). The sender wallet was funded by the Valar testnet
faucet.

Verify it against the chain:

    receipts verify @examples/testnet/receipt-link.txt --expect-address "$(cat examples/testnet/merchant.ua)"

Or open the verifier page with `#` followed by the contents of `receipt.txt`. The page fetches
the transaction from `zcash-testnet.chainsafe.dev` over grpc-web.

`tx.hex` holds the raw transaction bytes, so the page's offline mode can verify it with no
network access.

## An exchange deposit across the ZIP 320 TEX two-step

`deposit-receipt.txt` proves a real testnet deposit of 0.002 TAZ to the TEX address in
`merchant.tex`. The contributor wallet paid it in two transactions mined in block 4,502,928:
`cfb97544…` (shielded Ironwood spend to a one-time transparent address) and `ee624215…` (that
address to the TEX). The receipt is for the first one and signs `tex-deposit:` and `second-tx:`
lines; verifiers check the spend proof and that the second transaction spends the first and pays
the TEX.

    receipts verify @examples/testnet/deposit-receipt.txt

It links the sender's shielded funds to the exchange deposit, so share it only with the exchange.
