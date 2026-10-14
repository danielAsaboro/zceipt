# A real receipt on the Zcash public testnet (NU7)

Transaction `571de6e4cc96b64c0d849cc172905449011b195e521532d78fe9c29a149e0e73`, an Ironwood
payment of 0.01 TAZ with the memo "Invoice 42: two coffees", mined at testnet height
4,500,997 (after NU7 activated at 4,465,026). The sender wallet was funded by the Valar testnet
faucet.

Verify it against the chain:

    receipts verify @examples/testnet/receipt.txt --expect-address "$(cat examples/testnet/merchant.ua)"

Or open the verifier page with `#` followed by the contents of `receipt.txt`. The page fetches
the transaction from `zcash-testnet.chainsafe.dev` over grpc-web.

`tx.hex` holds the raw transaction bytes, so the page's offline mode can verify it with no
network access.
