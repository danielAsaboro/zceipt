# A public demo wallet: sign a real receipt with your own message

Transaction `d2d4c90445cb714e0ca8da14d881be4fb606cdcd9bd6b658ec3da76fb44252f4` (testnet block
4,532,976) pays 0.002 TAZ to the merchant in `../merchant.ua` from a throwaway wallet made for
this. Its Orchard spending key is `orchard-spending-key.hex`, public on purpose: never send it
funds.

`prepared.txt` is that payment's receipt with every proof made (`receipts create --unsigned`).
The proofs don't cover the message, so anyone can sign it for their own message:

    receipts demo -m "your message"

or **Make one with your own message** on the verifier page, which signs in the browser in
milliseconds and verifies the result against the chain. `tx.hex` is the transaction, for offline
checks.

What it shows: a receipt is signed by the key that spent the money. What it doesn't: since this
key is public, a receipt from this wallet proves nothing about who made it.
