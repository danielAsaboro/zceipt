# One request answered by two payments, on the Zcash public testnet

A shop asked for proof of payment for invoices 42 and 43 with one request (challenge
`b7e2c41a9d03`, payee `../merchant.ua`, at least 0.01 TAZ). The payer answered with one batch of
the two payments (`571de6e4…` and `db7c3c5e…`): every receipt signs the challenge, together they
paid the shop at least 0.01 TAZ, and the batch's same-payer proof shows one key signed both.
`link.txt` is the link's fragment.

    receipts verify "#$(cat examples/testnet/batch-request/link.txt)" --challenge b7e2c41a9d03 --expect-address "$(cat examples/testnet/merchant.ua)" --min 0.01

Made with `receipts create --txid … --txid … --request '<the shop's request link>'`.
