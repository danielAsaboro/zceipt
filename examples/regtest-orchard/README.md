# A real Orchard receipt (regtest)

Transaction `6fe3c4a49619e7cba08ab69cdb85c71e152c4e9983564e8de203c8276b4de66e`: an Orchard-pool
payment of 0.42 ZEC with the memo "Invoice 7: Orchard espresso", mined at height 212 of a Zebra
regtest chain where NU5 through NU6.2 are active from height 1 and NU6.3 (Ironwood) only from
height 1000 (`heights.toml`). That is the shape of today's mainnet, where wallets such as Zashi
send from the Orchard pool. The sender was funded with Orchard coinbase and paid with
`zcash-devtool`; the receipt was made with `receipts create` (it picks Orchard automatically
when the transaction has no Ironwood bundle).

    receipts verify @examples/regtest-orchard/receipt.txt --regtest examples/regtest-orchard/heights.toml \
      --raw-tx examples/regtest-orchard/tx.hex --height 212 --expect-address "$(cat examples/regtest-orchard/merchant.ua)"
