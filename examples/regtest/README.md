# A real receipt from a local regtest chain

`tx.hex` is transaction `dcd2700def717468e6fe07c29a7a7f0fd7ec4e4157d03737f3a9f64e0fd4b732`, an
Ironwood (v6) payment of 0.42 ZEC with the memo "Invoice 42: two coffees". It was mined at
height 222 of a Zebra regtest chain with every upgrade through NU6.3 active from height 1
(`heights.toml`). It was sent by `zcash-devtool` from a wallet funded with mined coinbase.

`receipt.txt` was created from that sending wallet with:

    receipts create -w ./sender -i ./sender.age --txid dcd2700d… -m "Order #42 at Kemi's Coffee"

Verify it with no network at all:

    cargo test -p receipts-cli --release --test regtest_fixture

or open the verifier page, tick "Local regtest chain" in Settings, and paste `tx.hex` with
height `222`.

`merchant.ua` is the recipient's unified address, for the "was it paid to you?" check.
