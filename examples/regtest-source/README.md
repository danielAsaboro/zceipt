# Source of funds, end to end on a private regtest chain

Made by `scripts/e2e-regtest.sh` (section "Source of funds"):

1. An "exchange" wallet withdraws 0.3 ZEC to a customer's transparent address
   `tmRyMkJH1MJYcfbkshZcWs2XhZNWc9jy8Vb` (tx `cd79ad1e…`).
2. The customer shields it (tx `5093e033…`, height 530).
3. The customer pays a merchant 0.12 ZEC from the shielded note, memo "Deposit 99"
   (tx `b1ea959a…`, height 538).
4. `receipts create --prove-source` proves the payment's spent note was created by the shielding
   transaction; `report-chain.json` is what `receipts verify` printed against the chain, including
   the withdrawal address and amount that funded the shielding.

`receipt-source-value.txt` also reveals the spent note's exact value (0.149925 ZEC: the wallet
split the shielded 0.29985 ZEC into two notes).

Verify offline (no chain needed; the source transaction is supplied):

    receipts verify @examples/regtest-source/receipt-source-hidden.txt --regtest examples/regtest-source/heights.toml \
      --raw-tx examples/regtest-source/tx.hex --height 538 --source-raw-tx 530:examples/regtest-source/source-tx.hex

Offline, the transparent inputs are listed by outpoint only; online, the verifier also reads the
previous outputs (address and amount).
