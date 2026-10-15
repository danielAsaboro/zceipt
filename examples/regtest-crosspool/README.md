# A cross-pool receipt: Orchard notes spent into an Ironwood output

After NU6.3 the Orchard pool is closed to new value, so a wallet still holding Orchard notes pays
by spending them into Ironwood outputs. The spend proof is about an Orchard note and the payment
is in the Ironwood bundle. This receipt (format v3) covers both: spend authority over the Orchard
action, and the disclosed Ironwood output.

It was made by `scripts/e2e-regtest.sh` (the merchant's refund in that run, signing the refund's
challenge) on a regtest chain with NU6.3 at height 300 (`heights.toml`).

    receipts verify @examples/regtest-crosspool/receipt.txt --regtest examples/regtest-crosspool/heights.toml \
      --raw-tx examples/regtest-crosspool/tx.hex --height $(cat examples/regtest-crosspool/height)
