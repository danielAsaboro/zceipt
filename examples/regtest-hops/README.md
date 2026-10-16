# Multi-hop source of funds on a private regtest chain

Made by `scripts/e2e-regtest.sh` ("Multi-hop source of funds"): an exchange wallet withdraws
0.5 ZEC to a saver's transparent address; the saver shields it (`83ff8227…`), moves 0.45 ZEC to
itself (`884fd957…`), then pays a merchant 0.3 ZEC (`4366c749…`). `batch.txt` holds receipts for
the self-transfer and the payment, each with `--prove-source`; `report.txt` is what
`receipts verify` printed against the chain: every hop proven back to the withdrawal address.
