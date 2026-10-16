# Proof of funds on the Zcash public testnet

`proof.txt` proves the testnet sender wallet holds 0.0969 TAZ in one unspent Ironwood note,
against the Ironwood tree root after block 4,507,663 (`anchor.hex`, as lightwalletd reported it),
bound to `challenge:otc-desk-7f3a holding check`. `report.txt` is what `receipts verify` printed:
373,677 blocks of Ironwood nullifiers scanned (45 s cold over a public lightwalletd, 2.5 s cached),
none of them the note's.

    receipts verify @examples/testnet/reserve/proof.txt

The result changes once the wallet spends that note: the same proof is then refused.
