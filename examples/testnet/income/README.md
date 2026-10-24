# Proof of income on the Zcash public testnet

`proof.txt` proves the merchant wallet (`../merchant.ua`) received at least 0.02 TAZ in total
across four real payments (`571de6e4…`, `08caa945…`, `ac5cf500…`, `fe3eb626…`), for a lender
who sent challenge `10a4e7c3d2b1`, without showing what any of them paid. It reveals which
outputs were counted and each note's nullifier, nothing else.

    receipts verify @examples/testnet/income/proof.txt --challenge 10a4e7c3d2b1 --min 0.02

Made with `receipts income -w <wallet> -i <identity> --txid … --txid … --min 0.02 -m "challenge:10a4e7c3d2b1"`.
