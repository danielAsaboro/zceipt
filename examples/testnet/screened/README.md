# A deposit from a screened list, on the Zcash public testnet

`list.txt` is an exchange's published screened list: the note commitments of the 16 Orchard and
Ironwood outputs of 8 testnet transactions it vetted (`zceipt screened-list`). `receipt.txt`
is a receipt for payment `571de6e4…` (block 4,500,997), and `proof.txt` proves the note that
payment spent was one of the 16, holding at least 0.01 TAZ, without saying which.

    zceipt verify @examples/testnet/screened/receipt.txt --screened-set examples/testnet/screened/list.txt --screened-proof @examples/testnet/screened/proof.txt

The verifier page's **Try a deposit from a screened list** shows the same check in the browser.
