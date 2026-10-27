# Signed by one of a published set of keys, on the Zcash public testnet

`keys.txt` is a co-op's published key set: four wallets' spend keys (`zceipt key -w <wallet>`).
`link.txt` is a receipt for payment `571de6e4…` with a key-set proof (`m=zip311m1…`): it was
signed under one of the four keys, without saying which.

    zceipt verify "#$(cat examples/testnet/keyset/link.txt)" --key-set examples/testnet/keyset/keys.txt

Made with `zceipt create -w <wallet> -i <identity> --txid … --key-set keys.txt`.
