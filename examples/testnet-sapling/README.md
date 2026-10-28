# A Sapling receipt on the Zcash public testnet

Transaction `cbbdb8e071de55a9538c20c52a43a15cade18d41b14f1eb1ea122d64c264d627`, block 4552325:
a Sapling note spent to a Sapling address (0.005 TAZ, memo "Sapling invoice 311"). The note came
from `e1fca487b7254de46684ce2d559ae4634908e038ef354b1e89c33b7cc738006e`.

```
zceipt create-sapling -w sender -i sender.age cbbdb8e0…d627 --msg "zecathon sapling demo"
zceipt verify @examples/testnet-sapling/receipt.txt
```

`verify.txt` is the verifier's output: one spend proven with a fresh Sapling Spend proof under the
Zcash parameters' verifying key, and output 0 opened with its `ock`.
