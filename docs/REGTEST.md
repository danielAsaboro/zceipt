# Run the whole flow on a private regtest chain

You need Docker (for Zebra), Go (for lightwalletd), Rust, and
[zcash-devtool](https://github.com/zcash/zcash-devtool) built with `--features regtest_support`.
Every network upgrade through NU6.3 (Ironwood) activates at height 1.

```bash
cd scripts/regtest

# 1. Zebra on regtest, JSON-RPC on :18232
docker run -d --name zebra-regtest -p 18232:18232 \
  -v $PWD/zebrad.toml:/etc/zebrad.toml:ro -v $PWD/zebra-state:/var/cache/zebra \
  --entrypoint zebrad zfnd/zebra:latest -c /etc/zebrad.toml start

# 2. Mine one block so lightwalletd has something to serve, then start lightwalletd on :9067
rpc() { curl -s -H 'content-type: application/json' -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" http://127.0.0.1:18232; }
rpc generatetoaddress '[1,"tmGys6dBuEGjch5LFnhdo5gpSa7jiNRWse6"]'
lightwalletd --no-tls-very-insecure --grpc-bind-addr 127.0.0.1:9067 --zcash-conf-path ./zcash.conf --data-dir ./lwd-data &

# 3. Two wallets
for w in sender merchant; do
  zcash-devtool wallet -w ./$w init --name $w -i ./$w.age -n regtest --activation-heights ./heights.toml -s 127.0.0.1:9067
done
SENDER=$(zcash-devtool wallet -w ./sender list-addresses | sed -n 's/.*Default Address: //p')
MERCHANT=$(zcash-devtool wallet -w ./merchant list-addresses | sed -n 's/.*Default Address: //p')

# 4. Mine shielded coinbase (Ironwood) to the sender and let it mature
rpc generatetoaddress "[4,\"$SENDER\"]"; rpc generatetoaddress '[101,"tmGys6dBuEGjch5LFnhdo5gpSa7jiNRWse6"]'
zcash-devtool wallet -w ./sender sync -s 127.0.0.1:9067

# 5. Pay the merchant, mine it
zcash-devtool wallet -w ./sender send -i ./sender.age --address "$MERCHANT" --value 42000000 --memo "Invoice 42" -s 127.0.0.1:9067
rpc generatetoaddress '[2,"tmGys6dBuEGjch5LFnhdo5gpSa7jiNRWse6"]'
zcash-devtool wallet -w ./sender sync -s 127.0.0.1:9067

# 6. Receipt, then verify (CLI and browser)
receipts create -w ./sender -i ./sender.age --txid <txid> -m "Order #42" --link-base 'http://localhost:5321/?regtest'
receipts verify @receipt.txt --regtest ./heights.toml --expect-address "$MERCHANT"
node ../dev-server.mjs   # serves web/ and bridges grpc-web to lightwalletd; open the printed link
```
