# Signed payment requests on the Zcash public testnet

- `request.txt`: a request signed by the testnet merchant's key for `kemis-coffee.test`
  (0.0025 TAZ, "Order 42: two coffees", code `0c0ffee042`, valid until 2036). The Python verifier
  checks it (`spec-verifier/tests/test_testnet.py::test_signed_request`).
- `request-paid.txt`: a request for 0.002 TAZ ("Order 88: one espresso (signed request)", code
  `5e9ed88a`) that `zceipt shop pay` checked against a local `/.well-known/zceipt.json` and
  paid on testnet in `fe3eb626…` (height 4,507,338).
- `receipt-link.txt`: the payer's receipt for it, which signs `challenge:5e9ed88a` and shows the
  shop's memo:

      zceipt verify @examples/testnet/request/receipt-link.txt --expect-address "$(cat examples/testnet/merchant.ua)"
