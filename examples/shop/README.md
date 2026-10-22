# Kemi's Coffee: a shop integration

A complete checkout built on the Receipts API, in about 200 lines of Node with no dependencies.

```bash
receipts serve                                             # in another terminal
RECEIPTS_KEY=rcpt_test_… SHOP_ADDRESS=utest1… node examples/shop/server.mjs
open http://localhost:4242
```

1. Pick drinks and press **Pay with Zcash**. The shop creates a proof request for the order
   total, with the order id in `metadata`.
2. The order page shows the ZIP-321 QR code and the exact `receipts create … --request …`
   command for the customer.
3. The customer pastes the receipt link. The shop calls `requests.submitReceipt`. Receipts also
   sends a signed `request.fulfilled` webhook, which the shop verifies with
   `webhooks.constructEvent` and uses to mark the order paid.

To try it with no wallet, paste `zip311_test_valid` as the receipt (test keys only).

Verified on the public testnet: order `KCZR49U` (2 flat whites, 0.01 ZEC) was paid by
transaction `571de6e4…9e0e73`. The customer's wallet answered the order's request, and the
webhook was delivered with a valid signature (HTTP 200).
