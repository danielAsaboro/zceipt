# Recipe: confirm a shielded checkout without sharing a viewing key

Today a payment processor needs your viewing key, which exposes every incoming payment, to
tell you an order was paid. With Receipts the customer proves their one payment instead.

1. At checkout: `requests.create({ payee, amount_zatoshis, metadata: { order_id } })`, then show
   `payment_uri` as a QR code.
2. After paying, the customer's wallet (or `receipts create --request <receipt_link>`)
   produces a receipt. They paste it on your order page, or their wallet posts it.
3. `requests.submitReceipt(id, { receipt })`, or listen for `request.fulfilled`, then ship.

What you learn: that this order was paid, how much, and the memo. What you don't: who the
customer is, their balance or their other payments.
