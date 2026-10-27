# Recipe: confirm a shielded checkout without sharing a viewing key

If you run your own wallet you already see your incoming payments. A receipt adds what your
wallet can't give you: proof of who paid (the customer's wallet made the payment, not someone who
saw it), proof that a third party can check (a processor, a marketplace, an arbitrator) without
your viewing key, and a payment tied to one order so it can't be claimed twice. A payment
processor that today needs your viewing key to confirm orders can confirm them from receipts
instead.

1. At checkout: `requests.create({ payee, amount_zatoshis, metadata: { order_id } })`, then show
   `payment_uri` as a QR code.
2. After paying, the customer's wallet (or `zceipt create --request <receipt_link>`)
   produces a receipt. They paste it on your order page, or their wallet posts it.
3. `requests.submitReceipt(id, { receipt })`, or listen for `request.fulfilled`, then ship.

What you learn: that this order was paid, how much, and the memo. What you don't: who the
customer is, their balance or their other payments.
