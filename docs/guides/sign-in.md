# Sign in with Zcash

Let a user prove they control a shielded address, with no transaction, no fee and no account.
Use it to log in donors, unlock a members' area for people who paid, or link a payout address.

## How it works

1. Your server asks for a challenge: a nonce bound to your domain, valid for 5 minutes.
2. The user's wallet answers with a `zsig1…` sign-in. It is a Halo 2 action proof that spends a fresh
   1-zatoshi note addressed to the chosen address under a fresh randomized key, plus a RedPallas
   signature by that key over `(network, domain, nonce, issued_at, address, proof)`.
   Only the holder of the address's spending key can make one.
3. Your server verifies it once. The challenge is then spent.

A sign-in made for another site is refused (the domain is signed), and so is a replay (the nonce is
single-use). Nothing else about the wallet is revealed: not its balance, its notes or its other addresses.

## With the API

```bash
curl -s -X POST localhost:8723/v1/sign_in/challenges \
  -H "authorization: Bearer $RECEIPTS_KEY" -d '{"domain":"kemis-coffee.test"}'
```

The response carries `nonce` and a ready-made `wallet_command`. The user runs:

```bash
receipts sign-in -w ./wallet -i ./wallet.age --domain kemis-coffee.test --nonce <nonce>
```

and pastes the `zsig1…` into your page, which posts it to `POST /v1/sign_in/verify`:

```json
{ "object": "sign_in", "verified": true, "domain": "kemis-coffee.test", "address": "utest1…" }
```

Errors: `sign_in_malformed`, `sign_in_challenge_not_found`, `sign_in_challenge_used`,
`sign_in_challenge_expired`, `sign_in_invalid` (see [ERRORS](../ERRORS.md)).

## Without a server

The npm package verifies locally, in the browser or Node. You keep the nonce single-use yourself.

```js
import { verifySignIn } from "zcash-receipts";
const { address } = await verifySignIn(zsig, { domain: "kemis-coffee.test", nonce });
```

`examples/testnet/sign-in.txt` is a real testnet sign-in for `kemis-coffee.test` with nonce
`example-nonce-0001`.
