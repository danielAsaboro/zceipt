# Your shielded deposit is held: give the desk one link

An exchange, bridge or swap service has held a deposit you made from shielded ZEC and asks you to
show where it came from, or that it was you. Handing over a viewing key would show them every
payment your wallet ever made or received. A receipt shows them this one deposit and, if you
choose, where its money came from and an address you control. Nothing else.

## What to send

From the wallet that made the deposit (it asks for the seed phrase without showing it; [other ways](../../README.md#make-a-receipt-from-your-wallet)):

```bash
receipts create --seed-stdin --birthday <wallet birthday> --network main --txid <your deposit txid> \
  --prove-source --reveal-source-value \
  --prove-address <your address they know, if any> \
  -m "Deposit for account 7731"
```

If the desk gave you a request link, add `--request '<its link>'` so the receipt answers that
request and can't be reused elsewhere. Send the link the command prints. It opens on any copy of
the verifier page and checks in the browser; the receipt sits in the link's `#fragment`, which
browsers don't send to the page's host.

| Option | What the desk learns | Leave it out if |
|---|---|---|
| (always) | that your wallet's spend authority made this payment, its recipient, amount and memo | |
| `--prove-source` | which earlier transaction output created each note you spent; if that transaction was you shielding an exchange withdrawal, its transparent addresses and amounts | the desk doesn't ask where the money came from |
| `--reveal-source-value` | each spent note's exact value, so the desk can check the clear funding covers it | you only need to show the link, not the amounts |
| `--prove-address` | that the same spend authority controls an address you name (one they already know) | you don't want to link the deposit to an address |
| `--refund-to <address>` | an address of yours, signed into the receipt, for a refund only you could have chosen (`fresh` makes a new one, with a wallet directory) | |

What it never shows: your balance, your other notes or transactions, your viewing key.

## What the desk sees

Try it on the verifier page: **Try a deposit with its source** opens a real testnet receipt that
proves the note it spent came from transaction `2a2bd721…`. That transaction was itself funded
from shielded notes, so a desk would hold it for review and could ask for the next hop (a batch:
`--txid <earlier> --txid <deposit> --prove-source`). A desk running `receipts serve` screens the
funding automatically; see the [exchange runbook](exchange-deposit.md).

## Before you send it

- **You choose.** A receipt is evidence you decide to give for one deposit, not a standing
  permission. Automatic address-ownership protocols that wallets were expected to run for every
  withdrawal (AOPP, 2022) drew a backlash and were pulled; nothing here runs without you.
- **It links what it shows.** With `--prove-source` the desk can tie this deposit to the
  transaction that funded it. Send it only to the desk that asked.
- **It is a bearer proof.** Anyone you forward it to can show it. A receipt that answers the
  desk's request is useless to anyone else.
