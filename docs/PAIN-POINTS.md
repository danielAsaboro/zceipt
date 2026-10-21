# What people say is hard about Zcash, and what Receipts does about it

Receipts proves one shielded payment and reveals nothing else (ZIP 311 for Orchard and
Ironwood). This document steps back from the code. It collects what real users, merchants,
exchanges and developers say is painful about Zcash, isolates the pains a payment-proof tool can
honestly fix, looks at how other chains handle the same problems, and records what we built in
response and how it was checked.

Read in October 2026 from: the Zcash Community Forum (83 posts), GitHub issues across 15 Zcash
repositories (92 issues), X/Twitter (about 30 searches, 31 posts kept), Hacker News, and the
documentation, issues and forums of Bitcoin, Ethereum, Monero, Aleo, Penumbra, Namada and
Midnight projects. Reddit blocks automated reading, so the Reddit rows (section F, about 90
threads) come from Google's indexed titles and snippets of r/zec, r/Monero, r/CryptoCurrency,
r/Coinbase and others, not from opening the threads. Every row links to what was read; the text
is paraphrased.

## 1. The pain points

`Fit` says how a payment-proof tool relates to the pain: **core** (it is the job), **related**
(a receipt is part of the answer), **no** (a different problem). `Status` says where Receipts
stands: **done** (shipped before this pass), **new** (built in this pass), **open**.

### A. Proving a payment without a viewing key

| # | Pain | Sources | Fit | Status |
|---|---|---|---|---|
| A1 | There is no standard, verifiable artifact to prove a shielded payment; the Sprout-only tool was deprecated and nothing replaced it. Oldest open need (2015–2020, 140+ comments) | [zcash#2036](https://github.com/zcash/zcash/issues/2036), [zcash#406](https://github.com/zcash/zcash/issues/406), [zips#387](https://github.com/zcash/zips/issues/387), [forum: receipt standard](https://forum.zcashcommunity.com/t/should-zcash-have-a-proof-of-payment-receipt-standard/42732) | core | done |
| A2 | "So how do you prove you paid? Hand over your viewing key and expose everything" | [X: Sapling](https://x.com/saplingdotcash/status/2104741422079615363), [X: to zooko](https://x.com/saplingdotcash/status/2104751792462680143), [forum: destroy a view key](https://forum.zcashcommunity.com/t/is-it-possible-to-destroy-a-view-key/48369/5) | core | done |
| A3 | Existing proofs show a payment happened, not that *I* paid it, and anyone holding one can replay it | [zcash#737](https://github.com/zcash/zcash/issues/737), [zcash#4618](https://github.com/zcash/zcash/issues/4618) | core | done (spend authority + challenge) |
| A4 | A sender can't prove a z-to-z payment when the recipient denies it | [forum: 10 ZEC dispute](https://forum.zcashcommunity.com/t/an-anonymous-transaction-how-does-the-sender-prove-that-he-sent-the-anonymous-transaction-authentication-issues-for-anonymous-transmissions/36768), [X: sync bug](https://x.com/MaCapital8/status/2011538812313407651) | core | done |
| A5 | Someone holding only a txid can't check the amount without the viewing key | [forum](https://forum.zcashcommunity.com/t/how-to-verify-the-amount-from-the-tx-send-to-a-privacy-address/43027) | core | done |
| A6 | Apps ask users to paste their whole viewing key to show one thing (stream tips, dashboards) | [X: LiveZEC](https://x.com/LiveZEC/status/2106022681476829520) | related | done for payments |
| A7 | No way to prove ownership of a shielded address | [zcash#1770](https://github.com/zcash/zcash/issues/1770) | related | done (address proofs, Sign in with Zcash) |
| A8 | **Can't prove the *source* of a shielded payment** (marked as blocking ZIP 311) | [zcash#3828](https://github.com/zcash/zcash/issues/3828) | core | **new** (§3) |
| A9 | Disclosure is all or nothing per output (reveal only the amount, or not the memo) | [zcash#2631](https://github.com/zcash/zcash/issues/2631) (blocking ZIP 311) | related | **new**: `--withhold-memo` discloses recipient and amount, not the memo (§3b) |
| A10 | How viewing keys and payment disclosures interact is unspecified | [zips#327](https://github.com/zcash/zips/issues/327) | core | done ([CLAIM.md](CLAIM.md): a viewing key can't make a receipt) |
| A11 | A "selected-payment receipts SDK" grant was turned down; the grants committee asked for receipts through ZIP 311 on Ironwood instead | [forum, Sep 2026](https://forum.zcashcommunity.com/t/grant-application-zcash-selected-payment-receipts-sdk/57729/4) | core | done (this is what Receipts is) |

### B. Exchanges, source of funds and the transparent trap

| # | Pain | Sources | Fit | Status |
|---|---|---|---|---|
| B1 | Binance threatened a global delisting unless it could refuse shielded deposits, because it couldn't see where funds came from. Largest forum thread found (694 posts, 3.2k likes); led to TEX addresses | [forum](https://forum.zcashcommunity.com/t/important-potential-binance-delisting/45954) | core | **new** (§3) |
| B2 | Shielded deposits rejected; refunds took up to 32 working days | [forum](https://forum.zcashcommunity.com/t/binance-rejecting-deposits-from-zcash-shielded-addresses/47667) | related | done (TEX deposit receipts) + **new** |
| B3 | Exchanges demand source of funds: every deposit's origin, wallet ownership, 10+ years of history | [forum: Kraken-style email](https://forum.zcashcommunity.com/t/anybody-else-getting-this-from-kraken-exchange/55347), [forum: Binance](https://forum.zcashcommunity.com/t/binance-harassed-me-for-trading-privacy-coins-including-zcash/53273) | core | **new** |
| B4 | EU exchanges flag users as "high-risk" after they withdraw to a t-address and shield it | [forum](https://forum.zcashcommunity.com/t/flagged-for-shielding-zec-privacy-in-europe-under-attack/53140) | core | **new**: the proof shows the shielded funds are that very withdrawal |
| B5 | DEXs and exchanges list Zcash t-address only "because they can check source of funds"; shielded inputs into a CEX raise red flags | [X: sethforprivacy](https://x.com/sethforprivacy/status/1978121050371010938), [X: MisterMonero](https://x.com/MisterMonero/status/1986707619307004397), [X: Midnight president](https://x.com/Memesandmkts/status/2068921697068073052) | core | **new** |
| B6 | So most volume stays transparent ($420B labelled by Arkham), and unshielding large amounts is suspicious | [X: arkham](https://x.com/arkham/status/2110586299342262407), [X: janowitz](https://x.com/janowitz/status/2109617211128074516), [X: thaianhoang](https://x.com/thaianhoang/status/2110608015237824776) | related | **new** (gives exchanges a reason to accept shielded) |
| B7 | Wallets and regulators want "safe source" proofs before accepting funds; protocol engineers worry about privacy loss | [forum: transaction controls](https://forum.zcashcommunity.com/t/introducing-transaction-controls-in-zcash/49640) | core | **new** (opt-in, per payment) |
| B8 | Users forced into t-to-t sends to reach KYC'd exchanges; "exchanges will confiscate" shielded funds | [zingolib#1313](https://github.com/zingolabs/zingolib/issues/1313), [zingo-mobile#908](https://github.com/zingolabs/zingo-mobile/issues/908), [zwallet#112](https://github.com/hhanh00/zwallet/issues/112) | related | **new** |
| B9 | Delistings under MiCA Art. 76 / AMLR 2027; Dubai ban | [X](https://x.com/KiwiTuckerNE/status/2104545622984687721), [X](https://x.com/realMaxAvery/status/2019193593970249764), [forum: EU](https://forum.zcashcommunity.com/t/binance-to-disable-zec-trading-in-france-italy-poland-and-spain-by-the-end-of-june/44750) | related | regulatory; receipts are the per-payment disclosure such rules ask for |
| B10 | Compliance teams only follow what the law recognises; new attestations without regulator sign-off won't be adopted | [forum: compliance bridge](https://forum.zcashcommunity.com/t/grant-application-shielded-compliance-bridge/56862) | caution | open: adoption is the exchange's call, not ours |
| B11 | TEX sends break wallets (crash, zero balance, stranded refunds) | [zwallet#173](https://github.com/hhanh00/zwallet/issues/173), [zingo-mobile#1400](https://github.com/zingolabs/zingo-mobile/issues/1400), [zingolib#2387](https://github.com/zingolabs/zingolib/issues/2387) | no | wallet bugs |
| B12 | Exchanges lack bulk deposit monitoring for shielded addresses | [zcash#1333](https://github.com/zcash/zcash/issues/1333), [zallet#773](https://github.com/zcash/zallet/issues/773) | related | done (requests API, webhooks) |

### C. Merchants: invoices, refunds, disputes

| # | Pain | Sources | Fit | Status |
|---|---|---|---|---|
| C1 | Accepting ZEC means syncing nodes, Docker and exporting viewing keys; a non-technical merchant gave up in 20 minutes; the BTCPay plugin broke unnoticed | [forum: CipherPay](https://forum.zcashcommunity.com/t/cipherpay-yes-another-zcash-payment-processor-sorry-live/54830), [forum: BTCPay](https://forum.zcashcommunity.com/t/btcpayserver-zcash-plugin-opinions-on-next-steps/53734) | related | done (no viewing key on the server; `receipts demo`) |
| C2 | No standard refund, underpaid or expired states | [forum: order-pay](https://forum.zcashcommunity.com/t/grant-application-zec-order-pay-shielded-zec-checkout-refunds-and-creator-payouts-for-service-marketplaces/58168) | related | done (requests, refunds, finality) |
| C3 | Refunds are slow because privacy makes failed payments hard to trace | [X: ZECBIT](https://x.com/NafterG/status/2103437968124018963) | core | done (signed `refund-to:`) |
| C4 | Shielded receivers learn no return address; swap UIs make users type refund addresses by hand, unvalidated | [X](https://x.com/monaverse_nft/status/2101960445267472704), [zodl-android#1983](https://github.com/zodl-inc/zodl-android/issues/1983) | related | done |
| C5 | Unsigned ZIP 321 requests: over/under/duplicate payments, no way to authenticate who is asking | [zips#611](https://github.com/zcash/zips/issues/611), [zips#977](https://github.com/zcash/zips/issues/977), [forum: ZecAuth](https://forum.zcashcommunity.com/t/zip-321-tells-a-wallet-what-to-pay-zecauth-adds-authenticated-privacy-aware-interaction/57553) | related | **new**: signed requests checked against the shop's domain (§3d) |
| C6 | Multi-payment URIs can hide recipients the user then signs | [zodl-android#2217](https://github.com/zodl-inc/zodl-android/issues/2217) | related | done (`receipts check-link` warns; `receipts pay` shows the full address and amount) |
| C7 | Strangers can't trade without someone paying first and hoping | [X: Aegis Gate](https://x.com/RaphElevator/status/2107193116650254665) | related | done for the proof half; escrow is out of scope |
| C8 | Point-of-sale: 3 minutes to confirm a shielded payment pushes builders back to transparent | [forum: ROZO](https://forum.zcashcommunity.com/t/rozo-merchant-pos-fast-zcash-payments-for-merchants-irl-grant-application/56374) | no | block time |

### D. Accounting, tax, audits, donations

| # | Pain | Sources | Fit | Status |
|---|---|---|---|---|
| D1 | Nothing turns a viewing key into records an accountant or auditor recognises (52-like thread) | [forum](https://forum.zcashcommunity.com/t/is-anyone-actually-using-viewing-keys-for-business-accounting/56300) | related | done for payments sent (batches); **new** for payments received (incoming receipts, §3c); full ledgers stay a viewing-key job |
| D2 | Wallet tax exports are thin or missing; history wrong (change as income) | [forum](https://forum.zcashcommunity.com/t/exporting-transaction-history-to-json-csv-from-ufvk-seed/54662), [librustzcash#1304](https://github.com/zcash/librustzcash/issues/1304), [zwallet#160](https://github.com/hhanh00/zwallet/issues/160) | no | wallet history |
| D3 | A DAO treasury couldn't produce repeatable proof of shielded reserves | [forum](https://forum.zcashcommunity.com/t/shielded-viewing-keys/54837) | related | **new**: proof of funds (§3f) |
| D4 | Donation campaigns publish viewing keys by hand for transparency | [forum: Venezuela](https://forum.zcashcommunity.com/t/zcash-for-venezuela/56445), [forum: ZOMG](https://forum.zcashcommunity.com/t/zomg-transparency-report-and-accounts/38949) | core | done (aggregate campaigns, public notes) |
| D5 | Grant and payroll proof for one transfer | [X: Zalary](https://x.com/UseZalary/status/2109338990109151660), [X: Obliq](https://x.com/IamAlikeX/status/2108080560811933808) | core | done (batches) |

### E. Not a payment-proof problem (recorded so we don't pretend otherwise)

| # | Pain | Sources |
|---|---|---|
| E1 | Amount and timing correlation de-anonymised the Ledger thief's pass-through (108/108 exits matched); 5,249 possible round trips | [X: YFarmX](https://x.com/YFarmX/status/2108918564015006200), [X: zecblock](https://x.com/zecblock/status/2109826962768429132) |
| E2 | Wallets break around network upgrades; balance shown but sends fail | [zwallet#266](https://github.com/hhanh00/zwallet/issues/266), [zwallet#268](https://github.com/hhanh00/zwallet/issues/268) |
| E3 | Slow sync, old wallets hard to recover | [X: lopp](https://x.com/lopp/status/1989769520936788160), [zodl-ios#1241](https://github.com/zodl-inc/zodl-ios/issues/1241) |
| E4 | Same seed, different u1 address across wallets | [X](https://x.com/besiktaspokemon/status/2099643383408906574) |
| E5 | NEAR Intents exits: holds, AML reversals, t-address reuse | [X: spirobel](https://x.com/spirobel/status/2110246706050912628) |
| E6 | Memo download leaks txids to the server; memos off by default | [zwallet#38](https://github.com/hhanh00/zwallet/issues/38), [zingo-mobile#93](https://github.com/zingolabs/zingo-mobile/issues/93) |

### F. Reddit (from Google's index of the threads)

| # | Pain | Thread | Fit | Status |
|---|---|---|---|---|
| F1 | Coinbase won't withdraw ZEC to a shielded address; users must make a transparent one | [r/Coinbase](https://www.reddit.com/r/Coinbase/comments/lzu8ie/withdraw_zcash_to_shielded_addresses/) | related | **new** (source proof covers the shield-after-withdrawal path) |
| F2 | Trouble sending ZEC from a Ledger to Coinbase; "is it only for shielded?" | [r/CryptoHelp](https://www.reddit.com/r/CryptoHelp/comments/1w8ua10/i_have_read_a_lot_stories_about_having_trouble/) | related | **new** |
| F3 | Users want to buy on Coinbase then gain privacy, unsure whether the KYC on-ramp undoes it | [r/zec](https://www.reddit.com/r/zec/comments/1pg162y/how_effective_is_zcash_for_improving_privacy/), [r/zec](https://www.reddit.com/r/zec/comments/1oc1tuz/buying_from_coinbase/) | related | **new**: the link back to the withdrawal is now shown only to whom the user chooses |
| F4 | Zodl forces shielding; can't send out from the transparent address | [r/zec](https://www.reddit.com/r/zec/comments/1s25i00/unshielding_zec_on_zodl_wallet_and_sending_back/) | no | wallet policy |
| F5 | "Why do KYC exchanges allow ZEC?" — because privacy is optional and most use is transparent; optional privacy seen as a trap that erodes the shielded set | [r/Monero](https://www.reddit.com/r/Monero/comments/1o453e3/why_centralised_kyc_exchanges_allow_zec/), [r/zec](https://www.reddit.com/r/zec/comments/1oyz2bt/is_zcashs_privacy_model_a_trap_how_optional/), [r/zec](https://www.reddit.com/r/zec/comments/1ovs5ad/some_zcash_info_people_really_arent_talking_about/) | related | **new**: gives exchanges a way to accept shielded deposits instead of pushing users transparent |
| F6 | Monero is adding view keys aimed at getting listed again | [r/Monero](https://www.reddit.com/r/Monero/comments/1v4ecbj/moneros_new_view_keys_will_allow_it_to_become/) | context | competitors move toward disclosure too |
| F7 | Monero users rely on tx keys / payment proofs for disputes; a gateway (xmr-pay) lets merchants verify tx proofs serverless; wallets like Exodus don't expose them | [r/Monero](https://www.reddit.com/r/Monero/comments/1u3kl74/xmrpay_free_open_source_monero_payment_gateway/), [r/ExodusWallet](https://www.reddit.com/r/ExodusWallet/comments/rov4za/how_do_i_find_payment_proof_of_monero/), [r/monerosupport](https://www.reddit.com/r/monerosupport/comments/1lh38x5/mastering_monero_questions_regarding_proof_of/) | core | done: Receipts is the Zcash equivalent, with sender proof |
| F8 | "Where one can prove payment was made if there is a dispute" raised against private money | [r/btc](https://www.reddit.com/r/btc/comments/1oexnp9/do_you_want_a_gps_tracker_on_the_cash_you/) | core | done |
| F9 | Viewing keys pitched as the compliance answer ("hand one to an accountant") | [r/CryptoCurrencyFIRE](https://www.reddit.com/r/CryptoCurrencyFIRE/comments/1vg59ii/building_a_compliancefirst_protocol_for/), [r/zec](https://www.reddit.com/r/zec/comments/9vg294/zec_may_not_list_on_coinbase/) | core | done (a receipt instead of a key) |
| F10 | The Orchard minting bug: "impossible to prove whether it was exploited" | [r/CryptoCurrency](https://www.reddit.com/r/CryptoCurrency/comments/1tyk1sd/zcash_bug_allowed_unlimited_minting_was_it/) | no | supply auditing, not payments |
| F11 | Zodl/Zashi balance shows zero, sends fail, wallet resets; YWallet shows a balance it can't spend | [r/zec](https://www.reddit.com/r/zec/comments/1w5jmd6/my_zodl_balance_is_showing_zero_but_history_of/), [r/zec](https://www.reddit.com/r/zec/comments/1q9fya1/zashi_transactions_not_working/), [r/zec](https://www.reddit.com/r/zec/comments/1w7hgvb/zodl_wallet_random_reset_and_all_my_zcash_gone/), [r/zec](https://www.reddit.com/r/zec/comments/18rtk7n/ywallet_shows_zec_balance_in_z_u_address_but_i/) | no | wallet reliability |
| F12 | Unified vs transparent addresses confuse users | [r/zec](https://www.reddit.com/r/zec/comments/1fw62gy/question_about_unified_addresses/), [r/zec](https://www.reddit.com/r/zec/comments/vksxvf/ua_addresses_and_shielded_funds/) | no | wallet UX |
| F13 | Amount correlation and a small anonymity set break optional privacy | [r/Monero](https://www.reddit.com/r/Monero/comments/1ij2pup/optional_privacy_vs_full_privacy/), [r/zec](https://www.reddit.com/r/zec/comments/9ql7dn/psa_zcash_sapling_fullyshielded_transactions/) | no | see E1 |
| F14 | Swaps make users paste a refund address by hand (and a QR adds a `solana:` prefix) | [r/zec](https://www.reddit.com/r/zec/comments/1x47ge9/for_people_who_hold_zec_on_solana_whats_your/) | related | done (signed, checked `refund-to:`) |

Reddit agrees with the other sources: the exchange on-ramp and off-ramp is where privacy breaks,
and Monero users already lean on per-payment proofs that Zcash lacked.

What stands out: the loudest pain a payment-proof tool can address is **B (source of funds)**.
It is the largest forum thread, it is why exchanges keep Zcash transparent, and it is the one
ZIP 311 blocker (A8) nobody had attempted.

## 2. What other chains do about the same problems

| System | Primitive | What it solves | Limits users complain about | Source |
|---|---|---|---|---|
| Monero | `get_tx_proof` / OutProof, SpendProof, reserve proof | Prove a payment, prove who paid, prove a balance; Bisq auto-confirms trades with tx keys | Proof keys lost on restore; GUI bugs; merchants got false "received nothing"; Koinly can't import; delisted by Binance and Kraken EEA | [prove a payment](https://getmonero.org/resources/user-guides/prove-payment.html), [GUI bug](https://github.com/monero-project/monero-gui/issues/2270), [false "never received"](https://forum.getmonero.org/5/support/89195/monero-never-received-funds-despite-confirmation), [Koinly](https://feedback.koinly.io/integrations/p/support-xmr), [Kraken EEA](https://decrypt.co/284276/monero-kraken-delisting-xmr-european) |
| Bitcoin BIP-352 | Silent payments | Unlinkable receiving | No proof of payment or refund story; a btc++ project ("Silent Receipts") adds one | [BIP-352](https://bips.dev/352/), [silent-receipts](https://github.com/echennells/silent-receipts) |
| Lightning BOLT12 | Payer proofs, preimage | Prove you paid, reveal chosen fields, bind a note | Shipped without security analysis (2026 paper) | [delving bitcoin](https://delvingbitcoin.org/t/expanding-on-bolt12/1167) |
| Bitcoin BIP-322 | Message signing | Prove control of an address (EU travel rule accepts it) | Transparent only | [BIP-322](https://bips.dev/322/) |
| Railgun | Private Proofs of Innocence | Prove funds are **not** from flagged lists; 1-hour standby after shielding | One list provider; users wait | [Railgun docs](https://docs.railgun.org/wiki/assurance/private-proofs-of-innocence), [L2BEAT](https://l2beat.com/privacy/projects/railgun) |
| Privacy Pools (0xbow) | Association sets, ragequit | Prove membership in an approved set of deposits | Closed list operator; 13-day revocation; withdraw delays | [docs](https://docs.privacypools.com/), [L2BEAT](https://l2beat.com/privacy/projects/privacy-pools) |
| Tornado Cash | Compliance tool | Prove a withdrawal's deposit | The proof note could also spend the funds | [docs history](https://git.hackliberty.org/TornadoCash/docs/commit/6d8785da0395c877a464a3b1c3a50d653596dcf9) |
| Aleo | Per-transaction view keys | Disclose one transaction | Key hash on chain | [Aleo](https://aleo.org/post/aleo-view-key-compliance/) |
| Midnight | Selective disclosure in contracts | Programmable disclosure | Rival pitch: "Zcash can't prove anything" ([X](https://x.com/1Exit_Liquidity/status/2099183711736733890)) | [docs](https://docs.midnight.network/learn) |
| EU rules | MiCA Art. 76(3), AMLR Art. 79 (2027) | Holders and history must be identifiable to the CASP | Unclear whether opt-in disclosure counts | [MiCA Art. 76](https://www.springlex.eu/de/packages/mica/mica-regulation/article-76/) |

The pattern across chains: payment proofs exist where privacy is default (Monero, Lightning),
and **provenance** proofs (Railgun, Privacy Pools) exist where exchanges and regulators push
back. Zcash had neither for its shielded pools. Railgun and Privacy Pools need new circuits and a
list operator. Zcash can do the positive version, "these funds came from *that* transaction",
with the Orchard circuit it already has, no list operator, and no waiting period.

## 3. What we built: proofs of where the money came from

`receipts create --prove-source` (and `zcash-devtool wallet receipt --prove-source`) adds, for
each spent note, a proof that it was created by output `k` of an earlier transaction `S`. With
`--reveal-source-value` the proof also shows the note's exact value. The verifier fetches `S`,
reads its public transparent inputs, and reports who funded it in the clear.

The typical case is B4: a user withdraws from an exchange to a transparent address, shields it,
and later deposits shielded ZEC at another exchange. The receipt shows the deposit spent a note
created by that shielding transaction, which was funded by that withdrawal, and nothing else
about the wallet.

```
receipts verify @deposit.txt
  source    action 1 spent the note created by tx 5093e033… action 0 (height 530)
            that tx was funded in the clear: 0.30000000 ZEC from tmRyMkJH…
            it moved 0.29985000 ZEC from transparent into the shielded pool
  paid      0.12000000 ZEC to uregtest1vj3g…   memo: Deposit 99
```

How it works (details in [SPEC.md](SPEC.md#source-of-funds-version-4), argument in
[CLAIM.md](CLAIM.md)): a third Orchard Action proof, under the same randomized key as the spend
disclosure, spends the same note against a one-leaf tree whose leaf is the source output's
commitment, which the verifier reads from `S`. Orchard nullifiers don't depend on the note's
position, so the one-leaf tree is a sound stand-in. The circuit only checks the tree when the
value is non-zero, so the verifier fixes the value commitment itself (as the sender-address
fix did): `ValueCommit_0(1)` with the value hidden, or `ValueCommit_0(v)` with the proof's
zero-value output opened, so `v` is exact. No new circuit, no trusted list, no waiting period.

### Evidence

| Check | Result |
|---|---|
| Unit and adversarial tests (`crates/receipts-core/tests/roundtrip.rs`) | Orchard and Ironwood round trips, hidden and revealed; a wrong source output, an unrelated output, a lie about the value (lower or higher), a hidden proof relabelled as revealed, a proof borrowed from another receipt, a dropped or edited claim: all refused. `a_zero_value_note_cannot_claim_any_source` builds a real forgery that satisfies the circuit and shows the fixed value commitment is what stops it |
| Independent verifier (`spec-verifier`, Python, written from the spec) | Decodes v4 and checks everything but the Halo 2 proof; agrees with Rust on 232 signed adversarial cases, including 9 source-proof cases whose public inputs match exactly |
| Real testnet | Receipts for testnet tx `571de6e4…` prove its note came from `2a2bd721…` action 0 (hidden, and with the value 0.125 TAZ revealed); verified against the chain by the CLI and the browser verifier, offline by the Rust, JS and Python tests ([examples/testnet/source](../examples/testnet/source)) |
| Private chain end to end (`scripts/e2e-regtest.sh`, 24/24) | Exchange withdraws 0.3 ZEC to a customer's t-address, the customer shields it and pays a merchant; the receipt proves the source and the verifier reports the withdrawal address and amount; with the value revealed it reports the exact note value ([examples/regtest-source](../examples/regtest-source)) |
| Everywhere a receipt is verified | CLI (online and offline with `--source-raw-tx`), API (`sources`, `checks.source_of_funds`), browser verifier and npm package (`sourceTxs`), devtool wallet command |
| No leak | The wallet builds the proof from its own records and asks no server for `S`; verifiers fetch `S` by txid (documented in [THREAT-MODEL.md](THREAT-MODEL.md) §11) |

## 3b. Outputs without their memo

`receipts create --withhold-memo` (and the devtool's `wallet receipt --withhold-memo`) proves
who was paid and how much but keeps the memo private. Memos carry invoice text, names and
refund addresses that an accountant or a court doesn't need. The receipt opens each output's note
commitment with `(ψ, rcm)` instead of `rseed`, so nothing in it decrypts the memo
([SPEC.md](SPEC.md#outputs-without-their-memo-version-5)). Checked by: Orchard and Ironwood round
trips, edits to value, recipient and opening refused (`opened_outputs_must_open_the_commitment`),
the receipt contains neither an `ock` nor the note's `rseed`, a real testnet receipt
([examples/testnet/memo-withheld](../examples/testnet/memo-withheld)), and the Python verifier
recomputing each commitment independently (232 corpus cases, 270 conformance vectors agree).

## 3c. Incoming receipts: the recipient proves it was paid

`receipts received -w wallet -i key.age --txid <txid>` gives a merchant, freelancer or charity a
`zrcin1…` link that proves it received chosen payments, for an accountant, a tax office or a
lender, without an incoming viewing key. The receipt reveals each output's `esk` (which opens that
output only) and proves, with the same address proof as Sign in with Zcash, that the presenter
controls the receiving address, so the payer can't make one. No nullifier is revealed.

Checked by: Orchard and Ironwood round trips; the payer refused even with the right `esk`;
validly signed wrong outputs, wrong keys and duplicates refused
(`only_the_recipient_can_prove_receipt`); a real testnet incoming receipt for the merchant of
`571de6e4…` ([examples/testnet/incoming](../examples/testnet/incoming)) verified by the CLI, the
API (`/v1/verify` returns an `incoming_verification`), the browser page, the npm package and the
independent Python verifier, which opens the output itself; 19 conformance vectors.

## 3d. Signed payment requests

`receipts request --domain shop.example --amount 0.25 --memo "Order 42"` signs a `zreq1…` request
with the payee address's own key; the shop lists its address at
`https://shop.example/.well-known/zcash-receipts.json`. `receipts pay 'zreq1…'` (and the
verifier page's link checker) refuses an edited request, an expired one, or one for an address the
domain doesn't list, then pays and makes a receipt that signs the request code. This is the
BIP-70-style authentication merchants asked for in zips#611 and #977, with the domain's TLS in place
of X.509 and the payee's spend authority in place of a merchant certificate.

Checked by: `signed_payment_requests` (every field edit refused, a thief's own signed request
refused by the domain check, malformed fields refused), the regtest end to end (shop signs,
tampered and thief requests refused, payer pays, the receipt answers the code with the shop's
memo), a testnet-signed example ([examples/testnet/request](../examples/testnet/request)) checked
by the Python verifier, and the page's link checker.

## 3e. Multi-hop source of funds

Real wallets move money around before it reaches an exchange. `receipts create --txid <hop>
--txid <payment> --prove-source` makes one batch link; `receipts verify` and the verifier page
follow the proven links from the payment back to where the money entered the shielded pool in
the clear:

```
source of funds (proven hop by hop):
  tx 4366c749c782… action 0 spent a note from tx 884fd9573215… output 0
      tx 884fd9573215… action 0 spent a note from tx 83ff82271d94… output 2
          tx 83ff82271d94… was funded in the clear: 0.50000000 ZEC from tmSMTtfm…
```

Checked by the regtest end to end (withdrawal to a transparent address, shielding, a self-transfer
of 0.45 ZEC, a 0.3 ZEC payment from the moved note; the batch proves every hop;
[examples/regtest-hops](../examples/regtest-hops)).

## 3f. Proof of funds

`receipts reserve -w wallet -i key.age --at-least 0.05 -m "challenge:<nonce>"` proves the wallet
holds at least that much in unspent shielded notes, for an OTC counterparty, an escrow, a lender
or a treasury report, with no viewing key. Each note is proven against the pool's real tree root
at a recent block with its exact value; the verifier downloads every nullifier the pool has
published since it activated and checks none is the proof's, so the funds are unspent as of the
tip. For Ironwood (where all new funds go) that is a few hundred thousand blocks: 45 seconds the
first time on testnet over a public lightwalletd, 2.5 seconds after (cached against a block hash).
Downloading everything tells the server nothing about which notes are checked.

The price, stated on every report: the verifier learns the notes' nullifiers, so it can see when
they are spent later. That is how "unspent" is checked at all (Monero's reserve proofs pay the
same); a holder chooses whom to give one to.

Checked by: `proof_of_funds` (values can't be overstated or understated even when re-signed by
the holder, duplicates, another key, a zero-value note and a wrong root refused), a real testnet
proof ([examples/testnet/reserve](../examples/testnet/reserve)) verified against the chain and
by the independent Python verifier, and the regtest end to end, where the same proof is refused
once the holder spends one of its notes.

## 3g. Deposit desks: shielded deposits an exchange can accept

The point of source-of-funds proofs is that an exchange can switch them on. A request created with
`"source_of_funds": {"required": true, "blocked_addresses": [...]}` (API, or a checkbox on the
dashboard) only accepts a receipt that proves where every spent note came from; `receipts pay`
adds the proof by itself when the request asks. The desk's server then screens the transparent
addresses that funded the money into the shielded pool against the exchange's own list:

- all clear: the deposit is credited, with a provenance record (funding addresses, amounts,
  source transactions) kept on the request;
- a listed address, or funding the payer didn't show: `held_for_review`
  (`request.held_for_review` webhook); the desk accepts or rejects it
  (`POST /v1/requests/{id}/review`), and a rejected deposit is refunded to the address the payer
  signed into the receipt.

The exchange learns the link and the funding addresses, what it would learn from a transparent
deposit, and nothing else about the customer's wallet. The customer stays shielded.

Checked by: the regtest end to end (a trader withdraws to a transparent address and shields; a
receipt without proof of source is refused with `source_of_funds_required`; with it, the deposit
is credited and the funding address recorded; against a list holding that address, `receipts pay`
attaches the proof on its own and the deposit is held; the desk rejects it and the refund goes to
the trader's signed address; webhook events recorded) and `api.rs::deposit_desk_policy` (policy
validation, the public view never shows the list, review only for held deposits).

## 4. Considered and not built (yet)

| Idea | Pain | Why not now |
|---|---|---|
| Prove an amount bracket ("at least X") without the exact amount | A9, X: [Pli](https://x.com/ZecPli/status/2102083749819334736) | Needs a range proof circuit; out of scope for a no-new-circuit design |
