..
  Proposed text for ZIP 311 (Zcash Payment Disclosures): Orchard and Ironwood.
  Local draft. Not submitted.

  Base: zcash/zips zips/zip-0311.rst (Draft). The ZIP preamble block is ZIP 311's own and is
  unchanged. Each section below is marked with where it goes in zip-0311.rst:

  - "Terminology": NEW, before "Abstract" (ZIP 311 uses MUST but has no BCP 14 section).
  - "Conventions" (additions): APPEND to the existing "Conventions" section.
  - "Orchard and Ironwood payment disclosures": REPLACES the line
    "TODO: Add support for Orchard." under "Specification / Payment disclosure data
    structure". It also defines versioning and encodings for Orchard and Ironwood
    disclosures only; the two encoding/versioning TODOs remain for Sapling and transparent
    inputs.
  - "Creating an Orchard or Ironwood payment disclosure" and "Verifying an Orchard or
    Ironwood payment disclosure": NEW subsections of "Specification", after "Verifying a
    payment disclosure".
  - "Rationale" (additions) and "Security and Privacy Considerations" (additions): APPEND to
    the existing sections.
  - "Relationship to zcash/zips#1406": NEW, for review; to be removed or folded in once the
    two texts are reconciled.
  - "Reference implementation": REPLACES "TBD".
  - "References" (additions): APPEND to the existing list.
  - "Appendix: Other signing domains (non-normative)": NEW, after "References".


Terminology
===========

The key words "MUST", "MUST NOT", "SHOULD", and "MAY" in this document are to be interpreted
as described in BCP 14 [#BCP14]_ when, and only when, they appear in all capitals.


Conventions (additions)
=======================

The following are used as defined in the Zcash protocol specification [#protocol]_:
$\mathsf{ValueCommit}$, $\mathsf{PRF^{ockOrchard}}$ [#protocol-concreteprfs]_,
$\mathsf{SpendAuthSig}$ (including $\mathsf{RandomizePublic}$, $\mathsf{RandomizePrivate}$ and
$\mathsf{Validate}$) [#protocol-concretespendauthsig]_, $\mathsf{DiversifyHash}$
[#protocol-concretediversifyhash]_, and the Action statement [#protocol-actionstatement]_.

- *Pool*: Orchard (``0``) or Ironwood (``1``). Ironwood uses the Orchard protocol, circuit and
  keys, with note-plaintext lead byte ``0x03``. [#zip-2005]_

- *Payment bundle*: the transaction's bundle of the disclosure's spend pool. *Output bundle*:
  the transaction's bundle of the disclosure's output pool (the same bundle unless the
  disclosure is cross-pool, version 3).

- $coinType$: the SLIP-44 coin type [#slip-0044]_, 133 on Mainnet and 1 on Testnet and
  Regtest.

- $\mathsf{I2LEOSP}_{\ell}(k)$: the $\ell$-bit little-endian encoding of the integer $k$.


Specification
=============

Orchard and Ironwood payment disclosures
----------------------------------------

An Orchard or Ironwood payment disclosure proves spend authority for one or more Actions of
the payment bundle, and discloses zero or more outputs of the output bundle. It has the
following fields:

- $\mathsf{txid}$: the transaction id of the transaction $\mathsf{tx}$ being disclosed.

- $\mathsf{msg}$: a message, which MAY carry a verifier's challenge as the line
  ``challenge:<hex>``. The challenge is read from the first line of $\mathsf{msg}$ (lines end
  at LF; a trailing CR is ignored) that starts with ``challenge:``: it is the rest of that line
  if that is 6 to 64 lowercase hexadecimal digits, and otherwise there is none. A request's
  challenge matches only if equal.

- $\mathsf{pool}$: the spend pool; $\mathsf{outputPool}$: the output pool.

- $\mathsf{outputs}$: a sequence of $(\mathsf{index}, \mathsf{ock})$, where
  $\mathsf{index}$ is an index into the Actions of the output bundle and $\mathsf{ock}$ is the
  outgoing cipher key for the output of that Action. It MAY be empty.

- $\mathsf{spends}$: a sequence of
  $(\mathsf{index}, \mathsf{cvNet}, \mathsf{rk}, \mathsf{cmx}, \mathsf{proof},
  \mathsf{spendAuthSig})$, where $\mathsf{index}$ is an index into the Actions of the payment
  bundle. It MUST NOT be empty.

Encoding
~~~~~~~~

::

  unsigned := "ZRCT" | version:u8 | coinType:u32le | pool:u8 | [outputPool:u8 if version = 3]
              | txid[32] | msgLen:u16le | msg
              | nOutputs:u8 | { index:u32le | ock[32] }^nOutputs
              | nSpends:u8  | { index:u32le | cvNet[32] | rk[32] | cmx[32] | proofLen:u32le | proof
                              | [addrFlag:u8 = 0 if version ∈ {2, 3}] }^nSpends
  receipt  := unsigned | { spendAuthSig[64] }^nSpends
  text     := "zip311r1" || base64url without padding (RFC 4648 §5) of receipt

  prepared := unsigned | { alpha[32] }^nSpends
  ptext    := "zip311u1" || base64url without padding of prepared

$\mathsf{txid}$ is in internal byte order (the reverse of the hex that block explorers
show). $\mathsf{version}$ MUST be the lowest that can carry the contents: 3 if
$\mathsf{outputPool} \neq \mathsf{pool}$, else 1. Versions 2, 4 and 5 are reserved for
extensions that this ZIP does not specify. Version 3 keeps one flag byte per spend, which MUST
be 0, so that its spends have the same layout as version 2's; it carries nothing in this ZIP.

A prepared receipt (``zip311u1``) carries a receipt with every proof made but no signature, and
each spend's $\alpha$ (the canonical 32-byte encoding of a Pallas scalar), from the prover to
a separate signer. Its decoder MUST apply rules 1 to 4 below to $\mathsf{unsigned}$, MUST
refuse a non-canonical $\alpha$ and any byte after the last one, and MUST use canonical
base64url as for the text form. It holds $\alpha$, so it MUST NOT be shared beyond the
signer.

A decoder MUST refuse a receipt that:

1. does not start with ``ZRCT``, has an unknown version, or has a version that is not the
   lowest for its contents;
2. has $\mathsf{pool}$ or $\mathsf{outputPool}$ other than 0 or 1, or
   $\mathsf{outputPool} = \mathsf{pool}$ in version 3;
3. has $\mathsf{proofLen} > 65536$, an $\mathsf{addrFlag}$ other than 0, fewer bytes than its
   lengths declare, or any byte after the last signature. ($\mathsf{addrFlag} = 1$
   introduces an address proof, an extension not specified here; a verifier that does not
   implement it, including its fixed $\mathsf{cvNet}$ rule, MUST refuse such receipts.);
4. does not re-encode to exactly its own bytes. Every receipt therefore has one encoding, and
   the signatures cover exactly those bytes.

The text form MUST be canonical base64url: a decoder MUST refuse padding, characters outside
the URL-safe alphabet, and non-zero trailing bits.

Signing digest
~~~~~~~~~~~~~~

::

  personalization := "ZIP311Signed" || I2LEOSP_32(coinType)        (16 bytes)
  digest          := BLAKE2b-256(personalization, unsigned)

This is the digest ZIP 311 already specifies for Sapling spends, applied to the encoding
above.

Creating an Orchard or Ironwood payment disclosure
--------------------------------------------------

For each output to disclose, at index $j$ of the output bundle, created with outgoing viewing
key $\mathsf{ovk}$:
$\mathsf{ock}_j := \mathsf{PRF^{ockOrchard}_{ovk}}(\mathsf{cv\_net}_j, \mathsf{cmx}_j,
\mathsf{ephemeralKey}_j)$ [#protocol-saplingencrypt]_.

For each spend to disclose, at index $i$ of the payment bundle, spending note $n$ with
spending key $\mathsf{sk}$ ($\mathsf{ask}$, $\mathsf{ak}$) and Merkle path $\mathsf{path}$ to
the payment bundle's anchor $\mathsf{rt}$:

1. Build an Orchard Action whose spend is $n$ with $\mathsf{path}$ against $\mathsf{rt}$ (so
   its nullifier is the transaction's $\mathsf{nf}_i$), and whose output is a zero-value
   dummy note with $\rho = \mathsf{nf}_i$.
2. Sample fresh $\alpha$ and $\mathsf{rcv}$.
   $\mathsf{rk} := \mathsf{SpendAuthSig.RandomizePublic}(\alpha, \mathsf{ak})$,
   $\mathsf{cvNet} := \mathsf{ValueCommit}_{\mathsf{rcv}}(\mathsf{v}(n) - 0)$, and
   $\mathsf{cmx}$ := the dummy note's $x(\mathsf{cm})$.
3. Prove the Action statement under the post-NU6.3 Orchard circuit, whatever the payment's
   height, with public inputs $(\mathsf{rt}, \mathsf{cvNet}, \mathsf{nf}_i, \mathsf{rk},
   \mathsf{cmx}, \mathsf{enableSpends} = 1, \mathsf{enableOutputs} = 1,
   \mathsf{enableCrossAddress} = 1)$. Earlier circuit versions MUST NOT be used: the pre-NU6.2
   circuit is unsound.
4. After all spends are proven and $unsigned$ is encoded, sign $digest$ with
   $\mathsf{rsk} := \mathsf{SpendAuthSig.RandomizePrivate}(\alpha, \mathsf{ask})$, one
   signature per spend, in spend order.

A receipt MUST disclose at least one spend. It MAY disclose zero outputs.

Verifying an Orchard or Ironwood payment disclosure
---------------------------------------------------

The inputs are the receipt; the transaction $T$ with id $\mathsf{txid}^*$, fetched or
supplied; and the expected network.

1. Decode the receipt (all rules above). Check that $\mathsf{txid} = \mathsf{txid}^*$, that
   $T$'s txid as computed by ZIP 244 [#zip-0244]_ (or ZIP 229 [#zip-0229]_ for version 6
   transactions) is $\mathsf{txid}^*$, and that $coinType$ is the expected network's.
2. Let $B$ be $T$'s bundle of $\mathsf{pool}$, and $B'$ its bundle of $\mathsf{outputPool}$
   (or $B$ for version 1). Both MUST exist.
3. $\mathsf{nSpends} \geq 1$, and the number of signatures MUST equal $\mathsf{nSpends}$.
4. Every spend and output index MUST be within its bundle's action count, and no index MAY
   appear twice among the spends or among the outputs.
5. For each spend $(i, \mathsf{cvNet}, \mathsf{rk}, \mathsf{cmx}, \mathsf{proof})$ with
   signature $\sigma$:

   1. $\mathsf{rk}$, $\mathsf{cvNet}$ and $\mathsf{cmx}$ MUST be canonical encodings
      ($\mathsf{rk}$ and $\mathsf{cvNet}$ of Pallas points, $\mathsf{cmx}$ of a Pallas base
      field element), and $\mathsf{rk}$ MUST NOT be the identity.
   2. $\mathsf{SpendAuthSig.Validate}(\mathsf{rk}, digest, \sigma)$ MUST hold.
   3. The proof MUST verify for the post-NU6.3 Action circuit with public inputs
      $(\mathsf{rt}(B), \mathsf{cvNet}, \mathsf{nf}(B.\mathsf{actions}[i]), \mathsf{rk},
      \mathsf{cmx}, 1, 1, 1)$. The verifier MUST take the anchor and the nullifier from $T$,
      never from the receipt.

6. For each output $(j, \mathsf{ock})$: run Orchard output recovery with $\mathsf{ock}$ on
   $B'.\mathsf{actions}[j]$ [#protocol-saplingdecryptovk]_ (the $\mathsf{ock}$ path, with the
   pool's lead byte and the rules of ZIP 212 [#zip-0212]_). It MUST succeed, and the
   recomputed note commitment MUST equal $\mathsf{cmx}(B'.\mathsf{actions}[j])$. Report the
   address $(\mathsf{d}, \mathsf{pk_d})$, the value and the memo.
7. The receipt is valid for $T$. Whether $T$ was mined, and how deep, is established
   separately from the chain; a verifier SHOULD report the source it used and the number of
   confirmations. A verifier that issued a challenge MUST check that $\mathsf{msg}$ carries
   it.

Note (non-normative): for lead byte ``0x03``, recovery derives $\mathsf{rcm}$ as specified
for Ironwood notes by ZIP 2005 [#zip-2005]_. A version of the recovery procedure that derives
$\mathsf{rcm}$ from $[5] \| \rho$ for every lead byte other than ``0x01`` fails to open
Ironwood outputs.


Rationale (additions)
=====================

Same anchor, same nullifier. As for Sapling, re-proving against the transaction's own anchor
costs nothing in privacy: the original spend already fixed the note's anonymity set. Taking
$\mathsf{rt}$ and $\mathsf{nf}$ from $T$ binds the proof to the payment. Soundness of spend
authority rests on the nullifier rather than the anchor: a witness for a different note with
the same $\mathsf{nf}_i$ would break the requirement that distinct note commitments do not
share a nullifier. This matters for version 6 transactions, whose txid does not commit to
the anchors [#zip-0229]_; a receipt checked against a re-anchored copy of $T$ fails to
verify rather than verifying wrongly.

Fresh $\alpha$ and $\mathsf{rcv}$. $\mathsf{rk}$ and $\mathsf{cvNet}$ are unlinkable to the
transaction's, and to those of any other disclosure of the same spend, so the receipt reveals
no more about the spent note than the transaction did. $\mathsf{cvNet}$ is chosen by the
prover: the spend proof only has to show knowledge of the note behind $\mathsf{nf}_i$, and
the spent value is not a claim of the disclosure.

Both flags enabled. The spend-authority argument does not depend on the output half; the
dummy output lets an unmodified wallet builder make the proof. The proof is never checked
by consensus, so ``enableCrossAddress = 1`` is allowed even for Orchard-pool spends after NU6.3,
whose consensus actions must set it to 0 (ZIP 258); verifiers use the receipt's own flags.
Spends-only proofs (which also force $\mathsf{v^{new}} = 0$) are an equally sound choice. A
verifier passes exactly the flags this ZIP fixes, so the two are not interchangeable within a
version.

One circuit. The disclosure proof is a new statement about an old note and is never verified
by consensus, so it uses the post-NU6.3 circuit for every payment, including Orchard
transactions mined before NU6.3. No new circuit or setup is needed.

One digest for all spends. Every signature covers every byte of $unsigned$, so receipts
cannot be merged, split or edited. Proof bytes are inside the signed message, so
re-randomizing a Halo 2 proof (which anyone can do) breaks every signature.

Canonical encoding, base64url text. One receipt, one encoding, which the signatures depend on.
The ``ZRCT`` magic and the personalization keep the digest apart from transaction digests.
Bech32m's 90-character checksum range does not cover a receipt of about 5 KB, and a corrupted
receipt fails its signature check anyway. A receipt with one spend and one output is about
5.2 KB (7 KB as text).

Index uniqueness and range imply the sequence-length checks of the Sapling procedure, so only
uniqueness and range are stated.


Security and Privacy Considerations (additions)
===============================================

Bearer proof. Anyone holding a receipt can show it. A verifier that needs to know a receipt
was made for it issues a challenge, which the sender places in $\mathsf{msg}$ as
``challenge:<hex>``. A challenge SHOULD carry at least 64 random bits (16 hex digits): the
6-digit minimum exists for codes a person reads aloud, which a verifier MUST then use only once
and only briefly. A verifier SHOULD also require the payment to be mined after it issued the
challenge, so that an old payment cannot answer a new request.

Chosen outputs. The sender chooses which outputs to disclose; a change output, or a payment to
itself, discloses like any other. A verifier binds a receipt to a payee by checking the
recipient it expects.

Inclusion. A receipt does not show that $T$ was mined; that rests on the chain source. A
verifier SHOULD fetch by block (or from its own node) so that the server does not learn the
txid, and MAY cross-check a second server.

Separate signers. A signer that holds $\mathsf{ask}$ apart from the prover (for example a
hardware wallet) MUST be given the unsigned receipt and each spend's $\alpha$, MUST compute
$digest$ itself with the ``ZIP311Signed`` personalization, MUST check each spend's
$\mathsf{rk} = \mathsf{SpendAuthSig.RandomizePublic}(\alpha, \mathsf{ak})$, and SHOULD display
the txid, the disclosed outputs and $\mathsf{msg}$ before signing. It MUST NOT sign a digest
supplied by the host: that could be a transaction's sighash, and the signature would authorize
a real spend. The proofs need only the full viewing key, so a watch-only wallet can prepare a
receipt for such a signer. The randomizers MUST stay between the prover and the signer and be
discarded once signing is done: with a finished receipt, $\alpha$ gives
$\mathsf{ak} = \mathsf{rk} - [\alpha]\,\mathcal{G}$, which would link every receipt the wallet
signs. The proofs don't cover $\mathsf{msg}$, so a signer MAY sign one prepared receipt for more
than one message; those receipts share each $\mathsf{rk}$, so whoever holds two of them can tell
they disclose the same spends.

Whose spend authority. Spend authority is proven for the signer's spend authorizing key. In a
transaction several parties built (a PCZT), it is whoever holds that $\mathsf{ask}$ and knew
each $\mathsf{ock}$.

Dummy spends. An honest wallet does not keep the keys of its dummy spends. A transaction
builder that keeps a dummy's key, and discloses outputs with its own $\mathsf{ovk}$, can make
a receipt for that dummy: it proves control of a spend that moved no value. Spend authority
therefore shows that the signer took part in building the transaction, not how much it paid
in.

Unlinkability of later spends. Disclosing a note's plaintext does not let the verifier
recognise its later spend: Orchard nullifiers depend on $\mathsf{nk}$, which stays with the
recipient.

Circuit version. The pre-NU6.2 Orchard circuit is unsound; a disclosure proof made or
accepted under it would not establish spend authority.

Identity $\mathsf{rk}$. Rejecting the identity $\mathsf{rk}$ matches the corresponding rule
for Action descriptions; an identity key would let anyone sign.


Relationship to zcash/zips#1406
===============================

What #1406 specifies. The open draft PR zcash/zips#1406 ("ZIP 311: add Orchard and Ironwood
output disclosures") fills ZIP 311's Orchard TODO for outputs only. It adds
$\mathsf{orchardOutputs}$ and $\mathsf{ironwoodOutputs}$ to the payment disclosure data
structure, each a sequence of (Action index, $\mathsf{ock}$) with the same length, uniqueness
and range checks as $\mathsf{saplingOutputs}$; derives $\mathsf{ock}$ with
$\mathsf{PRF^{ockOrchard}}$ from the Action's $\mathsf{cv}$, $\mathsf{cmx}$ and
$\mathsf{ephemeralKey}$; recovers outputs with the procedure of protocol §4.20.3, using its
NU6.3 version (with the ZIP 2005 changes) for Ironwood; and treats
$\mathsf{tx.vActionsOrchard}$ and $\mathsf{tx.vActionsIronwood}$ as empty for transaction
versions that lack them. Its rationale covers $\mathsf{ovk} = \bot$, the separate per-pool
lists, and the reduced use of Orchard output disclosures after NU6.3. It leaves Orchard and
Ironwood spend authority as a TODO, stating that until then Orchard or Ironwood outputs can be
disclosed only in a transaction that also has a transparent input or a Sapling spend. It
leaves the versioning and encoding TODOs open.

Where the two agree. Both derive $\mathsf{ock}$ the same way, recover outputs with the same
$\mathsf{ock}$ path of §4.20.3, use the ZIP 2005 $\mathsf{rcm}$ derivation for Ironwood, check
output indices for range and uniqueness per pool, and keep ZIP 311's semantics for
$\mathsf{ovk} = \bot$ (such an output cannot be disclosed). An output disclosed under either
text opens to the same note and memo.

Where they differ.

- Spend authority. This text adds Orchard and Ironwood spend authority (a fresh Action proof
  against the transaction's anchor and nullifier, and a $\mathsf{SpendAuthSig}$ by the fresh
  $\mathsf{rk}$ over the ZIP 311 digest). With it, a disclosure of Orchard or Ironwood outputs
  no longer needs a Sapling spend or transparent input.
- Structure. #1406 extends ZIP 311's abstract data structure with two output lists that sit
  beside the Sapling and transparent fields. This text defines a self-contained disclosure
  whose spends are in one pool and whose outputs are in that pool or, in version 3, the other
  one; it has no Sapling or transparent fields, and discloses outputs from one pool per
  receipt.
- Encoding and versioning. #1406 leaves them as TODOs. This text defines a binary encoding, a
  version byte, strict canonical decoding and a text form.
- Recovery inputs. #1406 runs recovery with the block height, transaction version and pool.
  This text selects the lead byte from the pool and does not take a height.

Mapping onto #1406. With both texts, ZIP 311's payment disclosure has the following fields in
addition to its Sapling and transparent ones:

- $\mathsf{orchardOutputs}$ and $\mathsf{ironwoodOutputs}$, as #1406 specifies them;
- $\mathsf{orchardSpends}$ and $\mathsf{ironwoodSpends}$, each a sequence of
  $(\mathsf{index}, \mathsf{cvNet}, \mathsf{rk}, \mathsf{cmx}, \mathsf{proof},
  \mathsf{spendAuthSig})$ for Actions of that pool's bundle, created and verified as this ZIP
  specifies for $\mathsf{spends}$ with $\mathsf{pool}$ set to that pool.

An index MUST NOT appear twice in one list. ZIP 311's rule that a disclosure proves at least
one input MUST count entries of $\mathsf{orchardSpends}$ and $\mathsf{ironwoodSpends}$, and
#1406's restriction that Orchard or Ironwood outputs need a Sapling spend or transparent input
is then lifted. A disclosure whose spends are all in one Orchard-family pool and whose outputs
are all in one Orchard-family pool MAY be encoded as this ZIP's ``zip311r1`` profile: its
$\mathsf{spends}$ are the $\mathsf{orchardSpends}$ or $\mathsf{ironwoodSpends}$ selected by
$\mathsf{pool}$, and its $\mathsf{outputs}$ are the $\mathsf{orchardOutputs}$ or
$\mathsf{ironwoodOutputs}$ selected by $\mathsf{outputPool}$ (or $\mathsf{pool}$ in
version 1). Any other disclosure needs ZIP 311's general encoding, which remains a TODO.

Reference implementation
========================

The Zceipt repository implements this text. Paths are relative to its root.

- ``crates/zceipt-core`` (Rust): creation (``create_cross``), preparation with a full viewing
  key (``prepare``), the separate-signer checks (``sign_prepared``), verification
  (``verify_cross``, which takes the anchor and nullifier from the transaction), output recovery
  (``recover_with_ock``) and the circuit choice (``RECEIPT_CIRCUIT``) in ``src/lib.rs``; the
  encoding and text form in ``src/encoding.rs``. It builds on ``orchard`` 0.16.0 with a patch
  in ``vendor/``.
- ``spec-verifier/`` (Python): an independent verifier written from this text. It checks every
  rule except the Halo 2 proof, and reports for each proof the public inputs it must verify
  against.
- ``conformance/vectors.json``: 278 cases from real Orchard, Ironwood and cross-pool receipts,
  each with the answer a correct verifier gives.
- Tests in ``crates/zceipt-core/tests``: ``roundtrip.rs`` (``orchard_receipt_roundtrip``,
  ``ironwood_receipt_roundtrip``, ``only_the_spender_can_create``, ``tampering_is_rejected``,
  ``every_byte_matters``, ``encodings_are_canonical``,
  ``disclosures_are_unlinkable_to_the_action_and_to_each_other``,
  ``prepare_with_viewing_key_then_sign_elsewhere``) and ``properties.rs``
  (``encoding_is_a_bijection``, ``only_canonical_encodings_decode``,
  ``all_signing_domains_are_distinct``).

The construction has not been reviewed by anyone other than its author.


References (additions)
======================

.. [#BCP14] `Information on BCP 14 — "RFC 2119: Key words for use in RFCs to Indicate Requirement Levels" and "RFC 8174: Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words" <https://www.rfc-editor.org/info/bcp14>`_
.. [#protocol-concreteprfs] `Zcash Protocol Specification, Version 2025.6.1 [NU6.1]. Pseudo Random Functions <protocol/protocol.pdf#concreteprfs>`_
.. [#protocol-actionstatement] `Zcash Protocol Specification, Version 2025.6.1 [NU6.1]. Action Statement (Orchard) <protocol/protocol.pdf#actionstatement>`_
.. [#zip-0212] `ZIP 212: Allow Recipient to Derive Ephemeral Secret from Note Plaintext <zip-0212.rst>`_
.. [#zip-0229] `ZIP 229: Version 6 Transaction Format <zip-0229.md>`_
.. [#zip-0244] `ZIP 244: Transaction Identifier Non-Malleability <zip-0244.rst>`_
.. [#zip-2005] `ZIP 2005: Ironwood Quantum Recoverability <zip-2005.md>`_

ZIP 311's existing entries [#protocol]_, [#protocol-saplingencrypt]_,
[#protocol-saplingdecryptovk]_, [#protocol-concretediversifyhash]_,
[#protocol-concretespendauthsig]_, [#RFC4648]_ (cited for the text form) and [#slip-0044]_ are used as they stand; #1406
updates the section titles and anchors of the two §4.20 entries.


Appendix: Other signing domains (non-normative)
===============================================

This ZIP specifies one signing personalization, ``ZIP311Signed``. The Zceipt implementation
defines further signed formats with their own BLAKE2b personalizations (12 bytes, then
$coinType$ as 4 bytes little-endian), so that no signature made for one verifies as another or
as a transaction. They are outside ZIP 311's scope, are not registered names, and are listed
only so that implementers can avoid collisions:

====================================== ================== ==================================
Format                                 Personalization    Signed by
====================================== ================== ==================================
Incoming receipt (``zrcin1``)          ``ZIP311Incomg``   a fresh $\mathsf{rk}$ of the recipient
Sign in with Zcash (``zsig1``)         ``ZcashSignIn\0``  a fresh $\mathsf{rk}$
Payment request (``zreq1``)            ``ZIP321Signed``   a fresh $\mathsf{rk}$ of the payee
Proof of funds (``zrsv1``)             ``ZcashReserve``   a fresh $\mathsf{rk}$ per note
====================================== ================== ==================================

``ZIP321Signed`` is not defined by ZIP 321.
