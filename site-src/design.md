# Zceipt design

## Who it is for
Zecathon judges (Zcash engineers) first, then shops, exchanges and wallet developers. They
give the page ten seconds. In that time they must see the idea: one payment comes out of a
sealed wallet, nothing else does.

## Story (landing, scroll-driven, one 3D object)
The wallet is a deck of payment cards.
0. **Hero.** The deck floats, every face sealed. "Prove one payment. Reveal nothing else."
1. **Sealed.** The deck fans out: every card is ciphertext. That is Zcash working.
2. **Exposed.** Someone asks for proof. A viewing key turns every card face up: rent, clinic,
   salary, balance, and blank cards for payments not made yet. Flare red.
3. **One card.** The deck reseals. One card slides out. Only recipient, amount and memo show.
4. **Proven.** A proof seal lands on the card: signed by the key that spent the money.
After the story: a real receipt verified in the tab, a disclosure builder, the proof family
as a bento of small diagrams, the developer code, the close.

## Visual language
Light, porcelain, Apple-calm. Paper is the metaphor (a receipt), so the canvas is light and the
sealed parts are dark graphite: you can see what is hidden.

| Token | Value | Use |
|---|---|---|
| `--bg` | `#F4F4F6` | canvas |
| `--surface` | `#FFFFFF` | cards, islands |
| `--ink` | `#111114` | text, sealed bars |
| `--ink-2` | `#6B6B74` | secondary text |
| `--ink-3` | `#A3A3AD` | tertiary |
| `--line` | `rgba(17,17,20,.08)` | hairlines |
| `--iris` | `#5B3DF5` | revealed by choice, verified. Never a general CTA colour |
| `--azure` | `#2FA8FF` | second stop of the iris gradient only |
| `--flare` | `#FF4D2E` | exposed against your will (viewing key) only |
| `--bad` | `#E5484D` | invalid receipts |

Discipline: about 80% neutral, 15% ink, 5% iris. CTAs are ink (black pill). Iris appears only
where something is proven or chosen to be shown. Flare appears only in the viewing-key beat.

Type: the system stack (SF Pro on Apple), so the verifier's CSP needs no font host.
Display 600, tracking -0.045em. Mono (`ui-monospace`) only for keys, txids and receipt text.

Shape: radius 28 (islands), 20 (cards), 12 (inputs), 999 (pills). Elevation is one soft shadow
`0 1px 0 rgba(255,255,255,.8) inset, 0 20px 50px -24px rgba(17,17,20,.18)`.
Motion: 600–900 ms, `cubic-bezier(.2,.8,.2,1)`; scroll scenes scrub, never autoplay;
`prefers-reduced-motion` jumps to end states.

## Components
- **Island nav:** floating pill, centred, frosted white, 56 px, logo left, links, ink CTA.
- **Redaction bar:** graphite rounded bar with faint ciphertext; the sealed state of any field.
- **Field chip:** iris dot + label = shown; graphite bar = sealed.
- **Proof seal:** iris ring with a check, stamped once.
- **Island card:** white, radius 28, hairline, soft shadow.

## Dashboard
A floating sidebar island and a top island on the grey canvas. The request list is a grid of
receipt cards with a disclosure strip (iris dots for what was shown, graphite for sealed).
Overview islands: money received (ink card), proved ring, 14-day bars, disclosure matrix.
