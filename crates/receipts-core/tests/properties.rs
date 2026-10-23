//! Property tests for the receipt format's invariants, over thousands of random receipts
//! (seeded, so failures reproduce; no extra dependencies).
//!
//! 1. Encoding is a bijection: every structurally valid receipt round-trips, re-encoding is
//!    byte-identical, relabelling the version byte never decodes to the same receipt, and no
//!    mutated byte string decodes unless it is itself the canonical encoding of what it decodes to.
//! 2. The signing digest covers every field: changing any one field changes the digest.
//! 3. Domain separation: the receipt digest is BLAKE2b under the "ZIP311Signed" personalization
//!    of its own network, which differs from the sign-in personalization and from the other
//!    network's (so the same bytes hash differently in each domain).

use receipts_core::{signing_digest, AddressProof, OpenedOutput, OutputDisclosure, Pool, Receipt, SourceProof, SourceValue, SpendDisclosure, UnsignedReceipt};

struct Rng(u64);
impl Rng {
    fn u64(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.u64() % n
    }
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        b.iter_mut().for_each(|x| *x = self.u64() as u8);
        b
    }
    fn vec(&mut self, max: u64) -> Vec<u8> {
        (0..self.below(max)).map(|_| self.u64() as u8).collect()
    }
}

fn random_receipt(r: &mut Rng) -> Receipt {
    let pool = if r.below(2) == 0 { Pool::Orchard } else { Pool::Ironwood };
    let output_pool = match r.below(3) {
        0 => Some(if pool == Pool::Orchard { Pool::Ironwood } else { Pool::Orchard }),
        _ => None,
    };
    let with_addr = r.below(3) == 0;
    let with_source = r.below(3) == 0;
    let n_sp = 1 + r.below(3) as usize;
    let spends: Vec<SpendDisclosure> = (0..n_sp)
        .map(|i| SpendDisclosure {
            index: r.below(100) as u32,
            cv_net: r.bytes(),
            rk: r.bytes(),
            cmx: r.bytes(),
            proof: r.vec(300),
            // At least one address proof when "with_addr", so v2 is canonical.
            address: (with_addr && (i == 0 || r.below(2) == 0)).then(|| AddressProof {
                address: r.bytes(),
                rho: r.bytes(),
                rseed: r.bytes(),
                nf: r.bytes(),
                cv_net: r.bytes(),
                cmx: r.bytes(),
                proof: r.vec(300),
            }),
            // At least one source proof when "with_source", so v4 is canonical.
            source: (with_source && (i == 0 || r.below(2) == 0)).then(|| SourceProof {
                txid: r.bytes(),
                index: r.below(100) as u32,
                value: if r.below(2) == 0 {
                    SourceValue::Hidden { cmx: r.bytes() }
                } else {
                    SourceValue::Revealed { value: 1 + r.below(1_000_000), address: r.bytes(), rseed: r.bytes() }
                },
                proof: r.vec(300),
            }),
        })
        .collect();
    let unsigned = UnsignedReceipt {
        coin_type: if r.below(2) == 0 { 1 } else { 133 },
        pool,
        output_pool,
        txid: r.bytes(),
        msg: r.vec(200),
        outputs: (0..r.below(4)).map(|_| OutputDisclosure { index: r.below(100) as u32, ock: r.bytes() }).collect(),
        // Opened outputs only in some receipts, so v5 is exercised and every other version too.
        opened: if r.below(3) == 0 {
            (0..1 + r.below(3))
                .map(|_| OpenedOutput { index: r.below(100) as u32, address: r.bytes(), value: r.u64(), psi: r.bytes(), rcm: r.bytes() })
                .collect()
        } else {
            vec![]
        },
        spends,
    };
    let sigs = (0..n_sp).map(|_| r.bytes::<64>()).collect();
    Receipt { unsigned, spend_auth_sigs: sigs }
}

#[test]
fn encoding_is_a_bijection() {
    let mut r = Rng(0x5eed_0001);
    for _ in 0..3000 {
        let rc = random_receipt(&mut r);
        let b = rc.to_bytes();
        let back = Receipt::from_bytes(&b).expect("a structurally valid receipt decodes");
        assert_eq!(back, rc);
        assert_eq!(back.to_bytes(), b, "re-encoding is byte-identical");
        assert_eq!(Receipt::from_text(&rc.to_text()).unwrap(), rc);
        for v in 0u8..=5 {
            if v == b[4] {
                continue;
            }
            let mut m = b.clone();
            m[4] = v;
            if let Ok(other) = Receipt::from_bytes(&m) {
                assert_ne!(other, rc, "version {v} relabelled to the same receipt");
            }
        }
    }
}

#[test]
fn only_canonical_encodings_decode() {
    // Mutate real encodings at random (flip, insert, delete bytes): whatever still decodes must
    // re-encode to exactly the mutated bytes. A decoder that accepted a non-canonical form (an
    // extra flag value, a v2 with no address proof, a relabelled version) would fail this.
    let mut r = Rng(0x5eed_0004);
    let mut decoded = 0;
    for _ in 0..4000 {
        let mut b = random_receipt(&mut r).to_bytes();
        for _ in 0..1 + r.below(3) {
            let i = r.below(b.len() as u64) as usize;
            match r.below(3) {
                0 => b[i] ^= 1 << r.below(8),
                1 => b.insert(i, r.u64() as u8),
                _ => {
                    b.remove(i);
                }
            }
        }
        if let Ok(rc) = Receipt::from_bytes(&b) {
            decoded += 1;
            assert_eq!(rc.to_bytes(), b, "a non-canonical encoding decoded");
        }
    }
    assert!(decoded > 100, "the mutations should leave many decodable receipts ({decoded})");
}

#[test]
fn the_signing_digest_covers_every_field() {
    let mut r = Rng(0x5eed_0002);
    for _ in 0..1500 {
        let rc = random_receipt(&mut r);
        let base = signing_digest(&rc.unsigned);
        let mut variants: Vec<UnsignedReceipt> = Vec::new();
        let u = &rc.unsigned;
        let mut v = u.clone();
        v.coin_type ^= 1;
        variants.push(v);
        let mut v = u.clone();
        v.pool = if u.pool == Pool::Orchard { Pool::Ironwood } else { Pool::Orchard };
        v.output_pool = v.output_pool.filter(|p| *p != v.pool);
        variants.push(v);
        let mut v = u.clone();
        v.output_pool = match u.output_pool {
            Some(_) => None,
            None => Some(if u.pool == Pool::Orchard { Pool::Ironwood } else { Pool::Orchard }),
        };
        variants.push(v);
        let mut v = u.clone();
        v.txid[r.below(32) as usize] ^= 1 << r.below(8);
        variants.push(v);
        let mut v = u.clone();
        v.msg.push(r.u64() as u8);
        variants.push(v);
        if !u.outputs.is_empty() {
            let mut v = u.clone();
            v.outputs[0].ock[r.below(32) as usize] ^= 1;
            variants.push(v);
            let mut v = u.clone();
            v.outputs[0].index ^= 1;
            variants.push(v);
            let mut v = u.clone();
            v.outputs.pop();
            variants.push(v);
        }
        let i = r.below(u.spends.len() as u64) as usize;
        for f in 0..5 {
            let mut v = u.clone();
            let s = &mut v.spends[i];
            match f {
                0 => s.cv_net[0] ^= 1,
                1 => s.rk[31] ^= 0x80,
                2 => s.cmx[7] ^= 2,
                3 => s.proof.push(0),
                _ => s.index ^= 1,
            }
            variants.push(v);
        }
        // Proof contents, not just their length.
        if !u.spends[i].proof.is_empty() {
            let mut v = u.clone();
            let k = r.below(v.spends[i].proof.len() as u64) as usize;
            v.spends[i].proof[k] ^= 1;
            variants.push(v);
        }
        if let Some(a) = &u.spends[i].address {
            for f in 0..7 {
                let mut v = u.clone();
                let mut a = a.clone();
                match f {
                    0 => a.address[0] ^= 1,
                    1 => a.rho[1] ^= 1,
                    2 => a.rseed[2] ^= 1,
                    3 => a.nf[3] ^= 1,
                    4 => a.cv_net[4] ^= 1,
                    5 => a.cmx[5] ^= 1,
                    _ => a.proof.push(7),
                }
                v.spends[i].address = Some(a);
                variants.push(v);
            }
            // Dropping the address proof changes the digest too.
            let mut v = u.clone();
            v.spends[i].address = None;
            variants.push(v);
        }
        for v in variants {
            assert_ne!(signing_digest(&v), base, "a changed field left the digest unchanged");
        }
    }
}

#[test]
fn receipts_and_sign_ins_are_domain_separated() {
    use blake2b_simd::Params;
    let personal = |tag: &[u8; 12], coin: u32| {
        let mut p = [0u8; 16];
        p[..12].copy_from_slice(tag);
        p[12..].copy_from_slice(&coin.to_le_bytes());
        p
    };
    let mut r = Rng(0x5eed_0003);
    for _ in 0..500 {
        let data = r.vec(500);
        let h = |tag: &[u8; 12], coin| Params::new().hash_length(32).personal(&personal(tag, coin)).hash(&data);
        let receipt_main = h(b"ZIP311Signed", 133);
        let receipt_test = h(b"ZIP311Signed", 1);
        let signin_main = h(b"ZcashSignIn\0", 133);
        assert_ne!(receipt_main.as_bytes(), receipt_test.as_bytes(), "networks are separated");
        assert_ne!(receipt_main.as_bytes(), signin_main.as_bytes(), "protocols are separated");
    }
    // And the real receipt digest uses the receipt personalization for its network.
    let rc = random_receipt(&mut r);
    let enc = rc.unsigned.encode();
    let want = Params::new().hash_length(32).personal(&personal(b"ZIP311Signed", rc.unsigned.coin_type)).hash(&enc);
    assert_eq!(&signing_digest(&rc.unsigned)[..], want.as_bytes());
}

/// Every signed format has its own BLAKE2b personalization, so a signature made for one can't
/// verify as another (docs/ZIP311-ORCHARD.md, "Signing domains"). The tags are read from the source,
/// so a new or renamed format can't silently reuse one.
#[test]
fn all_signing_domains_are_distinct() {
    let src = [
        include_str!("../src/lib.rs"),
        include_str!("../src/incoming.rs"),
        include_str!("../src/signin.rs"),
        include_str!("../src/payreq.rs"),
        include_str!("../src/reserve.rs"),
    ]
    .concat();
    let mut tags: Vec<&str> = src
        .match_indices("signing_personal(b\"")
        .map(|(i, m)| {
            let rest = &src[i + m.len()..];
            &rest[..rest.find('"').unwrap()]
        })
        .collect();
    assert_eq!(tags.len(), 5, "{tags:?}");
    tags.sort();
    tags.dedup();
    assert_eq!(tags.len(), 5, "two formats share a signing domain: {tags:?}");
    assert!(tags.iter().all(|t| t.replace("\\0", "\0").len() == 12), "{tags:?}");
}

#[test]
fn the_challenge_rule() {
    use receipts_core::challenge_of;
    let c = |m: &str| challenge_of(m);
    assert_eq!(c("challenge:abcdef"), Some("abcdef".into()));
    assert_eq!(c("Order 7\nchallenge:abcdef\r\nmore"), Some("abcdef".into()));
    assert_eq!(c("challenge:abcdef\r"), Some("abcdef".into()), "a trailing CR is ignored, with or without LF");
    assert_eq!(c("challenge:abcde"), None, "fewer than 6 digits");
    assert_eq!(c(&format!("challenge:{}", "a".repeat(65))), None, "more than 64");
    assert_eq!(c("challenge:ABCDEF"), None, "uppercase");
    assert_eq!(c("challenge:abcdeg"), None, "not hex");
    assert_eq!(c("challenge:otc-7f3a holding"), None);
    assert_eq!(c("xchallenge:abcdef"), None, "only at the start of a line");
    assert_eq!(c("challenge:zzzzzz\nchallenge:abcdef"), None, "the first challenge line decides");
}
