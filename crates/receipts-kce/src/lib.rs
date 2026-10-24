//! Sibling-account proofs (Key-Class Equivalence): two payer tags in one domain come from two
//! accounts of one ZIP 32 wallet, without saying which wallet or which accounts.
//!
//! Orchard account keys are hardened ZIP 32 children of the wallet's coin-level key
//! (`m/32'/coin'`): `I = BLAKE2b-512("Zcash_ExpandSeed", c_par || 0x81 || sk_par || i)`,
//! `sk = I[..32]`, and the account's `nk = ToBase(BLAKE2b-512("Zcash_ExpandSeed", sk || 0x07))`.
//! A payer tag is `Poseidon(nk, domain)` (receipts-core `claim`). This circuit proves, for public
//! `domain`, `tag_1`, `tag_2`: there are `(sk_par, c_par)` and indices `i_1`, `i_2` whose children's
//! `nk`s give those tags. The parent key, the indices and the `nk`s stay private.
//!
//! With the payer tags that bind each tag to a real payment, a verifier learns that the two
//! payments were made by accounts of one wallet. BLAKE2b runs in the circuit (four compressions),
//! so the circuit is k = 17 (the gadget's 16-bit XOR table), far larger than an Action proof.

pub mod blake2b_halo2;

use blake2b_halo2::{
    blake2b::{
        blake2b_chip::{Blake2bChip, Blake2bConfig},
        NB_BLAKE2B_ADVICE_COLS,
    },
    types::{byte::AssignedByte, AssignedNative},
};
use ff::{Field, PrimeField};
use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, ConstantLength, P128Pow5T3},
    Hash as PoseidonHash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{self, Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Instance, Selector, SingleVerifier},
    poly::{commitment::Params, Rotation},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{pallas, vesta};

/// The circuit's size: 2^17 rows.
pub const K: u32 = 17;
const PERSONAL: [u8; 16] = *b"Zcash_ExpandSeed";

/// The witness: the parent extended key and the two children's indices.
#[derive(Clone, Debug, Default)]
pub struct SiblingCircuit {
    pub sk_par: Value<[u8; 32]>,
    pub c_par: Value<[u8; 32]>,
    pub indices: [Value<u32>; 2],
    pub domain: Value<pallas::Base>,
}

#[derive(Clone, Debug)]
pub struct Config {
    blake2b: Blake2bConfig,
    advice: [Column<Advice>; NB_BLAKE2B_ADVICE_COLS],
    poseidon: Pow5Config<pallas::Base, 3, 2>,
    q_acc_first: Selector,
    q_acc: Selector,
    instance: Column<Instance>,
}

/// `sk` of child `i` of `(sk_par, c_par)` (ZIP 32 Orchard hardened derivation), and its chain code.
pub fn child(sk_par: &[u8; 32], c_par: &[u8; 32], i: u32) -> ([u8; 32], [u8; 32]) {
    let h = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(&PERSONAL)
        .to_state()
        .update(c_par)
        .update(&[0x81])
        .update(sk_par)
        .update(&i.to_le_bytes())
        .finalize();
    (h.as_bytes()[..32].try_into().unwrap(), h.as_bytes()[32..].try_into().unwrap())
}

/// `nk = ToBase(PRF^expand(sk, [7]))`.
pub fn nk(sk: &[u8; 32]) -> pallas::Base {
    let h = blake2b_simd::Params::new().hash_length(64).personal(&PERSONAL).to_state().update(sk).update(&[0x07]).finalize();
    let mut acc = pallas::Base::ZERO;
    for b in h.as_bytes().iter().rev() {
        acc = acc * pallas::Base::from(256) + pallas::Base::from(*b as u64);
    }
    acc
}

/// A payer tag: `Poseidon(nk, domain)`.
pub fn tag(nk: pallas::Base, domain: pallas::Base) -> pallas::Base {
    poseidon::Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([nk, domain])
}

impl Circuit<pallas::Base> for SiblingCircuit {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Config {
        let advice: [Column<Advice>; NB_BLAKE2B_ADVICE_COLS] = std::array::from_fn(|_| meta.advice_column());
        let constants = meta.fixed_column();
        let blake2b = Blake2bChip::configure(meta, constants, advice[0], advice[1..].try_into().unwrap());

        let rc_a = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let rc_b = [meta.fixed_column(), meta.fixed_column(), meta.fixed_column()];
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, [advice[1], advice[2], advice[3]], advice[4], rc_a, rc_b);

        // ToBase: acc_0 = b_0, acc_r = 256 acc_{r-1} + b_r, bytes from the most significant.
        let (acc, byte) = (advice[0], advice[1]);
        let q_acc_first = meta.selector();
        let q_acc = meta.selector();
        meta.create_gate("acc first", |meta| {
            let q = meta.query_selector(q_acc_first);
            Constraints::with_selector(q, [meta.query_advice(acc, Rotation::cur()) - meta.query_advice(byte, Rotation::cur())])
        });
        meta.create_gate("acc step", |meta| {
            let q = meta.query_selector(q_acc);
            let step = meta.query_advice(acc, Rotation::cur())
                - meta.query_advice(acc, Rotation::prev()) * plonk::Expression::Constant(pallas::Base::from(256))
                - meta.query_advice(byte, Rotation::cur());
            Constraints::with_selector(q, [step])
        });

        let instance = meta.instance_column();
        meta.enable_equality(instance);
        Config { blake2b, advice, poseidon, q_acc_first, q_acc, instance }
    }

    fn synthesize(&self, config: Config, mut layouter: impl Layouter<pallas::Base>) -> Result<(), Error> {
        let chip = Blake2bChip::new(&config.blake2b);
        chip.load(&mut layouter)?;
        let byte_f = |b: u8| pallas::Base::from(b as u64);

        // The parent's key and chain code, shared by both children; the constants.
        let (sk_par, c_par, idx, c81, c07, domain) = layouter.assign_region(
            || "witnesses",
            |mut region| {
                let mut row = 0;
                let mut bytes = |vals: Vec<Value<pallas::Base>>, region: &mut halo2_proofs::circuit::Region<'_, pallas::Base>| {
                    let out = vals
                        .into_iter()
                        .enumerate()
                        .map(|(k, v)| region.assign_advice(|| "byte", config.advice[1 + k % 8], row + k / 8, || v))
                        .collect::<Result<Vec<_>, _>>();
                    row += 8;
                    out
                };
                let sk_par = bytes((0..32).map(|k| self.sk_par.map(|s| byte_f(s[k]))).collect(), &mut region)?;
                let c_par = bytes((0..32).map(|k| self.c_par.map(|s| byte_f(s[k]))).collect(), &mut region)?;
                let mut idx = Vec::new();
                for i in &self.indices {
                    idx.push(bytes((0..4).map(|k| i.map(|i| byte_f(i.to_le_bytes()[k]))).collect(), &mut region)?);
                }
                let c81 = region.assign_advice_from_constant(|| "0x81", config.advice[1], row, byte_f(0x81))?;
                let c07 = region.assign_advice_from_constant(|| "0x07", config.advice[2], row, byte_f(0x07))?;
                let domain = region.assign_advice(|| "domain", config.advice[3], row, || self.domain)?;
                Ok((sk_par, c_par, idx, c81, c07, domain))
            },
        )?;
        layouter.constrain_instance(domain.cell(), config.instance, 0)?;

        for (j, i) in idx.iter().enumerate() {
            // sk_j = BLAKE2b(c_par || 0x81 || sk_par || i_j)[..32]
            let input: Vec<AssignedNative<pallas::Base>> = c_par.iter().chain([&c81]).chain(&sk_par).chain(i).cloned().collect();
            let out = chip.hash_personalized(&mut layouter, &input, &[], 64, Some(PERSONAL))?;
            let sk = to_native(&config, &mut layouter, &out[..32])?;
            // nk_j = ToBase(BLAKE2b(sk_j || 0x07))
            let input: Vec<AssignedNative<pallas::Base>> = sk.iter().chain([&c07]).cloned().collect();
            let out = chip.hash_personalized(&mut layouter, &input, &[], 64, Some(PERSONAL))?;
            let nk = to_base(&config, &mut layouter, &out)?;
            // tag_j = Poseidon(nk_j, domain)
            let hasher = PoseidonHash::<_, _, P128Pow5T3, ConstantLength<2>, 3, 2>::init(
                Pow5Chip::construct(config.poseidon.clone()),
                layouter.namespace(|| "tag init"),
            )?;
            let t = hasher.hash(layouter.namespace(|| "tag"), [nk, domain.clone()])?;
            layouter.constrain_instance(t.cell(), config.instance, 1 + j)?;
        }
        Ok(())
    }
}

/// Copies hash output bytes into plain cells (equal to them) for the next hash's input.
fn to_native(config: &Config, layouter: &mut impl Layouter<pallas::Base>, bytes: &[AssignedByte<pallas::Base>]) -> Result<Vec<AssignedNative<pallas::Base>>, Error> {
    layouter.assign_region(
        || "copy bytes",
        |mut region| {
            bytes
                .iter()
                .enumerate()
                .map(|(k, b)| {
                    let c = region.assign_advice(|| "byte", config.advice[1 + k % 8], k / 8, || b.value().map(|v| pallas::Base::from(v.0 as u64)))?;
                    region.constrain_equal(c.cell(), b.cell())?;
                    Ok(c)
                })
                .collect()
        },
    )
}

/// The 64 little-endian bytes as one field element (reduced mod p, as ToBase).
fn to_base(config: &Config, layouter: &mut impl Layouter<pallas::Base>, bytes: &[AssignedByte<pallas::Base>]) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
    layouter.assign_region(
        || "to base",
        |mut region| {
            let mut acc_v = Value::known(pallas::Base::ZERO);
            let mut last = None;
            for (r, b) in bytes.iter().rev().enumerate() {
                let bv = b.value().map(|v| pallas::Base::from(v.0 as u64));
                let c = region.assign_advice(|| "byte", config.advice[1], r, || bv)?;
                region.constrain_equal(c.cell(), b.cell())?;
                acc_v = acc_v.zip(bv).map(|(a, b)| a * pallas::Base::from(256) + b);
                if r == 0 {
                    config.q_acc_first.enable(&mut region, r)?;
                } else {
                    config.q_acc.enable(&mut region, r)?;
                }
                last = Some(region.assign_advice(|| "acc", config.advice[0], r, || acc_v)?);
            }
            Ok(last.unwrap())
        },
    )
}

/// Public inputs: `[domain, tag_1, tag_2]`.
pub fn instance(domain: pallas::Base, tags: [pallas::Base; 2]) -> Vec<pallas::Base> {
    vec![domain, tags[0], tags[1]]
}

/// Proving and verifying keys (built once; slow).
pub struct Keys {
    params: Params<vesta::Affine>,
    pk: plonk::ProvingKey<vesta::Affine>,
}

impl Keys {
    pub fn build() -> Self {
        let params = Params::new(K);
        let vk = plonk::keygen_vk(&params, &SiblingCircuit::default()).expect("keygen_vk");
        let pk = plonk::keygen_pk(&params, vk, &SiblingCircuit::default()).expect("keygen_pk");
        Keys { params, pk }
    }

    pub fn prove(&self, c: SiblingCircuit, public: &[pallas::Base], rng: impl rand::CryptoRng) -> Result<Vec<u8>, Error> {
        let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
        plonk::create_proof(&self.params, &self.pk, &[c], &[&[public]], rng, &mut transcript)?;
        Ok(transcript.finalize())
    }

    pub fn verify(&self, proof: &[u8], public: &[pallas::Base]) -> Result<(), Error> {
        let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof);
        plonk::verify_proof(&self.params, self.pk.get_vk(), SingleVerifier::new(&self.params), &[&[public]], &mut transcript)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn mock_siblings() {
        let (sk_par, c_par) = ([3u8; 32], [5u8; 32]);
        let idx = [0x8000_0000u32, 0x8000_0001];
        let domain = pallas::Base::from(42);
        let tags = idx.map(|i| tag(nk(&child(&sk_par, &c_par, i).0), domain));
        let c = SiblingCircuit { sk_par: Value::known(sk_par), c_par: Value::known(c_par), indices: idx.map(Value::known), domain: Value::known(domain) };
        let p = MockProver::run(K, &c, vec![instance(domain, tags)]).unwrap();
        assert_eq!(p.verify(), Ok(()));
        // Another wallet's tag: refused.
        let other = tag(nk(&child(&[4u8; 32], &c_par, idx[1]).0), domain);
        let p = MockProver::run(K, &c, vec![instance(domain, [tags[0], other])]).unwrap();
        assert!(p.verify().is_err());
    }
}

#[cfg(test)]
mod against_orchard {
    use super::*;
    use orchard::keys::{FullViewingKey, SpendingKey};

    /// The coin-level key `m/32'/coin'` of a seed, by ZIP 32 (the parent of every account).
    fn coin_key(seed: &[u8], coin: u32) -> ([u8; 32], [u8; 32]) {
        let h = blake2b_simd::Params::new().hash_length(64).personal(b"ZcashIP32Orchard").hash(seed);
        let (sk, c): ([u8; 32], [u8; 32]) = (h.as_bytes()[..32].try_into().unwrap(), h.as_bytes()[32..].try_into().unwrap());
        let (sk, c) = child(&sk, &c, 32 | 0x8000_0000);
        child(&sk, &c, coin | 0x8000_0000)
    }

    #[test]
    fn accounts_are_children_of_the_coin_key() {
        let seed = [7u8; 32];
        let (sk_par, c_par) = coin_key(&seed, 1);
        let domain = pallas::Base::from(9);
        for a in 0..3u32 {
            let sk = SpendingKey::from_zip32_seed(&seed, 1, zip32::AccountId::try_from(a).unwrap()).unwrap();
            let (mine, _) = child(&sk_par, &c_par, a | 0x8000_0000);
            assert_eq!(&mine, sk.to_bytes());
            let fvk = FullViewingKey::from(&sk);
            assert_eq!(tag(nk(&mine), domain), orchard::circuit::claim::claim_tag(&fvk, domain));
        }
    }
}

#[cfg(test)]
mod real {
    use super::*;

    #[test]
    #[ignore = "slow: k = 17 keygen and proof"]
    fn prove_and_verify() {
        let t = std::time::Instant::now();
        let keys = Keys::build();
        eprintln!("keys {:?}", t.elapsed());
        let (sk_par, c_par) = ([3u8; 32], [5u8; 32]);
        let idx = [0x8000_0000u32, 0x8000_0002];
        let domain = pallas::Base::from(42);
        let tags = idx.map(|i| tag(nk(&child(&sk_par, &c_par, i).0), domain));
        let c = SiblingCircuit { sk_par: Value::known(sk_par), c_par: Value::known(c_par), indices: idx.map(Value::known), domain: Value::known(domain) };
        let t = std::time::Instant::now();
        let rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
        let proof = keys.prove(c, &instance(domain, tags), rng).unwrap();
        eprintln!("prove {:?}, {} bytes", t.elapsed(), proof.len());
        let t = std::time::Instant::now();
        keys.verify(&proof, &instance(domain, tags)).unwrap();
        eprintln!("verify {:?}", t.elapsed());
        assert!(keys.verify(&proof, &instance(domain, [tags[1], tags[0]])).is_err());
    }
}
