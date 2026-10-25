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

/// The coin-level key `m/32'/coin'` of a seed (ZIP 32 Orchard), the parent of every account.
pub fn coin_key(seed: &[u8], coin_type: u32) -> ([u8; 32], [u8; 32]) {
    let h = blake2b_simd::Params::new().hash_length(64).personal(b"ZcashIP32Orchard").hash(seed);
    let (sk, c): ([u8; 32], [u8; 32]) = (h.as_bytes()[..32].try_into().unwrap(), h.as_bytes()[32..].try_into().unwrap());
    let (sk, c) = child(&sk, &c, 32 | 0x8000_0000);
    child(&sk, &c, coin_type | 0x8000_0000)
}

pub const SIBLINGS_TEXT_PREFIX: &str = "zip311w1";
const MAGIC: &[u8; 4] = b"ZRCW";

/// A sibling-account proof: the two tags (in `domain`) are of two accounts of one wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Siblings {
    pub coin_type: u32,
    pub domain: Vec<u8>,
    pub tags: [[u8; 32]; 2],
    pub proof: Vec<u8>,
}

impl Siblings {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.push(1);
        v.extend_from_slice(&self.coin_type.to_le_bytes());
        v.extend_from_slice(&(self.domain.len() as u16).to_le_bytes());
        v.extend_from_slice(&self.domain);
        v.extend_from_slice(&self.tags[0]);
        v.extend_from_slice(&self.tags[1]);
        v.extend_from_slice(&(self.proof.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.proof);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        let mut p = 0usize;
        let mut take = |n: usize| -> Option<&[u8]> {
            let s = b.get(p..p + n)?;
            p += n;
            Some(s)
        };
        if take(4)? != MAGIC || take(1)? != [1] {
            return None;
        }
        let coin_type = u32::from_le_bytes(take(4)?.try_into().ok()?);
        let n = u16::from_le_bytes(take(2)?.try_into().ok()?) as usize;
        let domain = take(n)?.to_vec();
        let tags = [take(32)?.try_into().ok()?, take(32)?.try_into().ok()?];
        let n = u32::from_le_bytes(take(4)?.try_into().ok()?) as usize;
        if n == 0 || n > 1 << 16 {
            return None;
        }
        let proof = take(n)?.to_vec();
        (p == b.len()).then_some(Siblings { coin_type, domain, tags, proof })
    }

    pub fn to_text(&self) -> String {
        use base64::Engine;
        format!("{SIBLINGS_TEXT_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.to_bytes()))
    }

    pub fn from_text(s: &str) -> Option<Self> {
        use base64::Engine;
        let body = s.trim().strip_prefix(SIBLINGS_TEXT_PREFIX)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(body).ok()?;
        (base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) == body).then_some(())?;
        Self::from_bytes(&bytes)
    }
}

/// Proves accounts `a` and `b` of `seed` are siblings, for tags in the domain whose field element
/// is `domain_field`.
pub fn prove(keys: &Keys, seed: &[u8], coin_type: u32, accounts: [u32; 2], domain: &[u8], domain_field: pallas::Base, rng: impl rand::CryptoRng) -> Result<Siblings, Error> {
    if domain.len() > u16::MAX as usize {
        return Err(Error::Synthesis);
    }
    let (sk_par, c_par) = coin_key(seed, coin_type);
    let idx = accounts.map(|a| a | 0x8000_0000);
    let tags = idx.map(|i| tag(nk(&child(&sk_par, &c_par, i).0), domain_field));
    let c = SiblingCircuit { sk_par: Value::known(sk_par), c_par: Value::known(c_par), indices: idx.map(Value::known), domain: Value::known(domain_field) };
    let proof = keys.prove(c, &instance(domain_field, tags), rng)?;
    Ok(Siblings { coin_type, domain: domain.to_vec(), tags: tags.map(|t| t.to_repr()), proof })
}

/// Checks a sibling-account proof for the domain whose field element is `domain_field`.
pub fn verify(vk: &VerifyingKey, s: &Siblings, domain_field: pallas::Base) -> Result<(), Error> {
    let tags = s.tags.map(|t| Option::<pallas::Base>::from(pallas::Base::from_repr(t)));
    let [Some(t0), Some(t1)] = tags else { return Err(Error::Synthesis) };
    if t0 == t1 {
        return Err(Error::Synthesis);
    }
    vk.verify(&s.proof, &instance(domain_field, [t0, t1]))
}

/// Public inputs: `[domain, tag_1, tag_2]`.
pub fn instance(domain: pallas::Base, tags: [pallas::Base; 2]) -> Vec<pallas::Base> {
    vec![domain, tags[0], tags[1]]
}

/// BLAKE2b-256 of the k = 17 parameters' bytes, so a cached copy is used only if it is exactly
/// what `Params::new(K)` derives.
const PARAMS_DIGEST: &str = "375331e30b21a0188a9dcc63a67a11979ac7df716c93148a09bff27cd6c743c7";

/// `Params::new(K)` (deriving 2^17 points takes most of a key build), cached under `cache` when
/// given and checked against [`PARAMS_DIGEST`] when read back.
pub fn params(cache: Option<&std::path::Path>) -> Params<vesta::Affine> {
    let digest = |b: &[u8]| blake2b_simd::Params::new().hash_length(32).hash(b).to_hex().to_string();
    if let Some(bytes) = cache.and_then(|c| std::fs::read(c).ok()) {
        if digest(&bytes) == PARAMS_DIGEST {
            if let Ok(p) = Params::read(&mut &bytes[..]) {
                return p;
            }
        }
    }
    let p = Params::new(K);
    if let Some(c) = cache {
        let mut bytes = vec![];
        if p.write(&mut bytes).is_ok() && digest(&bytes) == PARAMS_DIGEST {
            let _ = c.parent().map(std::fs::create_dir_all);
            let _ = std::fs::write(c, bytes);
        }
    }
    p
}

/// Proving and verifying keys (built once; slow).
pub struct Keys {
    params: Params<vesta::Affine>,
    pk: plonk::ProvingKey<vesta::Affine>,
}

impl Keys {
    pub fn build(cache: Option<&std::path::Path>) -> Self {
        let params = params(cache);
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

/// The verifying key alone (no proving key: quicker to build).
pub struct VerifyingKey {
    params: Params<vesta::Affine>,
    vk: plonk::VerifyingKey<vesta::Affine>,
}

impl VerifyingKey {
    pub fn build(cache: Option<&std::path::Path>) -> Self {
        let params = params(cache);
        let vk = plonk::keygen_vk(&params, &SiblingCircuit::default()).expect("keygen_vk");
        VerifyingKey { params, vk }
    }

    pub fn verify(&self, proof: &[u8], public: &[pallas::Base]) -> Result<(), Error> {
        let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof);
        plonk::verify_proof(&self.params, &self.vk, SingleVerifier::new(&self.params), &[&[public]], &mut transcript)
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
        // A sibling under another chain code: refused.
        let other = tag(nk(&child(&sk_par, &[6u8; 32], idx[1]).0), domain);
        assert!(MockProver::run(K, &c, vec![instance(domain, [tags[0], other])]).unwrap().verify().is_err());
        // The right tags for another domain: refused.
        let d2 = pallas::Base::from(43);
        assert!(MockProver::run(K, &c, vec![instance(d2, tags)]).unwrap().verify().is_err());
        let t2 = idx.map(|i| tag(nk(&child(&sk_par, &c_par, i).0), d2));
        assert!(MockProver::run(K, &c, vec![instance(domain, t2)]).unwrap().verify().is_err());
        // The tag of the account's sk itself rather than its nk: refused (the circuit derives nk).
        let raw = idx.map(|i| {
            let sk = child(&sk_par, &c_par, i).0;
            let mut acc = pallas::Base::ZERO;
            for b in sk.iter().rev() {
                acc = acc * pallas::Base::from(256) + pallas::Base::from(*b as u64);
            }
            tag(acc, domain)
        });
        assert!(MockProver::run(K, &c, vec![instance(domain, raw)]).unwrap().verify().is_err());
    }

    #[test]
    fn mock_many_parents_and_indices() {
        // Several parents and account numbers, including account 0 and a large one.
        for (seed, accounts) in [(1u8, [0u32, 1]), (2, [5, 0]), (3, [0x7fff_fffe, 17])] {
            let (sk_par, c_par) = ([seed; 32], [seed.wrapping_mul(31); 32]);
            let idx = accounts.map(|a| a | 0x8000_0000);
            let domain = pallas::Base::from(seed as u64);
            let tags = idx.map(|i| tag(nk(&child(&sk_par, &c_par, i).0), domain));
            let c = SiblingCircuit { sk_par: Value::known(sk_par), c_par: Value::known(c_par), indices: idx.map(Value::known), domain: Value::known(domain) };
            assert_eq!(MockProver::run(K, &c, vec![instance(domain, tags)]).unwrap().verify(), Ok(()), "seed {seed}");
        }
    }
}

#[cfg(test)]
mod against_orchard {
    use super::*;
    use orchard::keys::{FullViewingKey, SpendingKey};

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
mod params_digest {
    #[test]
    #[ignore = "slow: derives the k = 17 parameters"]
    fn print_params_digest() {
        let t = std::time::Instant::now();
        let p = halo2_proofs::poly::commitment::Params::<pasta_curves::vesta::Affine>::new(super::K);
        let mut b = vec![];
        p.write(&mut b).unwrap();
        eprintln!("params {:?} digest {}", t.elapsed(), blake2b_simd::Params::new().hash_length(32).hash(&b).to_hex());
    }
}

#[cfg(test)]
mod real {
    use super::*;

    #[test]
    #[ignore = "slow: k = 17 keygen and proof"]
    fn prove_and_verify() {
        let t = std::time::Instant::now();
        let vk = VerifyingKey::build(None);
        eprintln!("vk {:?}", t.elapsed());
        let t = std::time::Instant::now();
        let keys = Keys::build(None);
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
        // Through the text format, from a seed, with the verifying key alone.
        let rng = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
        let s = prove(&keys, &[7u8; 32], 1, [0, 3], b"round", domain, rng).unwrap();
        let back = Siblings::from_text(&s.to_text()).unwrap();
        assert_eq!(back, s);
        let t = std::time::Instant::now();
        verify(&vk, &back, domain).unwrap();
        eprintln!("verify (vk only) {:?}", t.elapsed());
        assert!(verify(&vk, &back, pallas::Base::from(43)).is_err());
    }
}

/// The ported BLAKE2b gadget on its own: personalized digests against blake2b_simd, and inputs
/// that aren't bytes refused.
#[cfg(test)]
mod gadget {
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[derive(Clone, Default)]
    struct HashCircuit {
        input: Vec<Value<pallas::Base>>,
        personal: Option<[u8; 16]>,
    }

    impl Circuit<pallas::Base> for HashCircuit {
        type Config = (Blake2bConfig, [Column<Advice>; NB_BLAKE2B_ADVICE_COLS], Column<Instance>);
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            HashCircuit { input: vec![Value::unknown(); self.input.len()], personal: self.personal }
        }
        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
            let advice: [Column<Advice>; NB_BLAKE2B_ADVICE_COLS] = std::array::from_fn(|_| meta.advice_column());
            let constants = meta.fixed_column();
            let instance = meta.instance_column();
            meta.enable_equality(instance);
            (Blake2bChip::configure(meta, constants, advice[0], advice[1..].try_into().unwrap()), advice, instance)
        }
        fn synthesize(&self, (cfg, advice, instance): Self::Config, mut layouter: impl Layouter<pallas::Base>) -> Result<(), Error> {
            let chip = Blake2bChip::new(&cfg);
            chip.load(&mut layouter)?;
            let input = layouter.assign_region(
                || "input",
                |mut region| self.input.iter().enumerate().map(|(k, v)| region.assign_advice(|| "byte", advice[1 + k % 8], k / 8, || *v)).collect::<Result<Vec<_>, _>>(),
            )?;
            let out = chip.hash_personalized(&mut layouter, &input, &[], 64, self.personal)?;
            for (k, b) in out.iter().enumerate() {
                layouter.constrain_instance(b.cell(), instance, k)?;
            }
            Ok(())
        }
    }

    fn digest(input: &[u8], personal: Option<[u8; 16]>) -> Vec<pallas::Base> {
        let mut p = blake2b_simd::Params::new();
        p.hash_length(64);
        if let Some(pe) = personal {
            p.personal(&pe);
        }
        p.hash(input).as_bytes().iter().map(|b| pallas::Base::from(*b as u64)).collect()
    }

    fn run(input: Vec<Value<pallas::Base>>, personal: Option<[u8; 16]>, expected: Vec<pallas::Base>) -> bool {
        MockProver::run(K, &HashCircuit { input, personal }, vec![expected]).unwrap().verify().is_ok()
    }

    #[test]
    fn matches_blake2b_for_many_lengths() {
        // One and two blocks, the block boundary, and the two lengths ZIP 32 uses (33 and 69).
        for (n, personal) in [(0, Some(PERSONAL)), (1, None), (33, Some(PERSONAL)), (69, Some(PERSONAL)), (127, None), (128, Some(PERSONAL)), (129, Some(*b"ZcashIP32Orchard"))] {
            let bytes: Vec<u8> = (0..n).map(|i| (i * 37 + n * 11) as u8).collect();
            let input = bytes.iter().map(|b| Value::known(pallas::Base::from(*b as u64))).collect();
            assert!(run(input, personal, digest(&bytes, personal)), "length {n}");
        }
    }

    #[test]
    fn a_wrong_personalization_or_digest_is_refused() {
        let bytes = [7u8; 33];
        let input: Vec<_> = bytes.iter().map(|b| Value::known(pallas::Base::from(*b as u64))).collect();
        assert!(!run(input.clone(), Some(PERSONAL), digest(&bytes, None)));
        let mut wrong = digest(&bytes, Some(PERSONAL));
        wrong[63] += pallas::Base::ONE;
        assert!(!run(input, Some(PERSONAL), wrong));
    }

    #[test]
    fn inputs_that_are_not_bytes_are_refused() {
        // 256 at position 0 is the same as 0 at position 0 plus 1 at position 1, as a field sum,
        // so an unchecked gadget would accept it for another input. It must be range-checked.
        let mut input: Vec<_> = [0u8; 33].iter().map(|b| Value::known(pallas::Base::from(*b as u64))).collect();
        input[0] = Value::known(pallas::Base::from(256));
        let mut alias = [0u8; 33];
        alias[1] = 1;
        let r = std::panic::catch_unwind(|| run(input.clone(), Some(PERSONAL), digest(&alias, Some(PERSONAL))));
        assert_eq!(r.ok(), Some(false));
        let r = std::panic::catch_unwind(|| run(input, Some(PERSONAL), digest(&[0u8; 33], Some(PERSONAL))));
        assert_eq!(r.ok(), Some(false));
    }
}

#[cfg(test)]
pub mod unconstrained;
