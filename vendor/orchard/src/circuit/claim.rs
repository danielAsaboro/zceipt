//! Claim tags (local patch for Receipts): the Orchard Action circuit with one more public output,
//! `tag = Poseidon(nk, domain)`, and the spent note's nullifier kept private.
//!
//! The statement is the Action statement (the note is in the tree at `anchor`, it belongs to the
//! address derived from `ak`, `nk` and `rivk`, `rk = ak + [alpha] SpendAuthG`, `cv_net` commits
//! to `v_old - v_new`, and the new note commits to `cmx`) with the nullifier replaced by a tag
//! that depends only on the key's `nk` and a public `domain`. One key gives one tag per domain,
//! whichever of its notes it proves, and tags of different domains don't link.
//!
//! The nullifier is public or private by the keys' mode. Public, a verifier can check the note was
//! unspent at its snapshot (a note spent before it would otherwise claim again from a new key).
//! Private, the claim doesn't tie the note to its later spend; that suits a snapshot listing only
//! notes the verifier knows were held (its own deposits, say).

use alloc::vec::Vec;

use halo2_gadgets::poseidon::{
    primitives::{self as poseidon, ConstantLength},
    Hash as PoseidonHash,
};
use halo2_proofs::{
    circuit::{floor_planner, Layouter, Value},
    plonk::{self, SingleVerifier},
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas, vesta};
use rand::Rng;

use super::{
    gadget::assign_free_advice, Circuit, Config, Instance, OrchardCircuitVersion, Proof, INSTANCE_COLUMNS, INSTANCE_ROWS,
    K,
};

const DOMAIN: usize = INSTANCE_ROWS;
const TAG: usize = INSTANCE_ROWS + 1;
const CLAIM_ROWS: usize = INSTANCE_ROWS + 2;

/// The claim circuit: an Action circuit (post-NU6.3) and the claim's domain.
#[derive(Clone, Debug)]
pub struct ClaimCircuit {
    inner: Circuit,
    domain: Value<pallas::Base>,
    expose_nf: bool,
}

impl ClaimCircuit {
    /// From an Action circuit (as [`Circuit::from_action_context`] makes), the claim's domain and
    /// whether the nullifier is public.
    pub fn new(inner: Circuit, domain: pallas::Base, expose_nf: bool) -> Option<Self> {
        (inner.circuit_version == OrchardCircuitVersion::PostNu6_3).then_some(ClaimCircuit { inner, domain: Value::known(domain), expose_nf })
    }

    fn empty(expose_nf: bool) -> Self {
        ClaimCircuit { inner: Circuit::empty(OrchardCircuitVersion::PostNu6_3), domain: Value::unknown(), expose_nf }
    }
}

/// `Poseidon(nk, domain)`, the tag a key's claims carry in `domain`.
pub fn claim_tag(fvk: &crate::keys::FullViewingKey, domain: pallas::Base) -> pallas::Base {
    poseidon::Hash::<_, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([fvk.nk().inner(), domain])
}

impl plonk::Circuit<pallas::Base> for ClaimCircuit {
    type Config = Config;
    type FloorPlanner = floor_planner::V1;

    fn without_witnesses(&self) -> Self {
        ClaimCircuit::empty(self.expose_nf)
    }

    fn configure(meta: &mut plonk::ConstraintSystem<pallas::Base>) -> Self::Config {
        Config::configure(meta)
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<pallas::Base>) -> Result<(), plonk::Error> {
        let (addrs, nk) = self.inner.synthesize_inner(&config, &mut layouter, self.expose_nf)?;
        Circuit::synthesize_cross_address_checks(&config, &mut layouter, &addrs)?;

        let domain = assign_free_advice(layouter.namespace(|| "witness domain"), config.advices[0], self.domain)?;
        layouter.constrain_instance(domain.cell(), config.primary, DOMAIN)?;
        let hasher = PoseidonHash::<_, _, poseidon::P128Pow5T3, ConstantLength<2>, 3, 2>::init(config.poseidon_chip(), layouter.namespace(|| "tag init"))?;
        let tag = hasher.hash(layouter.namespace(|| "tag = Poseidon(nk, domain)"), [nk, domain])?;
        layouter.constrain_instance(tag.cell(), config.primary, TAG)?;
        Ok(())
    }
}

/// A claim's public inputs: the Action statement (its nullifier unused) plus the domain and tag.
#[derive(Clone, Debug)]
pub struct ClaimInstance {
    /// The Action statement (its `nf_old` ignored when the nullifier is private).
    pub action: Instance,
    /// The claim's domain (an airdrop's, a grant round's), as a field element.
    pub domain: pallas::Base,
    /// The key's tag in that domain.
    pub tag: pallas::Base,
}

impl ClaimInstance {
    fn to_halo2(&self, expose_nf: bool) -> [[vesta::Scalar; CLAIM_ROWS]; INSTANCE_COLUMNS] {
        let base = self.action.to_halo2_instance()[0];
        let mut rows = [vesta::Scalar::zero(); CLAIM_ROWS];
        rows[..INSTANCE_ROWS].copy_from_slice(&base);
        if !expose_nf {
            rows[super::NF_OLD] = vesta::Scalar::zero();
        }
        rows[DOMAIN] = self.domain;
        rows[TAG] = self.tag;
        [rows]
    }
}

/// Keys for the claim circuit (k = 11, as the Action circuit).
#[derive(Debug)]
pub struct ClaimKeys {
    params: halo2_proofs::poly::commitment::Params<vesta::Affine>,
    pk: plonk::ProvingKey<vesta::Affine>,
    expose_nf: bool,
}

impl ClaimKeys {
    /// Builds the proving (and verifying) key for the claim circuit, with the nullifier public
    /// or private.
    pub fn build(expose_nf: bool) -> Self {
        let params = halo2_proofs::poly::commitment::Params::new(K);
        let circuit = ClaimCircuit::empty(expose_nf);
        let vk = plonk::keygen_vk(&params, &circuit).unwrap();
        let pk = plonk::keygen_pk(&params, vk, &circuit).unwrap();
        ClaimKeys { params, pk, expose_nf }
    }

    /// Proves the claims.
    pub fn create(&self, circuits: &[ClaimCircuit], instances: &[ClaimInstance], mut rng: impl Rng) -> Result<Proof, plonk::Error> {
        if circuits.iter().any(|c| c.expose_nf != self.expose_nf) {
            return Err(plonk::Error::Synthesis);
        }
        let instances: Vec<_> = instances.iter().map(|i| i.to_halo2(self.expose_nf)).collect();
        let instances: Vec<Vec<&[vesta::Scalar]>> = instances.iter().map(|i| i.iter().map(|c| &c[..]).collect()).collect();
        let instances: Vec<&[&[vesta::Scalar]]> = instances.iter().map(|i| &i[..]).collect();
        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(alloc::vec![]);
        plonk::create_proof(&self.params, &self.pk, circuits, &instances, &mut rng, &mut transcript)?;
        Ok(Proof(transcript.finalize()))
    }

    /// Verifies claims' proof.
    pub fn verify(&self, proof: &Proof, instances: &[ClaimInstance]) -> Result<(), plonk::Error> {
        let instances: Vec<_> = instances.iter().map(|i| i.to_halo2(self.expose_nf)).collect();
        let instances: Vec<Vec<&[vesta::Scalar]>> = instances.iter().map(|i| i.iter().map(|c| &c[..]).collect()).collect();
        let instances: Vec<&[&[vesta::Scalar]]> = instances.iter().map(|i| &i[..]).collect();
        let strategy = SingleVerifier::new(&self.params);
        let mut transcript = Blake2bRead::init(&proof.0[..]);
        plonk::verify_proof(&self.params, self.pk.get_vk(), strategy, &instances, &mut transcript)
    }
}
