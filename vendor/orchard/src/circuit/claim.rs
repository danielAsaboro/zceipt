//! Claim tags (local patch for Zceipt): the Orchard Action circuit with one more public output,
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

    /// A circuit with no witnesses, for tests that read its structure.
    #[doc(hidden)]
    pub fn __empty_for_tests(expose_nf: bool) -> Self {
        Self::empty(expose_nf)
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

    /// BLAKE2b-256 (hex) of the verifying key's pinned description: changes whenever the circuit's
    /// constraint system does. Pinned in the tests, so a change cannot go unnoticed.
    pub fn vk_fingerprint(&self) -> alloc::string::String {
        let d = alloc::format!("{:?}", self.pk.get_vk().pinned());
        blake2b_simd::Params::new().hash_length(32).hash(d.as_bytes()).to_hex().as_str().into()
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
        // A proof has one encoding: bytes after what the verifier reads are refused.
        let mut rest: &[u8] = &proof.0[..];
        let mut transcript = Blake2bRead::init(&mut rest);
        plonk::verify_proof(&self.params, self.pk.get_vk(), strategy, &instances, &mut transcript)?;
        drop(transcript);
        if rest.is_empty() {
            Ok(())
        } else {
            Err(plonk::Error::Opening)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, vec, vec::Vec};
    use crate::{
        bundle::Flags,
        keys::{FullViewingKey, Scope, SpendValidatingKey},
        note::{Note, NoteVersion, Rho},
        tree::MerklePath,
        value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
    };
    use ff::Field;
    use halo2_proofs::{circuit::Value, dev::MockProver};
    use rand::{rand_core::UnwrapErr, rngs::SysRng};

    const FLOOR: u64 = 600;

    /// The claim circuit's constraint system is pinned: any change to it (or to the Action circuit
    /// it extends) changes these fingerprints and must be reviewed, then re-pinned here.
    #[test]
    fn verifying_keys_are_pinned() {
        assert_eq!(ClaimKeys::build(true).vk_fingerprint(), "7f865616220168520ff07d7f7c740a9347a3b8fba46419ccad296fe55560a585", "claim circuit, nullifier public");
        assert_eq!(ClaimKeys::build(false).vk_fingerprint(), "1278f6ecf78b467281bc5f3a40d645de941e18cf0404b5219bb3fa204859d5f1", "claim circuit, nullifier private");
    }

    /// A claim over a note of 1000 with floor 600, honest: the circuit and its public inputs.
    fn honest(expose_nf: bool) -> (ClaimCircuit, ClaimInstance) {
        let mut rng = UnwrapErr(SysRng);
        let version = NoteVersion::V2;
        let (_, fvk, dummy) = Note::dummy(&mut rng, None, version);
        let spent = Note::new(dummy.recipient(), NoteValue::from_raw(1000), dummy.rho(), version, &mut rng);
        let nf_old = spent.nullifier(&fvk);
        let (_, _, other_recipient) = Note::dummy(&mut rng, Some(Rho::from_nf_old(nf_old)), version);
        let output = Note::new(other_recipient.recipient(), NoteValue::from_raw(1000 - FLOOR), Rho::from_nf_old(nf_old), version, &mut rng);
        let alpha = pallas::Scalar::random(&mut rng);
        let ak: SpendValidatingKey = fvk.clone().into();
        let rk = ak.randomize(&alpha);
        let rivk = fvk.rivk(fvk.scope_for_address(&spent.recipient()).unwrap());
        let rcv = ValueCommitTrapdoor::zero();
        let cv_net = ValueCommitment::derive(spent.value() - output.value(), rcv.clone());
        let path = MerklePath::dummy(&mut rng);
        let anchor = path.root(spent.commitment().into());
        let inner = Circuit {
            circuit_version: OrchardCircuitVersion::PostNu6_3,
            path: Value::known(path.auth_path()),
            pos: Value::known(path.position()),
            g_d_old: Value::known(spent.recipient().g_d()),
            pk_d_old: Value::known(*spent.recipient().pk_d()),
            v_old: Value::known(spent.value()),
            rho_old: Value::known(spent.rho()),
            psi_old: Value::known(spent.psi()),
            rcm_old: Value::known(spent.rcm()),
            cm_old: Value::known(spent.commitment()),
            alpha: Value::known(alpha),
            ak: Value::known(ak),
            nk: Value::known(*fvk.nk()),
            rivk: Value::known(rivk),
            g_d_new: Value::known(output.recipient().g_d()),
            pk_d_new: Value::known(*output.recipient().pk_d()),
            v_new: Value::known(output.value()),
            psi_new: Value::known(output.psi()),
            rcm_new: Value::known(output.rcm()),
            rcv: Value::known(rcv),
        };
        let domain = pallas::Base::from(7);
        let instance = ClaimInstance {
            action: Instance::from_parts(anchor, cv_net, nf_old, rk, output.commitment().into(), Flags::ENABLED).unwrap(),
            domain,
            tag: claim_tag(&fvk, domain),
        };
        (ClaimCircuit { inner, domain: Value::known(domain), expose_nf }, instance)
    }

    fn accepts(c: &ClaimCircuit, i: &ClaimInstance) -> bool {
        let rows = i.to_halo2(c.expose_nf);
        MockProver::run(crate::circuit::K, c, vec![rows[0].to_vec()]).unwrap().verify().is_ok()
    }

    /// Every private witness, changed on its own, makes the circuit refuse the honest public inputs:
    /// none is free for a dishonest prover to choose.
    #[test]
    fn no_private_witness_is_free() {
        for expose_nf in [true, false] {
            let (c, i) = honest(expose_nf);
            assert!(accepts(&c, &i), "the honest claim (expose_nf={expose_nf})");
            // Values for another note, key and address, to swap in.
            let mut rng = UnwrapErr(SysRng);
            let (_, fvk2, n2) = Note::dummy(&mut rng, None, NoteVersion::V2);
            let ak2: SpendValidatingKey = fvk2.clone().into();
            let rivk2 = fvk2.rivk(Scope::External);
            let path2 = MerklePath::dummy(&mut rng);
            let mutations: Vec<(&str, Box<dyn Fn(&mut ClaimCircuit)>)> = vec![
                ("v_old", Box::new(|c| c.inner.v_old = Value::known(NoteValue::from_raw(1001)))),
                ("v_old_smaller", Box::new(|c| c.inner.v_old = Value::known(NoteValue::from_raw(999)))),
                ("v_new", Box::new(|c| c.inner.v_new = Value::known(NoteValue::from_raw(401)))),
                ("alpha", Box::new(|c| c.inner.alpha = Value::known(pallas::Scalar::from(3)))),
                ("nk", Box::new(move |c| c.inner.nk = Value::known(*fvk2.nk()))),
                ("rivk", Box::new(move |c| c.inner.rivk = Value::known(rivk2))),
                ("ak", Box::new(move |c| c.inner.ak = Value::known(ak2.clone()))),
                ("g_d_old", Box::new({ let g = n2.recipient().g_d(); move |c| c.inner.g_d_old = Value::known(g) })),
                ("pk_d_old", Box::new({ let p = *n2.recipient().pk_d(); move |c| c.inner.pk_d_old = Value::known(p) })),
                ("rho_old", Box::new({ let r = n2.rho(); move |c| c.inner.rho_old = Value::known(r) })),
                ("psi_old", Box::new({ let p = n2.psi(); move |c| c.inner.psi_old = Value::known(p) })),
                ("rcm_old", Box::new({ let r = n2.rcm(); move |c| c.inner.rcm_old = Value::known(r.clone()) })),
                ("cm_old", Box::new({ let m = n2.commitment(); move |c| c.inner.cm_old = Value::known(m.clone()) })),
                ("path", Box::new(move |c| c.inner.path = Value::known(path2.auth_path()))),
                ("pos", Box::new(|c| c.inner.pos = c.inner.pos.map(|p| p ^ 1))),
                ("g_d_new", Box::new({ let g = n2.recipient().g_d(); move |c| c.inner.g_d_new = Value::known(g) })),
                ("pk_d_new", Box::new({ let p = *n2.recipient().pk_d(); move |c| c.inner.pk_d_new = Value::known(p) })),
                ("psi_new", Box::new({ let p = n2.psi(); move |c| c.inner.psi_new = Value::known(p) })),
                ("rcm_new", Box::new({ let r = n2.rcm(); move |c| c.inner.rcm_new = Value::known(r.clone()) })),
                ("rcv", Box::new(|c| c.inner.rcv = Value::known(ValueCommitTrapdoor::random(UnwrapErr(SysRng))))),
                ("domain", Box::new(|c| c.domain = Value::known(pallas::Base::from(8)))),
            ];
            for (name, m) in mutations {
                let mut bad = c.clone();
                m(&mut bad);
                assert!(!accepts(&bad, &i), "the circuit accepted a changed {name} (expose_nf={expose_nf})");
            }
            // And each public input, changed with the witnesses honest.
            let mut wrong = i.clone();
            wrong.domain = pallas::Base::from(8);
            assert!(!accepts(&c, &wrong), "domain input");
            let mut wrong = i.clone();
            wrong.tag += pallas::Base::one();
            assert!(!accepts(&c, &wrong), "tag input");
            let mut wrong = i.clone();
            wrong.action = Instance::from_parts(
                wrong.action.anchor,
                ValueCommitment::derive(NoteValue::from_raw(FLOOR + 1) - NoteValue::from_raw(0), ValueCommitTrapdoor::zero()),
                wrong.action.nf_old,
                wrong.action.rk.clone(),
                wrong.action.cmx,
                Flags::ENABLED,
            )
            .unwrap();
            assert!(!accepts(&c, &wrong), "floor (cv_net) input");
        }
    }
}
