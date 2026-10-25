//! A 2-of-3 FROST treasury issues a receipt for a real testnet payment, with a policy proof.
//!
//!     frost_policy <wallet> <identity> <prepared> <out-dir>
//!
//! The wallet's spend authority `ask` is split among three holders by a trusted dealer (this
//! program, which is why it is for testnet wallets only): the group key is the wallet's own `ak`,
//! so the payment it already made is the treasury's. `prepared` is `receipts create --unsigned`
//! for that payment. Two holders sign the receipt's digest, re-randomized by the receipt's alpha;
//! the coordinator then proves the receipt is under the published sharing commitment. Writes
//! `receipt.txt`, `policy.txt` and `commitment.txt` (one `C_j` per line) to the output directory.

use ff::{FromUniformBytes, PrimeField};
use group::GroupEncoding;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use reddsa05::frost::redpallas::{self as frost, keys::EvenY, rerandomized};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Orchard's `PRF^expand` domain for `ask` (ZIP 32 / protocol §4.2.3).
const ORCHARD_ASK: u8 = 0x06;

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let [wallet, identity, prepared, out] = &a[..] else { anyhow::bail!("usage: frost_policy <wallet> <identity> <prepared> <out-dir>") };
    let sk = receipts_wallet::__orchard_spending_key_for_tests(&PathBuf::from(wallet), &PathBuf::from(identity))?;

    // ask = ToScalar(PRF^expand_sk(6)), negated if that makes ak odd (Orchard keeps ak's y even).
    let h = blake2b_simd::Params::new().hash_length(64).personal(b"Zcash_ExpandSeed").to_state().update(&sk).update(&[ORCHARD_ASK]).finalize();
    let mut ask = pasta_curves::pallas::Scalar::from_uniform_bytes(h.as_array());
    let g = receipts_core::link::spend_auth_base();
    if (g * ask).to_bytes()[31] & 0x80 != 0 {
        ask = -ask;
    }
    let ak = (g * ask).to_bytes();

    let mut rng = rand_core06::OsRng;
    let secret = frost::SigningKey::deserialize(&ask.to_repr()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let (shares, pubkeys) = frost::keys::split(&secret, 3, 2, frost::keys::IdentifierList::Default, &mut rng).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let pubkeys = pubkeys.into_even_y(None);
    let shares: BTreeMap<_, _> = shares.into_iter().map(|(id, s)| (id, s.into_even_y(None))).collect();
    let group_key: [u8; 32] = pubkeys.verifying_key().serialize().map_err(|e| anyhow::anyhow!("{e:?}"))?.try_into().map_err(|_| anyhow::anyhow!("key length"))?;
    anyhow::ensure!(group_key == ak, "the group key is not the wallet's ak");

    let text = std::fs::read_to_string(prepared)?;
    let prepared = receipts_core::PreparedReceipt::from_text(text.lines().next().unwrap_or(""))?;
    let digest = receipts_core::signing_digest(prepared.unsigned());
    anyhow::ensure!(prepared.alphas().len() == 1, "this example signs one spend");
    let alpha: [u8; 32] = prepared.alphas()[0].to_repr();
    #[allow(deprecated)] // frost_rerandomized::sign takes the randomizer directly; the receipt fixes it.
    let sign_with = |who: &[u16]| -> [u8; 64] {
        let randomizer = rerandomized::Randomizer::deserialize(&alpha).unwrap();
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for &i in who {
            let id = frost::Identifier::try_from(i).unwrap();
            let kp = frost::keys::KeyPackage::try_from(shares[&id].clone()).unwrap();
            let (n, c) = frost::round1::commit(kp.signing_share(), &mut rand_core06::OsRng);
            nonces.insert(id, (n, kp));
            commitments.insert(id, c);
        }
        let package = frost::SigningPackage::new(commitments, &digest);
        let mut sig_shares = BTreeMap::new();
        for (id, (n, kp)) in &nonces {
            sig_shares.insert(*id, frost_rerandomized::sign(&package, n, kp, randomizer).unwrap());
        }
        let params = rerandomized::RandomizedParams::from_randomizer(pubkeys.verifying_key(), randomizer);
        rerandomized::aggregate(&package, &sig_shares, &pubkeys, &params).unwrap().serialize().unwrap().try_into().unwrap()
    };
    let receipt = prepared.clone().apply_signatures(vec![sign_with(&[1, 3])])?;
    let any = shares.values().next().unwrap();
    let commitment: Vec<[u8; 32]> = any.commitment().serialize().map_err(|e| anyhow::anyhow!("{e:?}"))?.into_iter().map(|c| c.try_into().unwrap()).collect();
    let policy = receipts_core::policy::prove(&prepared, commitment.clone(), 3, b"challenge:testnet", UnwrapErr(SysRng))?;
    let out = PathBuf::from(out);
    std::fs::create_dir_all(&out)?;
    // The receipt and its policy proof together, as `receipts verify` reads them.
    std::fs::write(out.join("receipt.txt"), format!("{}\n{}\n", receipt.to_text(), policy.to_text()))?;
    std::fs::write(out.join("commitment.txt"), commitment.iter().map(|c| hex::encode(c) + "\n").collect::<String>())?;
    eprintln!("wrote receipt.txt (with its policy proof) and commitment.txt in {}", out.display());
    Ok(())
}
