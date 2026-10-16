//! Make receipts from a zcash-devtool wallet (keys.toml + data.sqlite): `create_receipt`,
//! `sign_in`, `wallet_network`, and the proof-request helpers `parse_request_link` /
//! `check_answers`.
//!
//! The wallet database is opened as zcash_client_sqlite opens it (it may cache witnesses), but
//! no notes, transactions or keys are written; the mnemonic is decrypted in memory, held in
//! zeroizing containers, and never logged or written. Used by the `receipts` CLI and by the `zcash-devtool wallet
//! receipt` command (see integrations/zcash-devtool).
//!
//! The mnemonic is decrypted in memory with the wallet's age identity, used to derive the
//! account's Orchard spending key, and dropped. Nothing is written back to the wallet.

use anyhow::{anyhow, bail, Context};
use incrementalmerkletree::Position;
use orchard::{
    keys::{Diversifier, FullViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey},
    note::{NoteVersion, RandomSeed, Rho},
    note_encryption::{IronwoodDomain, OrchardDomain},
    tree::MerklePath,
    value::NoteValue,
    Note,
};
/// `rand` 0.10 replaced the infallible `OsRng` with the fallible `SysRng`.
#[allow(non_upper_case_globals)]
const OsRng: rand::rand_core::UnwrapErr<rand::rngs::SysRng> = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
use receipts_chain::net::{Heights, Net};
use receipts_core::{Pool, Receipt, SpendWitness};
use secrecy::ExposeSecret;
use serde::Deserialize;
use shardtree::error::ShardTreeError;
use std::{io::Read, path::Path};
use zcash_client_backend::data_api::{WalletCommitmentTrees, WalletRead};
use zcash_client_sqlite::{util::SystemClock, WalletDb};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_note_encryption::try_note_decryption;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;


#[derive(Deserialize)]
struct KeysToml {
    mnemonic: Option<String>,
    network: Option<String>,
    activation_heights: Option<Heights>,
}

fn read_keys(wallet: &Path) -> anyhow::Result<KeysToml> {
    let keys_path = wallet.join("keys.toml");
    Ok(toml::from_str(&std::fs::read_to_string(&keys_path).with_context(|| format!("reading {} (is -w a zcash-devtool wallet directory?)", keys_path.display()))?)?)
}

/// The network a wallet is for (no secrets are read).
pub fn wallet_network(wallet: &Path) -> anyhow::Result<Net> {
    let keys = read_keys(wallet)?;
    net_of(&keys)
}

fn net_of(keys: &KeysToml) -> anyhow::Result<Net> {
    Ok(match keys.network.as_deref().unwrap_or("test") {
        "main" => Net::Main,
        "test" => Net::Test,
        "regtest" => Net::Regtest(
            keys.activation_heights
                .as_ref()
                .ok_or_else(|| anyhow!("regtest wallet has no activation heights"))?
                .to_local(),
        ),
        other => bail!("unsupported network {other}"),
    })
}

fn decrypt_seed(wallet: &Path, identity: &Path) -> anyhow::Result<(Net, secrecy::SecretVec<u8>)> {
    let keys = read_keys(wallet)?;
    let net = net_of(&keys)?;
    let ct = keys.mnemonic.ok_or_else(|| anyhow!("this wallet has no mnemonic (viewing-only)"))?;
    let ids = age::IdentityFile::from_file(identity.to_string_lossy().into_owned())
        .context("reading age identity")?
        .into_identities()?;
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(ct.as_bytes()))?;
    let mut phrase = String::new();
    decryptor
        .decrypt(ids.iter().map(|i| i.as_ref() as &dyn age::Identity))?
        .read_to_string(&mut phrase)?;
    // Zeroized when dropped.
    let phrase = secrecy::SecretString::new(phrase);
    let mnemonic = <bip0039::Mnemonic<bip0039::English>>::from_phrase(phrase.expose_secret().trim())
        // Never echo the error: it can quote a word of the phrase.
        .map_err(|_| anyhow!("the wallet's mnemonic doesn't decode as a BIP 39 phrase"))?;
    let seed = secrecy::SecretVec::new(mnemonic.to_seed("").to_vec());
    Ok((net, seed))
}

struct StoredNote {
    note: Note,
    position: u64,
    /// Height at which the note was received, if known.
    mined_height: Option<u32>,
    /// The transaction and action index that created the note.
    source_txid: [u8; 32],
    source_action: u32,
}

/// Looks up a note this wallet received, by nullifier, in the pool's received-notes table.
fn find_spent_note(
    conn: &rusqlite::Connection,
    pool: Pool,
    fvk: &FullViewingKey,
    nf: &[u8; 32],
) -> anyhow::Result<Option<StoredNote>> {
    let table = match pool {
        Pool::Ironwood => "ironwood_received_notes",
        Pool::Orchard => "orchard_received_notes",
    };
    let sql = format!(
        "SELECT rn.diversifier, rn.value, rn.rho, rn.rseed, rn.commitment_tree_position,
                rn.recipient_key_scope, rn.note_version, t.mined_height, t.txid, rn.action_index
         FROM {table} rn JOIN transactions t ON t.id_tx = rn.transaction_id
         WHERE rn.nf = ?1"
    );
    let mut stmt = conn.prepare(&sql)?;
    let mut rows = stmt.query([nf.as_slice()])?;
    let Some(row) = rows.next()? else { return Ok(None) };
    let d: Vec<u8> = row.get(0)?;
    let value: i64 = row.get(1)?;
    let rho: Vec<u8> = row.get(2)?;
    let rseed: Vec<u8> = row.get(3)?;
    let position: Option<i64> = row.get(4)?;
    let scope: Option<i64> = row.get(5)?;
    let version: i64 = row.get(6)?;
    let mined_height: Option<u32> = row.get(7)?;
    let source_txid: Vec<u8> = row.get(8)?;
    let source_txid: [u8; 32] = source_txid.try_into().map_err(|_| anyhow!("bad txid"))?;
    let source_action: u32 = row.get(9)?;

    let d = Diversifier::from_bytes(d.try_into().map_err(|_| anyhow!("bad diversifier"))?);
    let scope = match scope {
        Some(1) => Scope::Internal,
        _ => Scope::External,
    };
    let rho = Option::<Rho>::from(Rho::from_bytes(&rho.try_into().map_err(|_| anyhow!("bad rho"))?))
        .ok_or_else(|| anyhow!("bad rho"))?;
    let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(
        rseed.try_into().map_err(|_| anyhow!("bad rseed"))?,
        &rho,
    ))
    .ok_or_else(|| anyhow!("bad rseed"))?;
    let version = match version {
        2 => NoteVersion::V2,
        3 => NoteVersion::V3,
        v => bail!("unknown note version {v}"),
    };
    let note = Option::<Note>::from(Note::from_parts(
        fvk.address(d, scope),
        NoteValue::from_raw(value as u64),
        rho,
        rseed,
        version,
    ))
    .ok_or_else(|| anyhow!("stored note does not reconstruct"))?;
    let position = position.ok_or_else(|| anyhow!("note has no tree position yet; sync the wallet"))?;
    Ok(Some(StoredNote { note, position: position as u64, mined_height, source_txid, source_action }))
}

fn search_checkpoints<S>(
    tree: &mut shardtree::ShardTree<S, 32, 16>,
    position: u64,
    anchor: orchard::Anchor,
    near: BlockHeight,
) -> Result<Option<MerklePath>, ShardTreeError<S::Error>>
where
    S: shardtree::store::ShardStore<H = orchard::tree::MerkleHashOrchard, CheckpointId = BlockHeight>,
{
    // Wallets choose an anchor a few blocks below the target height; search back from the
    // mined height.
    let mut h = u32::from(near);
    let lowest = h.saturating_sub(200);
    while h > lowest {
        let id = BlockHeight::from_u32(h);
        if let Some(root) = tree.root_at_checkpoint_id(&id)? {
            if orchard::Anchor::from(root) == anchor {
                return Ok(tree
                    .witness_at_checkpoint_id_caching(Position::from(position), &id)?
                    .map(MerklePath::from));
            }
        }
        h -= 1;
    }
    Ok(None)
}

/// Finds the wallet checkpoint whose root is `anchor` and returns the note's witness there.
fn witness_at_anchor(
    db: &mut WalletDb<rusqlite::Connection, Net, SystemClock, rand::rand_core::UnwrapErr<rand::rngs::SysRng>>,
    pool: Pool,
    position: u64,
    anchor: orchard::Anchor,
    near: BlockHeight,
) -> anyhow::Result<MerklePath> {
    type E = ShardTreeError<zcash_client_sqlite::wallet::commitment_tree::Error>;
    let path = match pool {
        Pool::Orchard => db.with_orchard_tree_mut::<_, _, E>(|t| search_checkpoints(t, position, anchor, near))?,
        Pool::Ironwood => db
            .with_ironwood_tree_mut::<_, _, E>(|t| search_checkpoints(t, position, anchor, near))?
            .flatten(),
    };
    path.ok_or_else(|| {
        anyhow!(
            "the wallet no longer has a checkpoint at this transaction's anchor. \
             Create receipts within ~100 blocks of sending, or rescan."
        )
    })
}

/// Whether to prove where each spent note came from, and whether to reveal its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceMode {
    /// Prove the source transaction output; keep the note's value hidden.
    HideValue,
    /// Prove the source transaction output and reveal the note's exact value.
    RevealValue,
}

/// How to obtain each spent note's Merkle path at the transaction's anchor.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WitnessSource {
    /// The wallet's own checkpoints, falling back to the chain if they were pruned.
    Auto,
    /// Always rebuild from public chain data.
    Chain,
}

#[allow(clippy::too_many_arguments)]
pub async fn create_receipt(
    wallet: &Path,
    identity: &Path,
    txid: [u8; 32],
    msg: &[u8],
    outputs: &[u32],
    pool: Option<Pool>,
    witness_source: WitnessSource,
    server: Option<&str>,
    prove_address: Option<&str>,
    prove_source: Option<SourceMode>,
    withhold_memo: bool,
) -> anyhow::Result<(Receipt, u32)> {
    let (net, seed) = decrypt_seed(wallet, identity)?;
    let coin_type = net.coin_type();
    let usk = UnifiedSpendingKey::from_seed(&net, seed.expose_secret(), zip32::AccountId::ZERO)
        .map_err(|e| anyhow!("deriving keys: {e:?}"))?;
    let sk: SpendingKey = usk.orchard().clone();
    let fvk = FullViewingKey::from(&sk);
    let prove_address = match prove_address {
        None => None,
        Some(ua) => {
            let raw = receipts_chain::chain::orchard_receiver_of(ua)?;
            let addr = Option::<orchard::Address>::from(orchard::Address::from_raw_address_bytes(&raw))
                .ok_or_else(|| anyhow!("invalid Orchard receiver in {ua}"))?;
            if fvk.scope_for_address(&addr).is_none() {
                bail!("{ua} is not an address of this wallet's account");
            }
            Some(addr)
        }
    };

    let db_path = wallet.join("data.sqlite");
    let mut db = WalletDb::for_path(&db_path, net, SystemClock, OsRng)?;
    let tx = db
        .get_transaction(TxId::from_bytes(txid))?
        .ok_or_else(|| anyhow!("this wallet has no record of that transaction; sync it first"))?;
    let conn = rusqlite::Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mined: Option<u32> = conn.query_row(
        "SELECT mined_height FROM transactions WHERE txid = ?1",
        [txid.as_slice()],
        |r| r.get(0),
    )?;
    let mined = mined.ok_or_else(|| anyhow!("transaction is not mined yet; wait and sync"))?;

    let bundle_of = |p: Pool| match p {
        Pool::Ironwood => tx.ironwood_bundle(),
        Pool::Orchard => tx.orchard_bundle(),
    };
    // The spends' pool: where this wallet's nullifiers are. After NU6.3 a wallet spending
    // Orchard notes pays into Ironwood outputs, so spends and outputs can be in different pools.
    let spends_in = |p: Pool| -> anyhow::Result<bool> {
        let Some(b) = bundle_of(p) else { return Ok(false) };
        for a in b.actions() {
            if find_spent_note(&conn, p, &fvk, &a.nullifier().to_bytes())?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    };
    let pool = match pool {
        Some(p) => p,
        None if spends_in(Pool::Ironwood)? => Pool::Ironwood,
        None if spends_in(Pool::Orchard)? => Pool::Orchard,
        None => bail!("this wallet did not spend any notes in that transaction, so it cannot prove it sent it"),
    };
    let bundle = bundle_of(pool).ok_or_else(|| anyhow!("transaction has no {pool:?} bundle"))?;

    // Spends: every action that spent one of our notes.
    let mut spends = Vec::new();
    for (i, action) in bundle.actions().iter().enumerate() {
        if let Some(stored) = find_spent_note(&conn, pool, &fvk, &action.nullifier().to_bytes())? {
            let local = if witness_source == WitnessSource::Auto {
                witness_at_anchor(&mut db, pool, stored.position, *bundle.anchor(), BlockHeight::from_u32(mined)).ok()
            } else {
                None
            };
            let path = match local {
                Some(p) => p,
                None => {
                    let h = stored
                        .mined_height
                        .ok_or_else(|| anyhow!("the spent note's block height is unknown; sync the wallet"))?;
                    eprintln!("Rebuilding the note's Merkle path from chain data (blocks {}..{mined})…", receipts_chain::chain::witness_window_start(h));
                    receipts_chain::chain::rebuild_witness(net, server, pool, stored.note.commitment().into(), h, *bundle.anchor(), mined).await?
                }
            };
            let source = match prove_source {
                None => None,
                Some(mode) => {
                    // Read the source output's cmx from the wallet's own copy of that transaction.
                    // A wallet that found the note in compact blocks may not keep the full
                    // transaction; then the note's own commitment stands in, with no network
                    // request (so no server learns which transaction is being proven), and every
                    // verifier checks it against the chain anyway.
                    let cmx = match db.get_transaction(TxId::from_bytes(stored.source_txid))? {
                        Some(stx) => {
                            let sb = match pool {
                                Pool::Ironwood => stx.ironwood_bundle(),
                                Pool::Orchard => stx.orchard_bundle(),
                            };
                            sb.and_then(|b| receipts_core::output_cmx(b, stored.source_action))
                                .ok_or_else(|| anyhow!("the source transaction has no such output"))?
                        }
                        None => orchard::note::ExtractedNoteCommitment::from(stored.note.commitment()).to_bytes(),
                    };
                    Some(receipts_core::SourceWitness { txid: stored.source_txid, index: stored.source_action, cmx, reveal_value: mode == SourceMode::RevealValue })
                }
            };
            spends.push(SpendWitness { index: i, sk: sk.clone(), note: stored.note, merkle_path: path, prove_address, source });
        }
    }
    if spends.is_empty() {
        bail!("this wallet did not spend any notes in that transaction, so it cannot prove it sent it");
    }

    // Outputs: by default, everything we sent to someone else (recoverable with our external
    // OVK and not decryptable by our own incoming keys).
    let ovk = fvk.to_ovk(Scope::External);
    let ivks = [
        PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External)),
        PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::Internal)),
    ];
    let ours = |p: Pool, a: &orchard::Action<_>| {
        ivks.iter().any(|ivk| match p {
            Pool::Orchard => try_note_decryption(&OrchardDomain::for_action(a), ivk, a).is_some(),
            Pool::Ironwood => try_note_decryption(&IronwoodDomain::for_action(a), ivk, a).is_some(),
        })
    };
    let sent_to_others = |p: Pool| -> Vec<(usize, orchard::keys::OutgoingViewingKey)> {
        bundle_of(p)
            .map(|b| {
                b.actions()
                    .iter()
                    .enumerate()
                    .filter(|(_, a)| !ours(p, a) && b.recover_output_with_ovk_v(p, a, &ovk))
                    .map(|(i, _)| (i, ovk.clone()))
                    .collect()
            })
            .unwrap_or_default()
    };
    // Outputs: in the spends' pool, or else in the other pool (a cross-pool payment).
    let other = if pool == Pool::Orchard { Pool::Ironwood } else { Pool::Orchard };
    let (output_pool, selected) = if !outputs.is_empty() {
        (pool, outputs.iter().map(|&i| (i as usize, ovk.clone())).collect())
    } else {
        let same = sent_to_others(pool);
        if same.is_empty() && bundle_of(other).is_some() {
            let cross = sent_to_others(other);
            if cross.is_empty() { (pool, same) } else { (other, cross) }
        } else {
            (pool, same)
        }
    };
    if output_pool != pool {
        eprintln!("This payment spent {pool:?} notes into {output_pool:?} outputs; the receipt covers both (format v3).");
    }

    eprintln!("Building spend-authority proof(s)…");
    let pk = receipts_core::proving_key();
    let out_bundle = bundle_of(output_pool).ok_or_else(|| anyhow!("transaction has no {output_pool:?} bundle"))?;
    // With `withhold_memo`, every disclosed output shows its recipient and value only.
    let (with_memo, without): (&[_], &[_]) = if withhold_memo { (&[], &selected) } else { (&selected, &[]) };
    Ok((receipts_core::create_cross_ext(&pk, coin_type, pool, bundle, output_pool, out_bundle, txid, msg, with_memo, without, &spends, OsRng)?, mined))
}

trait RecoverExt {
    fn recover_output_with_ovk_v<A>(&self, pool: Pool, a: &orchard::Action<A>, ovk: &orchard::keys::OutgoingViewingKey) -> bool;
}

impl<T: orchard::bundle::Authorization, V> RecoverExt for orchard::Bundle<T, V> {
    fn recover_output_with_ovk_v<A>(&self, pool: Pool, a: &orchard::Action<A>, ovk: &orchard::keys::OutgoingViewingKey) -> bool {
        use zcash_note_encryption::try_output_recovery_with_ovk;
        let out = &a.encrypted_note().out_ciphertext;
        match pool {
            Pool::Orchard => try_output_recovery_with_ovk(&OrchardDomain::for_action(a), ovk, a, a.cv_net(), out).is_some(),
            Pool::Ironwood => try_output_recovery_with_ovk(&IronwoodDomain::for_action(a), ovk, a, a.cv_net(), out).is_some(),
        }
    }
}

/// Signs in to `domain` with `nonce`, proving control of `address` (default: the account's
/// first Orchard address). No transaction is made and nothing is written to the wallet.
pub fn sign_in(wallet: &Path, identity: &Path, domain: &str, nonce: &str, address: Option<&str>) -> anyhow::Result<(receipts_core::signin::SignIn, String)> {
    let (net, seed) = decrypt_seed(wallet, identity)?;
    let usk = UnifiedSpendingKey::from_seed(&net, seed.expose_secret(), zip32::AccountId::ZERO)
        .map_err(|e| anyhow!("deriving keys: {e:?}"))?;
    let sk: SpendingKey = usk.orchard().clone();
    let fvk = FullViewingKey::from(&sk);
    let addr = match address {
        None => fvk.address_at(0u32, Scope::External),
        Some(ua) => {
            let raw = receipts_chain::chain::orchard_receiver_of(ua)?;
            let a = Option::<orchard::Address>::from(orchard::Address::from_raw_address_bytes(&raw))
                .ok_or_else(|| anyhow!("invalid Orchard receiver in {ua}"))?;
            if fvk.scope_for_address(&a).is_none() {
                bail!("{ua} is not an address of this wallet's account");
            }
            a
        }
    };
    let issued_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let s = receipts_core::signin::sign_in(&receipts_core::proving_key(), net.coin_type(), domain, nonce, issued_at, &sk, addr, OsRng)?;
    Ok((s, receipts_chain::chain::encode_orchard_receiver(net, addr.to_raw_address_bytes())))
}

/// A shop's proof-request link: `…?request=<challenge>&to=<payee>&min=<zatoshis>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestLink {
    pub code: String,
    pub to: Option<String>,
    pub min: u64,
}

/// Parses a proof-request link. Each parameter may appear once; the payee must have an Orchard
/// receiver (so a receipt can prove it).
pub fn parse_request_link(link: &str) -> anyhow::Result<RequestLink> {
    let query = link.split('#').next().unwrap_or(link).split_once('?').map(|(_, q)| q).unwrap_or("");
    let (mut code, mut to, mut min) = (None, None, None);
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v);
        let slot = match k {
            "request" => &mut code,
            "to" => &mut to,
            "min" => &mut min,
            _ => continue,
        };
        if slot.replace(v).is_some() {
            bail!("the link has `{k}` more than once");
        }
    }
    let code = code.ok_or_else(|| anyhow!("that link has no request code"))?;
    if !(6..=64).contains(&code.len()) || !code.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("malformed request code");
    }
    if let Some(to) = &to {
        receipts_chain::chain::orchard_receiver_of(to).map_err(|e| anyhow!("the request's payee can't be proven with a receipt (needs an Orchard/Ironwood receiver): {e}"))?;
    }
    let min = match min {
        None => 0,
        Some(m) => m.parse().map_err(|_| anyhow!("bad min amount in request"))?,
    };
    Ok(RequestLink { code, to, min })
}

/// Checks that `receipt` answers `req` against the chain: it pays the requested address at least
/// the requested amount. Returns what it paid that address.
pub async fn check_answers(receipt: &Receipt, req: &RequestLink, server: Option<&str>, regtest: Option<&Path>) -> anyhow::Result<u64> {
    let report = receipts_chain::chain::verify_against_chain(receipt, server, regtest).await?;
    let paid: u64 = match &req.to {
        Some(to) => {
            let want = receipts_chain::chain::orchard_receiver_of(to)?;
            report.outputs.iter().filter(|o| o.recipient_raw == want).map(|o| o.zatoshis).sum()
        }
        None => report.outputs.iter().map(|o| o.zatoshis).sum(),
    };
    if req.to.is_some() && paid == 0 {
        bail!("this transaction paid nothing to the requested address");
    }
    if paid < req.min {
        bail!("this transaction paid {} ZEC, less than the requested {}", receipts_chain::chain::zec(paid), receipts_chain::chain::zec(req.min));
    }
    Ok(paid)
}

/// Checks an address can receive a refund that a receipt can prove (an Orchard receiver).
pub fn check_refund_address(addr: &str) -> anyhow::Result<()> {
    receipts_chain::chain::orchard_receiver_of(addr).map(|_| ()).map_err(|e| anyhow!("refund address: {e}"))
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            // Slice bytes, not the str: "%é" must not panic on a char boundary.
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn request_links() {
        let to = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa";
        let r = super::parse_request_link(&format!("https://shop/verify/?request=00aa11bb&to={to}&min=5")).unwrap();
        assert_eq!((r.code.as_str(), r.to.as_deref(), r.min), ("00aa11bb", Some(to), 5));
        // A percent sign before a multi-byte character is refused, never a panic.
        assert!(super::parse_request_link("https://shop/?request=00aa11bb&to=%\u{e9}x").is_err());
        assert!(super::parse_request_link("https://x/?request=00aa11bb&request=ffff0000").is_err(), "duplicates refused");
        assert!(super::parse_request_link("https://x/?request=00aa11bb&to=tmEZhbWHTpdKMw5it8YDspUXSMGQyFwovpU").is_err(), "unprovable payee refused");
        assert!(super::parse_request_link("https://x/?request=zz").is_err());
        assert!(super::check_refund_address("not-an-address").is_err());
    }
}
