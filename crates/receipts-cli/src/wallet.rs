//! Reading a zcash-devtool wallet (keys.toml + data.sqlite) to build a receipt.
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
use rand::rngs::OsRng;
use crate::net::{Heights, Net};
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

fn decrypt_seed(wallet: &Path, identity: &Path) -> anyhow::Result<(Net, secrecy::SecretVec<u8>)> {
    let keys: KeysToml = toml::from_str(&std::fs::read_to_string(wallet.join("keys.toml"))?)?;
    let net = match keys.network.as_deref().unwrap_or("test") {
        "main" => Net::Main,
        "test" => Net::Test,
        "regtest" => Net::Regtest(
            keys.activation_heights
                .as_ref()
                .ok_or_else(|| anyhow!("regtest wallet has no activation heights"))?
                .to_local(),
        ),
        other => bail!("unsupported network {other}"),
    };
    let ct = keys.mnemonic.ok_or_else(|| anyhow!("this wallet has no mnemonic (viewing-only)"))?;
    let ids = age::IdentityFile::from_file(identity.to_string_lossy().into_owned())
        .context("reading age identity")?
        .into_identities()?;
    let decryptor = age::Decryptor::new(age::armor::ArmoredReader::new(ct.as_bytes()))?;
    let mut phrase = String::new();
    decryptor
        .decrypt(ids.iter().map(|i| i.as_ref() as &dyn age::Identity))?
        .read_to_string(&mut phrase)?;
    let mnemonic = <bip0039::Mnemonic<bip0039::English>>::from_phrase(phrase.trim())
        .map_err(|e| anyhow!("bad mnemonic: {e}"))?;
    let seed = secrecy::SecretVec::new(mnemonic.to_seed("").to_vec());
    Ok((net, seed))
}

struct StoredNote {
    note: Note,
    position: u64,
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
        "SELECT diversifier, value, rho, rseed, commitment_tree_position, recipient_key_scope, note_version
         FROM {table} WHERE nf = ?1"
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
    Ok(Some(StoredNote { note, position: position as u64 }))
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
    db: &mut WalletDb<rusqlite::Connection, Net, SystemClock, OsRng>,
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

pub fn create_receipt(
    wallet: &Path,
    identity: &Path,
    txid: [u8; 32],
    msg: &[u8],
    outputs: &[u32],
    pool: Option<Pool>,
) -> anyhow::Result<Receipt> {
    let (net, seed) = decrypt_seed(wallet, identity)?;
    let coin_type = net.coin_type();
    let usk = UnifiedSpendingKey::from_seed(&net, seed.expose_secret(), zip32::AccountId::ZERO)
        .map_err(|e| anyhow!("deriving keys: {e:?}"))?;
    let sk: SpendingKey = *usk.orchard();
    let fvk = FullViewingKey::from(&sk);

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

    let pool = pool.unwrap_or(if tx.ironwood_bundle().is_some() { Pool::Ironwood } else { Pool::Orchard });
    let bundle = match pool {
        Pool::Ironwood => tx.ironwood_bundle(),
        Pool::Orchard => tx.orchard_bundle(),
    }
    .ok_or_else(|| anyhow!("transaction has no {pool:?} bundle"))?;

    // Spends: every action that spent one of our notes.
    let mut spends = Vec::new();
    for (i, action) in bundle.actions().iter().enumerate() {
        if let Some(stored) = find_spent_note(&conn, pool, &fvk, &action.nullifier().to_bytes())? {
            let path = witness_at_anchor(&mut db, pool, stored.position, *bundle.anchor(), BlockHeight::from_u32(mined))?;
            spends.push(SpendWitness { index: i, sk, note: stored.note, merkle_path: path });
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
    let ours = |a: &orchard::Action<_>| {
        ivks.iter().any(|ivk| match pool {
            Pool::Orchard => try_note_decryption(&OrchardDomain::for_action(a), ivk, a).is_some(),
            Pool::Ironwood => try_note_decryption(&IronwoodDomain::for_action(a), ivk, a).is_some(),
        })
    };
    let selected: Vec<(usize, orchard::keys::OutgoingViewingKey)> = if outputs.is_empty() {
        bundle
            .actions()
            .iter()
            .enumerate()
            .filter(|(_, a)| !ours(a) && bundle.recover_output_with_ovk_v(pool, a, &ovk))
            .map(|(i, _)| (i, ovk.clone()))
            .collect()
    } else {
        outputs.iter().map(|&i| (i as usize, ovk.clone())).collect()
    };

    eprintln!("Building spend-authority proof(s)…");
    let pk = receipts_core::proving_key();
    Ok(receipts_core::create(&pk, coin_type, pool, txid, bundle, msg, &selected, &spends, OsRng)?)
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
