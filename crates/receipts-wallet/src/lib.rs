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
    keys::{Diversifier, FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::{NoteVersion, RandomSeed, Rho},
    note_encryption::{IronwoodDomain, OrchardDomain},
    tree::MerklePath,
    value::NoteValue,
    Note,
};
static ACCOUNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Chooses the ZIP 32 account (default 0) whose keys every function here derives. Notes are found
/// by trial decryption with that account's keys, so a multi-account wallet works one account at
/// a time.
pub fn set_account(index: u32) -> anyhow::Result<()> {
    zip32::AccountId::try_from(index).map_err(|_| anyhow!("account {index} is not a valid ZIP 32 account index"))?;
    ACCOUNT.store(index, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

fn account() -> zip32::AccountId {
    zip32::AccountId::try_from(ACCOUNT.load(std::sync::atomic::Ordering::Relaxed)).expect("checked by set_account")
}

/// `rand` 0.10 replaced the infallible `OsRng` with the fallible `SysRng`.
#[allow(non_upper_case_globals)]
const OsRng: rand::rand_core::UnwrapErr<rand::rngs::SysRng> = rand::rand_core::UnwrapErr(rand::rngs::SysRng);
use receipts_chain::net::{Heights, Net};
use receipts_core::{Pool, PreparedReceipt, Receipt, ViewingSpendWitness};
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
    let usk = UnifiedSpendingKey::from_seed(&net, seed.expose_secret(), account())
        .map_err(|e| anyhow!("deriving keys: {e:?}"))?;
    let sk: SpendingKey = usk.orchard().clone();
    let (prepared, mined) = prepare_with(wallet, net, FullViewingKey::from(&sk), txid, msg, outputs, pool, witness_source, server, prove_address, prove_source, withhold_memo).await?;
    let asks = vec![SpendAuthorizingKey::from(&sk); prepared.unsigned().spends.len()];
    Ok((prepared.sign(&asks, OsRng)?, mined))
}

/// Makes every proof of a receipt with the wallet's viewing key only (the identity file is not
/// read), for signing on another machine with [`sign_prepared`]. The viewing key comes from the
/// wallet database, so a viewing-only wallet works too.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_receipt(
    wallet: &Path,
    txid: [u8; 32],
    msg: &[u8],
    outputs: &[u32],
    pool: Option<Pool>,
    witness_source: WitnessSource,
    server: Option<&str>,
    prove_address: Option<&str>,
    prove_source: Option<SourceMode>,
    withhold_memo: bool,
) -> anyhow::Result<(PreparedReceipt, u32)> {
    let (net, fvk) = viewing_key(wallet)?;
    prepare_with(wallet, net, fvk, txid, msg, outputs, pool, witness_source, server, prove_address, prove_source, withhold_memo).await
}

/// Signs a prepared receipt with the wallet's spend authorizing key. Needs only `keys.toml`
/// and the identity, not the wallet database or a network connection. The digest is computed
/// here from the unsigned receipt, and each spend's `rk` is checked against this key first.
pub fn sign_prepared(wallet: &Path, identity: &Path, prepared: PreparedReceipt) -> anyhow::Result<Receipt> {
    let (net, seed) = decrypt_seed(wallet, identity)?;
    if prepared.unsigned().coin_type != net.coin_type() {
        bail!("this receipt is for another network than the wallet");
    }
    let usk = UnifiedSpendingKey::from_seed(&net, seed.expose_secret(), account()).map_err(|e| anyhow!("deriving keys: {e:?}"))?;
    let asks = vec![SpendAuthorizingKey::from(usk.orchard()); prepared.unsigned().spends.len()];
    prepared.sign(&asks, OsRng).map_err(|e| match e {
        receipts_core::Error::BadSignature(_) => anyhow!("this wallet's key did not make these spends"),
        e => e.into(),
    })
}

/// The account's Orchard full viewing key, from the wallet database.
fn viewing_key(wallet: &Path) -> anyhow::Result<(Net, FullViewingKey)> {
    let net = wallet_network(wallet)?;
    let conn = rusqlite::Connection::open_with_flags(wallet.join("data.sqlite"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let ufvk: String = conn
        .query_row("SELECT ufvk FROM accounts WHERE hd_account_index = ?1 AND ufvk IS NOT NULL", [u32::from(account())], |r| r.get(0))
        .context("this wallet database has no viewing key for the account")?;
    let ufvk = zcash_keys::keys::UnifiedFullViewingKey::decode(&net, &ufvk).map_err(|e| anyhow!("decoding the wallet's viewing key: {e}"))?;
    let fvk = ufvk.orchard().cloned().ok_or_else(|| anyhow!("the wallet's viewing key has no Orchard part"))?;
    Ok((net, fvk))
}

/// A spent note this account owns, found in the wallet database or by scanning the chain.
struct SpentNote {
    note: Note,
    /// Tree position, when the wallet database knows it (lets its checkpoints give the path).
    position: Option<u64>,
    mined_height: Option<u32>,
    source_txid: [u8; 32],
    source_action: u32,
    /// The commitment the source transaction published for this note.
    source_cmx: [u8; 32],
}

/// The account's spent notes in `tx`, by pool and nullifier, from the wallet database.
fn spent_notes_in_db(
    db: &WalletDb<rusqlite::Connection, Net, SystemClock, rand::rand_core::UnwrapErr<rand::rngs::SysRng>>,
    conn: &rusqlite::Connection,
    fvk: &FullViewingKey,
    tx: &zcash_primitives::transaction::Transaction,
) -> anyhow::Result<std::collections::HashMap<(Pool, [u8; 32]), SpentNote>> {
    let mut found = std::collections::HashMap::new();
    for pool in [Pool::Orchard, Pool::Ironwood] {
        let Some(b) = (match pool {
            Pool::Ironwood => tx.ironwood_bundle(),
            Pool::Orchard => tx.orchard_bundle(),
        }) else {
            continue;
        };
        for a in b.actions() {
            let nf = a.nullifier().to_bytes();
            let Some(stored) = find_spent_note(conn, pool, fvk, &nf)? else { continue };
            // Read the source output's cmx from the wallet's own copy of that transaction. A
            // wallet that found the note in compact blocks may not keep the full transaction;
            // then the note's own commitment stands in, with no network request (so no server
            // learns which transaction is being proven), and every verifier checks it anyway.
            let source_cmx = match db.get_transaction(TxId::from_bytes(stored.source_txid))? {
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
            found.insert(
                (pool, nf),
                SpentNote { note: stored.note, position: Some(stored.position), mined_height: stored.mined_height, source_txid: stored.source_txid, source_action: stored.source_action, source_cmx },
            );
        }
    }
    Ok(found)
}

#[allow(clippy::too_many_arguments)]
async fn prepare_with(
    wallet: &Path,
    net: Net,
    fvk: FullViewingKey,
    txid: [u8; 32],
    msg: &[u8],
    outputs: &[u32],
    pool: Option<Pool>,
    witness_source: WitnessSource,
    server: Option<&str>,
    prove_address: Option<&str>,
    prove_source: Option<SourceMode>,
    withhold_memo: bool,
) -> anyhow::Result<(PreparedReceipt, u32)> {
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
    let spent = spent_notes_in_db(&db, &conn, &fvk, &tx)?;
    let mut local = |pool: Pool, position: u64, anchor: orchard::Anchor| {
        if witness_source == WitnessSource::Auto {
            witness_at_anchor(&mut db, pool, position, anchor, BlockHeight::from_u32(mined)).ok()
        } else {
            None
        }
    };
    build_prepared(net, &fvk, txid, &tx, mined, &spent, &mut local, msg, outputs, pool, server, prove_address, prove_source, withhold_memo).await
}

/// A wallet held as keys alone, such as the seed phrase or viewing key of Zodl, Zingo or
/// YWallet: its notes are found by scanning compact blocks from its birthday, so no wallet
/// database is needed.
pub struct KeysWallet {
    pub net: Net,
    fvk: FullViewingKey,
    sk: Option<SpendingKey>,
    /// The wallet's birthday height: no note of it is older.
    pub birthday: u32,
}

impl KeysWallet {
    /// From a BIP 39 seed phrase (ZIP 32 account [`set_account`], default 0).
    pub fn from_phrase(net: Net, phrase: &str, birthday: u32) -> anyhow::Result<Self> {
        let phrase = secrecy::SecretString::new(phrase.split_whitespace().collect::<Vec<_>>().join(" "));
        let mnemonic = <bip0039::Mnemonic<bip0039::English>>::from_phrase(phrase.expose_secret())
            // Never echo the error: it can quote a word of the phrase.
            .map_err(|_| anyhow!("that doesn't decode as a BIP 39 seed phrase"))?;
        let seed = secrecy::SecretVec::new(mnemonic.to_seed("").to_vec());
        let usk = UnifiedSpendingKey::from_seed(&net, seed.expose_secret(), account()).map_err(|e| anyhow!("deriving keys: {e:?}"))?;
        let sk = usk.orchard().clone();
        Ok(KeysWallet { net, fvk: FullViewingKey::from(&sk), sk: Some(sk), birthday })
    }

    /// From a unified full viewing key: makes the proofs, not the signature.
    pub fn from_ufvk(net: Net, ufvk: &str, birthday: u32) -> anyhow::Result<Self> {
        let ufvk = zcash_keys::keys::UnifiedFullViewingKey::decode(&net, ufvk.trim()).map_err(|e| anyhow!("that isn't a unified full viewing key for {}: {e}", net.name()))?;
        let fvk = ufvk.orchard().cloned().ok_or_else(|| anyhow!("that viewing key has no Orchard part"))?;
        Ok(KeysWallet { net, fvk, sk: None, birthday })
    }

    /// Signs a prepared receipt with this wallet's spend key (only when made from a phrase).
    pub fn sign(&self, prepared: PreparedReceipt) -> anyhow::Result<Receipt> {
        let sk = self.sk.as_ref().ok_or_else(|| anyhow!("a viewing key can't sign; sign with the seed phrase"))?;
        if prepared.unsigned().coin_type != self.net.coin_type() {
            bail!("this receipt is for another network than the wallet");
        }
        let asks = vec![SpendAuthorizingKey::from(sk); prepared.unsigned().spends.len()];
        prepared.sign(&asks, OsRng).map_err(|e| match e {
            receipts_core::Error::BadSignature(_) => anyhow!("this wallet's key did not make these spends"),
            e => e.into(),
        })
    }
}

/// Like [`prepare_receipt`], for a [`KeysWallet`]: fetches the payment (among its block's
/// transactions when `height` is given), then finds the spent notes by trial-decrypting every
/// Orchard and Ironwood output from the wallet's birthday up to the payment.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_receipt_from_keys(
    w: &KeysWallet,
    txid: [u8; 32],
    height: Option<u32>,
    msg: &[u8],
    outputs: &[u32],
    pool: Option<Pool>,
    server: Option<&str>,
    prove_address: Option<&str>,
    prove_source: Option<SourceMode>,
    withhold_memo: bool,
) -> anyhow::Result<(PreparedReceipt, u32)> {
    let (tx, mined) = match height {
        Some(h) => {
            let (tx, mined, _) = receipts_chain::chain::fetch_mined_tx_in_block(w.net, server, txid, h).await?;
            (tx, mined)
        }
        None => {
            eprintln!("Fetching the payment by its txid (pass --height <block> to fetch it among its block's transactions instead).");
            receipts_chain::chain::fetch_mined_tx(w.net, server, txid).await?
        }
    };
    if w.birthday >= mined {
        bail!("the birthday {} is not before the payment's block {mined}", w.birthday);
    }
    let mut wanted = std::collections::HashSet::new();
    for (pool, b) in [(Pool::Orchard, tx.orchard_bundle()), (Pool::Ironwood, tx.ironwood_bundle())] {
        for a in b.map(|b| b.actions().iter().collect::<Vec<_>>()).unwrap_or_default() {
            wanted.insert((pool, a.nullifier().to_bytes()));
        }
    }
    let spent = scan_for_spent_notes(w, server, mined, &wanted).await?;
    if spent.is_empty() {
        bail!("none of this wallet's notes from block {} on were spent in that transaction (wrong wallet, account or birthday?)", w.birthday);
    }
    let mut no_local = |_: Pool, _: u64, _: orchard::Anchor| None;
    build_prepared(w.net, &w.fvk, txid, &tx, mined, &spent, &mut no_local, msg, outputs, pool, server, prove_address, prove_source, withhold_memo).await
}

/// Trial-decrypts the compact blocks from the birthday up to (not including) `mined` and keeps
/// the notes whose nullifiers are in `wanted`. The server sees the block range only.
async fn scan_for_spent_notes(
    w: &KeysWallet,
    server: Option<&str>,
    mined: u32,
    wanted: &std::collections::HashSet<(Pool, [u8; 32])>,
) -> anyhow::Result<std::collections::HashMap<(Pool, [u8; 32]), SpentNote>> {
    use zcash_client_backend::proto::service::{BlockId, BlockRange, PoolType};
    use zcash_note_encryption::try_compact_note_decryption;
    let ivks = [
        PreparedIncomingViewingKey::new(&w.fvk.to_ivk(Scope::External)),
        PreparedIncomingViewingKey::new(&w.fvk.to_ivk(Scope::Internal)),
    ];
    let mut client = receipts_chain::chain::connect(server.unwrap_or(w.net.default_server())).await?;
    eprintln!("Scanning blocks {}..{} for this wallet's notes (trial decryption, done here)…", w.birthday, mined - 1);
    let mut stream = client
        .get_block_range(BlockRange {
            start: Some(BlockId { height: u64::from(w.birthday), hash: vec![] }),
            end: Some(BlockId { height: u64::from(mined - 1), hash: vec![] }),
            pool_types: vec![PoolType::Orchard as i32, PoolType::Ironwood as i32],
        })
        .await
        .map_err(|e| anyhow!("block range: {}", e.message()))?
        .into_inner();
    let mut found = std::collections::HashMap::new();
    while let Some(block) = stream.message().await? {
        for ctx in &block.vtx {
            let source_txid: [u8; 32] = ctx.txid.as_slice().try_into().map_err(|_| anyhow!("bad txid in compact block"))?;
            for (pool, actions) in [(Pool::Orchard, &ctx.actions), (Pool::Ironwood, &ctx.ironwood_actions)] {
                for (i, ca) in actions.iter().enumerate() {
                    let Ok(action) = orchard::note_encryption::CompactAction::try_from(ca) else { continue };
                    let note = ivks.iter().find_map(|ivk| match pool {
                        Pool::Orchard => try_compact_note_decryption(&OrchardDomain::for_compact_action(&action), ivk, &action),
                        Pool::Ironwood => try_compact_note_decryption(&IronwoodDomain::for_compact_action(&action), ivk, &action),
                    });
                    let Some((note, _)) = note else { continue };
                    let nf = note.nullifier(&w.fvk).to_bytes();
                    if wanted.contains(&(pool, nf)) {
                        let source_cmx = orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes();
                        found.insert((pool, nf), SpentNote { note, position: None, mined_height: Some(block.height as u32), source_txid, source_action: i as u32, source_cmx });
                    }
                }
            }
        }
    }
    Ok(found)
}

/// Everything after the spent notes are known, whichever way they were found.
#[allow(clippy::too_many_arguments)]
async fn build_prepared(
    net: Net,
    fvk: &FullViewingKey,
    txid: [u8; 32],
    tx: &zcash_primitives::transaction::Transaction,
    mined: u32,
    spent: &std::collections::HashMap<(Pool, [u8; 32]), SpentNote>,
    local_witness: &mut dyn FnMut(Pool, u64, orchard::Anchor) -> Option<MerklePath>,
    msg: &[u8],
    outputs: &[u32],
    pool: Option<Pool>,
    server: Option<&str>,
    prove_address: Option<&str>,
    prove_source: Option<SourceMode>,
    withhold_memo: bool,
) -> anyhow::Result<(PreparedReceipt, u32)> {
    let coin_type = net.coin_type();
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
    let bundle_of = |p: Pool| match p {
        Pool::Ironwood => tx.ironwood_bundle(),
        Pool::Orchard => tx.orchard_bundle(),
    };
    // The spends' pool: where this wallet's nullifiers are. After NU6.3 a wallet spending
    // Orchard notes pays into Ironwood outputs, so spends and outputs can be in different pools.
    let spends_in = |p: Pool| spent.keys().any(|(q, _)| *q == p);
    let pool = match pool {
        Some(p) => p,
        None if spends_in(Pool::Ironwood) => Pool::Ironwood,
        None if spends_in(Pool::Orchard) => Pool::Orchard,
        None => bail!("this wallet did not spend any notes in that transaction, so it cannot prove it sent it"),
    };
    let bundle = bundle_of(pool).ok_or_else(|| anyhow!("transaction has no {pool:?} bundle"))?;

    // Spends: every action that spent one of our notes.
    let mut spends = Vec::new();
    for (i, action) in bundle.actions().iter().enumerate() {
        let Some(stored) = spent.get(&(pool, action.nullifier().to_bytes())) else { continue };
        let path = match stored.position.and_then(|p| local_witness(pool, p, *bundle.anchor())) {
            Some(p) => p,
            None => {
                let h = stored.mined_height.ok_or_else(|| anyhow!("the spent note's block height is unknown; sync the wallet"))?;
                eprintln!(
                    "Rebuilding the note's Merkle path from chain data (blocks {}..={}, whole 1,000-block windows)…",
                    receipts_chain::chain::witness_window_start(h),
                    receipts_chain::chain::witness_window_end(mined)
                );
                receipts_chain::chain::rebuild_witness(net, server, pool, stored.note.commitment().into(), h, *bundle.anchor(), mined).await?
            }
        };
        let source = prove_source.map(|mode| receipts_core::SourceWitness {
            txid: stored.source_txid,
            index: stored.source_action,
            cmx: stored.source_cmx,
            reveal_value: mode == SourceMode::RevealValue,
        });
        spends.push(ViewingSpendWitness { index: i, fvk: fvk.clone(), note: stored.note, merkle_path: path, prove_address, source });
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
    Ok((receipts_core::prepare(&pk, coin_type, pool, bundle, output_pool, out_bundle, txid, msg, with_memo, without, &spends, OsRng)?, mined))
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

/// The block the wallet recorded `txid` in, once a sync has seen it. Waiting on this (instead of
/// asking a chain server for the txid) keeps the server from learning which transaction the
/// payer is waiting for: a sync downloads whole blocks.
pub fn mined_height_in_wallet(wallet: &Path, txid: [u8; 32]) -> Option<u32> {
    let conn = rusqlite::Connection::open_with_flags(wallet.join("data.sqlite"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()?;
    conn.query_row("SELECT mined_height FROM transactions WHERE txid = ?1", [txid.as_slice()], |r| r.get::<_, Option<u32>>(0)).ok().flatten()
}

/// A fresh Orchard address of the wallet's account (a random diversifier), for a `refund-to:`
/// line: reusing one address in every receipt would let merchants link the receipts. The wallet
/// finds payments to it like any other of its addresses (Orchard decryption doesn't depend on
/// the diversifier). Needs only the viewing key.
pub fn fresh_address(wallet: &Path) -> anyhow::Result<String> {
    let (net, fvk) = viewing_key(wallet)?;
    let mut index = [0u8; 11];
    let mut rng = OsRng;
    rand::Rng::fill_bytes(&mut rng, &mut index);
    let addr = fvk.address_at(orchard::keys::DiversifierIndex::from(index), Scope::External);
    Ok(receipts_chain::chain::encode_orchard_receiver(net, addr.to_raw_address_bytes()))
}

/// Signs in to `domain` with `nonce`, proving control of `address` (default: an address of the
/// account derived from the domain, so every site sees a different one and sites can't link a
/// user by it; the same site sees the same address each time). No transaction is made and
/// nothing is written to the wallet.
pub fn sign_in(wallet: &Path, identity: &Path, domain: &str, nonce: &str, address: Option<&str>) -> anyhow::Result<(receipts_core::signin::SignIn, String)> {
    let (net, seed) = decrypt_seed(wallet, identity)?;
    let usk = UnifiedSpendingKey::from_seed(&net, seed.expose_secret(), account())
        .map_err(|e| anyhow!("deriving keys: {e:?}"))?;
    let sk: SpendingKey = usk.orchard().clone();
    let fvk = FullViewingKey::from(&sk);
    let addr = match address {
        None => {
            // Normalized, so `Shop.Example`, `shop.example.` and `shop.example:443` are one site.
            let site = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            let site = site.strip_suffix(":443").unwrap_or(&site);
            let h = blake2b_simd::Params::new().hash_length(32).personal(b"ReceiptsSignInDv").hash(site.as_bytes());
            let index: [u8; 11] = h.as_bytes()[..11].try_into().expect("11 bytes");
            fvk.address_at(orchard::keys::DiversifierIndex::from(index), Scope::External)
        }
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

/// Makes an incoming receipt: this wallet proves it received outputs of `txid` (all of them at
/// one address, or the given action indices). Returns it and the transaction's block height.
pub async fn create_incoming_receipt(wallet: &Path, identity: &Path, txid: [u8; 32], msg: &[u8], outputs: &[u32], pool: Option<Pool>, server: Option<&str>) -> anyhow::Result<(receipts_core::incoming::IncomingReceipt, u32)> {
    let (net, seed) = decrypt_seed(wallet, identity)?;
    let usk = UnifiedSpendingKey::from_seed(&net, seed.expose_secret(), account()).map_err(|e| anyhow!("deriving keys: {e:?}"))?;
    let sk: SpendingKey = usk.orchard().clone();
    let db_path = wallet.join("data.sqlite");
    let db = WalletDb::for_path(&db_path, net, SystemClock, OsRng)?;
    // The wallet's own copy if it kept one; else the chain (the server then learns the txid).
    let (tx, height) = match db.get_transaction(TxId::from_bytes(txid))? {
        Some(tx) => {
            let conn = rusqlite::Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let h: Option<u32> = conn.query_row("SELECT mined_height FROM transactions WHERE txid = ?1", [txid.as_slice()], |r| r.get(0))?;
            (tx, h.ok_or_else(|| anyhow!("transaction is not mined yet; wait and sync"))?)
        }
        None => receipts_chain::chain::fetch_mined_tx(net, server, txid).await?,
    };
    let idx: Vec<usize> = outputs.iter().map(|&i| i as usize).collect();
    let pk = receipts_core::proving_key();
    let mut last = None;
    for p in pool.map(|p| vec![p]).unwrap_or_else(|| vec![Pool::Ironwood, Pool::Orchard]) {
        let b = match p {
            Pool::Ironwood => tx.ironwood_bundle(),
            Pool::Orchard => tx.orchard_bundle(),
        };
        let Some(b) = b else { continue };
        match receipts_core::incoming::create_incoming(&pk, net.coin_type(), p, txid, b, msg, &sk, &idx, OsRng) {
            Ok(r) => return Ok((r, height)),
            Err(e) => last = Some(e),
        }
    }
    match last {
        Some(e) => bail!("this wallet did not receive the selected output(s) of that transaction: {e}"),
        None => bail!("that transaction has no Orchard or Ironwood outputs"),
    }
}

/// Signs a payment request (`zreq1`) for `domain` with the wallet's key, for its default address
/// (or `payee`, an address of this wallet). Returns the request and the payee address.
#[allow(clippy::too_many_arguments)]
pub fn sign_payment_request(wallet: &Path, identity: &Path, domain: &str, amount: u64, memo: &str, code: &str, expires_at: u64, payee: Option<&str>) -> anyhow::Result<(receipts_core::payreq::PaymentRequest, String)> {
    let (net, seed) = decrypt_seed(wallet, identity)?;
    let usk = UnifiedSpendingKey::from_seed(&net, seed.expose_secret(), account()).map_err(|e| anyhow!("deriving keys: {e:?}"))?;
    let sk: SpendingKey = usk.orchard().clone();
    let fvk = FullViewingKey::from(&sk);
    let addr = match payee {
        None => fvk.address_at(0u32, Scope::External),
        Some(ua) => {
            let raw = receipts_chain::chain::orchard_receiver_of(ua)?;
            let a = Option::<orchard::Address>::from(orchard::Address::from_raw_address_bytes(&raw)).ok_or_else(|| anyhow!("invalid Orchard receiver in {ua}"))?;
            if fvk.scope_for_address(&a).is_none() {
                bail!("{ua} is not an address of this wallet's account");
            }
            a
        }
    };
    let r = receipts_core::payreq::sign_request(&receipts_core::proving_key(), net.coin_type(), domain, amount, memo, code, expires_at, &sk, addr, OsRng)
        .map_err(|_| anyhow!("invalid request: the domain must be a host name, the amount above 0, the memo at most 512 bytes and the code 6-64 hex characters"))?;
    Ok((r, receipts_chain::chain::encode_orchard_receiver(net, addr.to_raw_address_bytes())))
}

/// Makes a proof of funds over this wallet's unspent notes in `pool`, proven against the tree root
/// of its latest checkpoint. With `at_least`, uses the largest notes until that much is covered.
pub fn create_reserve_proof(wallet: &Path, identity: &Path, pool: Pool, msg: &[u8], at_least: Option<u64>) -> anyhow::Result<receipts_core::reserve::ReserveProof> {
    let (net, seed) = decrypt_seed(wallet, identity)?;
    let usk = UnifiedSpendingKey::from_seed(&net, seed.expose_secret(), account()).map_err(|e| anyhow!("deriving keys: {e:?}"))?;
    let sk: SpendingKey = usk.orchard().clone();
    let fvk = FullViewingKey::from(&sk);
    let db_path = wallet.join("data.sqlite");
    let conn = rusqlite::Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let (notes_t, spends_t, cp_t) = match pool {
        Pool::Ironwood => ("ironwood_received_notes", "ironwood_received_note_spends", "ironwood_tree_checkpoints"),
        Pool::Orchard => ("orchard_received_notes", "orchard_received_note_spends", "orchard_tree_checkpoints"),
    };
    let fk = match pool {
        Pool::Ironwood => "ironwood_received_note_id",
        Pool::Orchard => "orchard_received_note_id",
    };
    // Mined notes with no mined spend. (The chain is the judge: a spent note fails verification.)
    let sql = format!(
        "SELECT rn.nf FROM {notes_t} rn JOIN transactions t ON t.id_tx = rn.transaction_id
         WHERE t.mined_height IS NOT NULL AND rn.nf IS NOT NULL AND rn.value > 0 AND rn.id NOT IN (
           SELECT s.{fk} FROM {spends_t} s JOIN transactions st ON st.id_tx = s.transaction_id WHERE st.mined_height IS NOT NULL)"
    );
    let mut stmt = conn.prepare(&sql)?;
    let nfs: Vec<Vec<u8>> = stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
    let mut found = Vec::new();
    for nf in nfs {
        let nf: [u8; 32] = nf.try_into().map_err(|_| anyhow!("bad nullifier in wallet"))?;
        if let Some(n) = find_spent_note(&conn, pool, &fvk, &nf)? {
            found.push(n);
        }
    }
    if found.is_empty() {
        bail!("this wallet has no unspent {pool:?} notes (sync it first)");
    }
    found.sort_by_key(|n| std::cmp::Reverse(n.note.value().inner()));
    if let Some(min) = at_least {
        let mut sum = 0u64;
        let k = found.iter().take_while(|n| { let before = sum; sum += n.note.value().inner(); before < min }).count();
        if sum < min {
            bail!("unspent notes total {}, less than the {} asked for", receipts_chain::chain::zec(sum), receipts_chain::chain::zec(min));
        }
        found.truncate(k);
    }
    let height: u32 = conn.query_row(&format!("SELECT max(checkpoint_id) FROM {cp_t}"), [], |r| r.get(0)).map_err(|_| anyhow!("the wallet has no tree checkpoint; sync it"))?;
    let mut db = WalletDb::for_path(&db_path, net, SystemClock, OsRng)?;
    type E = ShardTreeError<zcash_client_sqlite::wallet::commitment_tree::Error>;
    let id = BlockHeight::from_u32(height);
    let mut witnesses = Vec::with_capacity(found.len());
    let mut anchor = None;
    for n in &found {
        let pos = Position::from(n.position);
        let (root, path) = match pool {
            Pool::Orchard => db.with_orchard_tree_mut::<_, _, E>(|t| Ok((t.root_at_checkpoint_id(&id)?, t.witness_at_checkpoint_id_caching(pos, &id)?)))?,
            Pool::Ironwood => db
                .with_ironwood_tree_mut::<_, _, E>(|t| Ok((t.root_at_checkpoint_id(&id)?, t.witness_at_checkpoint_id_caching(pos, &id)?)))?
                .ok_or_else(|| anyhow!("the wallet has no Ironwood tree"))?,
        };
        let root = root.ok_or_else(|| anyhow!("no tree root at the wallet's checkpoint {height}"))?;
        let path = path.ok_or_else(|| anyhow!("no witness for a note at checkpoint {height}; sync the wallet"))?;
        anchor = Some(orchard::Anchor::from(root));
        witnesses.push(receipts_core::reserve::ReserveWitness { note: n.note, merkle_path: orchard::tree::MerklePath::from(path) });
    }
    eprintln!("Proving {} note(s) against the {pool:?} tree at block {height}…", witnesses.len());
    Ok(receipts_core::reserve::create_reserve(&receipts_core::proving_key(), net.coin_type(), pool, height, anchor.expect("at least one note"), msg, &sk, &witnesses, OsRng)?)
}

/// A shop's proof-request link: `…#request=<challenge>&to=<payee>&min=<zatoshis>` (or the older
/// `…?request=…` form).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestLink {
    pub code: String,
    pub to: Option<String>,
    pub min: u64,
}

/// Parses a proof-request link. Each parameter may appear once; the payee must have an Orchard
/// receiver (so a receipt can prove it).
pub fn parse_request_link(link: &str) -> anyhow::Result<RequestLink> {
    // Parameters are in the #fragment (so the page's host never sees them); older links put them
    // in the query string. Receipt tokens and `h=` in the fragment are skipped.
    let (before, fragment) = link.split_once('#').unwrap_or((link, ""));
    let query = before.split_once('?').map(|(_, q)| q).unwrap_or("");
    let (mut code, mut to, mut min) = (None, None, None);
    for pair in query.split('&').chain(fragment.split('&')).filter(|p| !p.is_empty()) {
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
            let want = receipts_chain::chain::orchard_receiver_on(report.network, to)?;
            // Memo-withheld outputs (v5) don't show the payee can receive the note: not counted.
            report.outputs.iter().filter(|o| o.recipient_raw == want && !o.memo_withheld).map(|o| o.zatoshis).sum()
        }
        None => report.outputs.iter().filter(|o| !o.memo_withheld).map(|o| o.zatoshis).sum(),
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
    fn keys_wallets_from_a_phrase_or_a_viewing_key_agree_and_never_echo_the_phrase() {
        use super::{KeysWallet, Net};
        let Err(e) = KeysWallet::from_phrase(Net::Test, "abandon secretword abandon", 1) else { panic!("bad phrase accepted") };
        assert!(!e.to_string().contains("secretword"));
        // The BIP 39 test phrase: the viewing-key wallet derived from it is the same account.
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let w = KeysWallet::from_phrase(Net::Test, phrase, 1).unwrap();
        let seed = <bip0039::Mnemonic<bip0039::English>>::from_phrase(phrase).unwrap().to_seed("");
        let ufvk = zcash_keys::keys::UnifiedSpendingKey::from_seed(&Net::Test, &seed, zip32::AccountId::ZERO).unwrap().to_unified_full_viewing_key();
        let v = KeysWallet::from_ufvk(Net::Test, &ufvk.encode(&Net::Test).unwrap(), 1).unwrap();
        assert_eq!(w.fvk.to_bytes(), v.fvk.to_bytes());
        assert!(v.sk.is_none() && w.sk.is_some());
    }

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
        // The fragment form, with a receipt and a block hint after it.
        let r = super::parse_request_link(&format!("https://shop/verify/#request=00aa11bb&to={to}&min=5&zip311r1Abc&h=12")).unwrap();
        assert_eq!((r.code.as_str(), r.min), ("00aa11bb", 5));
        assert!(super::parse_request_link("https://x/?request=00aa11bb#request=ffff0000").is_err(), "one code, not two");
        assert!(super::check_refund_address("not-an-address").is_err());
    }
}
