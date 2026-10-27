//! SQLite storage: API keys, proof requests, webhook endpoints, events, deliveries and
//! idempotency records. One file, created on first start.

use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;

pub struct Db(pub Mutex<Connection>);

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS api_keys (
    key TEXT PRIMARY KEY,
    mode TEXT NOT NULL CHECK (mode IN ('test', 'live')),
    created INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    challenge TEXT NOT NULL UNIQUE,
    payee TEXT NOT NULL,
    amount_zatoshis INTEGER,
    label TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL,
    created INTEGER NOT NULL,
    expires_at INTEGER,
    fulfilled_at INTEGER,
    txid TEXT,
    paid_zatoshis INTEGER,
    receipt TEXT,
    verification TEXT
);
CREATE TABLE IF NOT EXISTS payments_used (
    mode TEXT NOT NULL,
    txid TEXT NOT NULL,
    action INTEGER NOT NULL,
    request_id TEXT NOT NULL,
    zatoshis INTEGER NOT NULL,
    created INTEGER NOT NULL,
    PRIMARY KEY (mode, txid, action)
);
CREATE TABLE IF NOT EXISTS request_payments (
    id INTEGER PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES requests(id),
    txid TEXT NOT NULL,
    zatoshis INTEGER NOT NULL,
    mined_height INTEGER,
    memo TEXT,
    sender_addresses TEXT NOT NULL DEFAULT '[]',
    created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS signing_keys (
    kid TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS test_clocks (
    id TEXT PRIMARY KEY,
    frozen_time INTEGER NOT NULL,
    height INTEGER NOT NULL,
    created INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS refunds (
    id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    request_id TEXT NOT NULL REFERENCES requests(id),
    payment_txid TEXT NOT NULL,
    address TEXT NOT NULL,
    amount_zatoshis INTEGER NOT NULL,
    reason TEXT,
    challenge TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    created INTEGER NOT NULL,
    refunded_at INTEGER,
    txid TEXT,
    receipt TEXT,
    verification TEXT
);
CREATE TABLE IF NOT EXISTS sign_in_challenges (
    id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    domain TEXT NOT NULL,
    nonce TEXT NOT NULL,
    created INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    UNIQUE (mode, nonce)
);
CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events TEXT NOT NULL,
    created INTEGER NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    type TEXT NOT NULL,
    created INTEGER NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
    id INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES events(id),
    endpoint_id TEXT NOT NULL REFERENCES webhook_endpoints(id),
    attempts INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    next_attempt_at INTEGER NOT NULL,
    last_status INTEGER,
    last_error TEXT,
    delivered_at INTEGER
);
CREATE TABLE IF NOT EXISTS idempotency (
    api_key TEXT NOT NULL,
    idem_key TEXT NOT NULL,
    route TEXT NOT NULL,
    body_hash TEXT NOT NULL,
    status INTEGER NOT NULL,
    response TEXT NOT NULL,
    created INTEGER NOT NULL,
    PRIMARY KEY (api_key, idem_key)
);
";

pub fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// `prefix` + 24 hex characters from the OS RNG.
pub fn new_id(prefix: &str) -> String {
    let mut b = [0u8; 12];
    getrandom::fill(&mut b).expect("OS RNG");
    format!("{prefix}{}", hex::encode(b))
}

/// How an API key is stored: a SHA-256 digest of a 192-bit random key, so a copy of the database
/// doesn't hold keys that work.
pub fn key_digest(key: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(key.as_bytes())))
}

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
        // The file holds API keys and webhook secrets: owner-only, as are the WAL and shared-memory files SQLite adds.
        #[cfg(unix)]
        if path != ":memory:" && !path.is_empty() {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")?;
        conn.execute_batch(SCHEMA)?;
        // Columns added after the first release; ignore "duplicate column" on existing files.
        for col in [
            "kind TEXT NOT NULL DEFAULT 'single'",
            "received_zatoshis INTEGER NOT NULL DEFAULT 0",
            "client_secret TEXT",
            "expired_notified INTEGER NOT NULL DEFAULT 0",
            "public_k INTEGER NOT NULL DEFAULT 3",
            "snapshot TEXT",
            "snapshot_at INTEGER",
            "test_clock TEXT",
            "final_at INTEGER",
            "source_policy TEXT",
            "provenance TEXT",
            "created_height INTEGER",
        ] {
            let _ = conn.execute(&format!("ALTER TABLE requests ADD COLUMN {col}"), []);
        }
        // The chain tip when a refund was made: a settling payment must be mined after it.
        let _ = conn.execute("ALTER TABLE refunds ADD COLUMN created_height INTEGER", []);
        // Who made a test clock (a digest of the API key), so one tenant cannot move another's.
        let _ = conn.execute("ALTER TABLE test_clocks ADD COLUMN owner TEXT", []);
        for col in ["public_note TEXT", "refund_address TEXT"] {
            let _ = conn.execute(&format!("ALTER TABLE request_payments ADD COLUMN {col}"), []);
        }
        // Indexes for the hot lookups (the soak test showed throughput sliding without them).
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS deliveries_due ON deliveries(status, next_attempt_at);
             CREATE INDEX IF NOT EXISTS request_payments_request ON request_payments(request_id);
             CREATE INDEX IF NOT EXISTS refunds_request ON refunds(request_id);
             CREATE INDEX IF NOT EXISTS requests_mode_created ON requests(mode, created);
             CREATE INDEX IF NOT EXISTS requests_clock ON requests(test_clock);
             CREATE INDEX IF NOT EXISTS requests_open_expiry ON requests(status, expires_at);
             CREATE INDEX IF NOT EXISTS events_mode ON events(mode);",
        )?;
        Ok(Db(Mutex::new(conn)))
    }

    /// The keys to show the operator now: API keys are stored as digests (`sha256:…`), so only a key
    /// made in this call, or a plaintext key from an older database being converted in this call,
    /// can be shown; a later start shows none (the first start's printout, or the `.keys` file next
    /// to the database, is where they are).
    pub fn ensure_keys(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let c = self.0.lock().unwrap();
        let mut shown: Vec<(String, String)> = Vec::new();
        // Convert keys stored in the clear by earlier versions.
        let old: Vec<(String, String)> = c
            .prepare("SELECT key, mode FROM api_keys WHERE key NOT LIKE 'sha256:%'")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        for (key, mode) in old {
            c.execute("UPDATE api_keys SET key = ?1 WHERE key = ?2", params![key_digest(&key), key])?;
            // Idempotency records were keyed by the clear key; they only live a day.
            c.execute("DELETE FROM idempotency", [])?;
            shown.push((key, mode));
        }
        for mode in ["test", "live"] {
            let have: i64 = c.query_row("SELECT COUNT(*) FROM api_keys WHERE mode = ?1 AND revoked = 0", [mode], |r| r.get(0))?;
            if have == 0 {
                let mut b = [0u8; 24];
                getrandom::fill(&mut b).expect("OS RNG");
                let key = format!("rcpt_{mode}_{}", hex::encode(b));
                c.execute("INSERT INTO api_keys (key, mode, created) VALUES (?1, ?2, ?3)", params![key_digest(&key), mode, now()])?;
                shown.push((key, mode.to_string()));
            }
        }
        Ok(shown)
    }

    pub fn mode_for_key(&self, key: &str) -> rusqlite::Result<Option<String>> {
        let c = self.0.lock().unwrap();
        c.query_row("SELECT mode FROM api_keys WHERE key = ?1 AND revoked = 0", [key_digest(key)], |r| r.get(0)).optional()
    }
}
