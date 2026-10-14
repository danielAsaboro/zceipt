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

impl Db {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = Connection::open(path)?;
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
        ] {
            let _ = conn.execute(&format!("ALTER TABLE requests ADD COLUMN {col}"), []);
        }
        let _ = conn.execute("ALTER TABLE request_payments ADD COLUMN public_note TEXT", []);
        Ok(Db(Mutex::new(conn)))
    }

    pub fn ensure_keys(&self) -> rusqlite::Result<Vec<(String, String)>> {
        let c = self.0.lock().unwrap();
        let mut keys: Vec<(String, String)> = c
            .prepare("SELECT key, mode FROM api_keys WHERE revoked = 0 ORDER BY created")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<_, _>>()?;
        for mode in ["test", "live"] {
            if !keys.iter().any(|(_, m)| m == mode) {
                let mut b = [0u8; 24];
                getrandom::fill(&mut b).expect("OS RNG");
                let key = format!("rcpt_{mode}_{}", hex::encode(b));
                c.execute("INSERT INTO api_keys (key, mode, created) VALUES (?1, ?2, ?3)", params![key, mode, now()])?;
                keys.push((key, mode.to_string()));
            }
        }
        Ok(keys)
    }

    pub fn mode_for_key(&self, key: &str) -> rusqlite::Result<Option<String>> {
        let c = self.0.lock().unwrap();
        c.query_row("SELECT mode FROM api_keys WHERE key = ?1 AND revoked = 0", [key], |r| r.get(0)).optional()
    }
}
