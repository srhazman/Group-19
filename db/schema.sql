PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS peers (
    fid TEXT PRIMARY KEY,
    addr TEXT NOT NULL,
    nick TEXT,
    pubkey TEXT,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    capabilities TEXT
);

CREATE INDEX IF NOT EXISTS idx_peers_last_seen ON peers(last_seen);

CREATE TABLE IF NOT EXISTS messages (
    msg_id TEXT PRIMARY KEY,
    from_fid TEXT,
    to_addr TEXT,
    type TEXT,
    ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    envelope TEXT,
    FOREIGN KEY(from_fid) REFERENCES peers(fid) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts);
