-- Migration number: 0002 	 2025-01-08T00:00:00.000Z
CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    label TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(uid) REFERENCES users(uid)
);

CREATE INDEX IF NOT EXISTS idx_tokens_uid ON tokens(uid);
CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token);
