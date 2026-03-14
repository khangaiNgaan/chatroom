-- Migration number: 0008        2026-02-19T00:00:00.000Z
-- 彻底迁移 Access Tokens 为 OATs

DROP TABLE IF EXISTS tokens;

CREATE TABLE IF NOT EXISTS oats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT NOT NULL,
    hashed_ticket TEXT NOT NULL UNIQUE,
    label TEXT,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(uid) REFERENCES users(uid)
);

CREATE INDEX IF NOT EXISTS idx_oats_uid ON oats(uid);
CREATE INDEX IF NOT EXISTS idx_oats_hashed_ticket ON oats(hashed_ticket);
