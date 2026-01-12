-- Migration number: 0003 	 2026-01-12T00:00:00.000Z
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    uid TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    created_at INTEGER,
    expires_at INTEGER,
    FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_uid ON sessions(uid);
