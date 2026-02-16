-- Migration number: 0006 	 2026-01-30T02:00:00.000Z
-- 创建密码重置临时表
CREATE TABLE IF NOT EXISTS password_resets (
    token TEXT PRIMARY KEY,
    uid TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
