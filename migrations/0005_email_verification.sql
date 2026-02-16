-- Migration number: 0005 	 2026-01-30T01:00:00.000Z
-- 创建邮箱验证临时表
CREATE TABLE IF NOT EXISTS email_verifications (
    token TEXT PRIMARY KEY,
    uid TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
