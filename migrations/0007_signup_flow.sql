-- Migration number: 0007 	 2026-01-30T03:00:00.000Z
-- 待验证的新用户注册信息
CREATE TABLE IF NOT EXISTS pending_registrations (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

-- 在 users 表添加原始邮箱记录
ALTER TABLE users ADD COLUMN original_email TEXT;
