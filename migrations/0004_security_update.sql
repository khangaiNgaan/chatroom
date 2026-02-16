-- Migration number: 0004 	 2026-01-30T00:00:00.000Z
-- 添加安全相关字段
ALTER TABLE users ADD COLUMN totp_secret TEXT;
ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN recovery_codes TEXT;
ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0;
