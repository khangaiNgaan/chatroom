-- Migration number: 0001 	 2024-04-05T00:00:00.000Z
-- 创建用户表
CREATE TABLE IF NOT EXISTS users (
    uid TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT,
    signup_date INTEGER,
    role TEXT DEFAULT 'user' -- 'admin', 'user'
);

-- 创建邀请码表
CREATE TABLE IF NOT EXISTS invites (
    code TEXT PRIMARY KEY,
    is_used INTEGER DEFAULT 0, -- 0: unused, 1: used
    used_by_uid TEXT
);

-- 系统默认管理员账户
INSERT OR IGNORE INTO users (uid, username, password, signup_date, role) VALUES ('01001', 'caffeine', '$2b$10$ECn1juQXzzwuzhO7/M1Bb.jOjTAzKjN17BS1nUHM2Hwd0O.J.w.EK', 0, 'admin');
