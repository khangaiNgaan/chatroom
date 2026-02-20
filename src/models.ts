export interface User {
    uid: string
    username: string
    password: string
    email: string | null
    original_email: string | null
    email_verified: number // 0 or 1
    role: string // 'admin' | 'user'
    signup_date: number
    two_factor_enabled: number // 0 or 1
    totp_secret: string | null
    recovery_codes: string | null // JSON string
}

export interface Invite {
    code: string
    is_used: number // 0 or 1
    used_by_uid: string | null
}

export interface Token {
    id: number
    uid: string
    token: string
    label: string | null
    created_at: number
}

export interface Session {
    id: string
    uid: string
    ip: string | null
    user_agent: string | null
    created_at: number
    expires_at: number
}

export interface EmailVerification {
    token: string
    uid: string
    email: string
    created_at: number
    expires_at: number
}

export interface PasswordReset {
    token: string
    uid: string
    email: string
    created_at: number
    expires_at: number
}

export interface PendingRegistration {
    token: string
    username: string
    password_hash: string
    email: string
    created_at: number
    expires_at: number
}
