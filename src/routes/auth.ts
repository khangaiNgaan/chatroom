import { Hono } from 'hono'
import { setCookie, deleteCookie, getCookie } from 'hono/cookie'
import { SignJWT, jwtVerify } from 'jose'
import bcrypt from 'bcryptjs'
import { verify } from 'otplib'
import { Bindings, Variables } from '../types'
import { verifyTurnstile, sha256, decrypt } from '../utils/security'
import { sendEmail } from '../utils/email'
import { generateNextUid } from '../utils/user'
import * as templates from '../templates/pages'
import * as emailTemplates from '../templates/email'
import { User, Invite, Token, PasswordReset, EmailVerification, PendingRegistration } from '../models'

const auth = new Hono<{ Bindings: Bindings, Variables: Variables }>()

// Helper to set session cookie
const setSessionCookie = async (c: any, user: User, sessionId: string) => {
    const secret = new TextEncoder().encode(c.env.JWT_SECRET)
    const token = await new SignJWT({
        uid: user.uid,
        username: user.username,
        role: user.role,
        sessionId: sessionId
    })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt()
        .setExpirationTime('7d')
        .sign(secret)

    const isSecure = new URL(c.req.url).protocol === 'https:'
    setCookie(c, 'session', token, {
        httpOnly: true,
        secure: isSecure,
        domain: c.env.COOKIE_DOMAIN,
        sameSite: 'Lax',
        maxAge: 60 * 60 * 24 * 7,
        path: '/'
    })
}

// POST /api/login
auth.post('/api/login', async (c) => {
    try {
        const formData = await c.req.parseBody()
        const accessToken = formData['access_token'] as string
        const loginUsername = formData['username'] as string

        // 1. Access Token Login
        if (accessToken) {
            const tokenRecord = await c.env.DB.prepare('SELECT id, uid FROM tokens WHERE token = ?').bind(accessToken).first<Token>()
            if (!tokenRecord) {
                return c.json({ success: false, message: 'invalid access token' }, 403)
            }

            const user = await c.env.DB.prepare('SELECT * FROM users WHERE uid = ?').bind(tokenRecord.uid).first<User>()
            if (!user) return c.json({ success: false, message: 'user not found' }, 404)

            if (loginUsername && user.username !== loginUsername) {
                return c.json({ success: false, message: 'username does not match token owner' }, 403)
            }

            // Create Session
            const sessionId = crypto.randomUUID()
            const ip = c.req.header('CF-Connecting-IP') || 'unknown'
            const userAgent = c.req.header('User-Agent') || 'unknown'
            const expiresAt = Date.now() + (90 * 24 * 60 * 60 * 1000)

            await c.env.DB.prepare('INSERT INTO sessions (id, uid, ip, user_agent, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
                .bind(sessionId, user.uid, ip, userAgent, Date.now(), expiresAt)
                .run()
            
            // Set Cookie (90 days for token login)
            const secret = new TextEncoder().encode(c.env.JWT_SECRET)
            const token = await new SignJWT({ 
                uid: user.uid, 
                username: user.username, 
                role: user.role, 
                sessionId: sessionId 
            })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setExpirationTime('90d')
                .sign(secret)

            const isSecure = new URL(c.req.url).protocol === 'https:'
            setCookie(c, 'session', token, {
                httpOnly: true,
                secure: isSecure,
                domain: c.env.COOKIE_DOMAIN,
                sameSite: 'Lax',
                maxAge: 60 * 60 * 24 * 90,
                path: '/'
            })

            // Burn Token
            await c.env.DB.prepare('DELETE FROM tokens WHERE id = ?').bind(tokenRecord.id).run()

            return c.json({ success: true, message: 'login successful' })
        }

        // 2. Normal Login
        const password = formData['password'] as string
        const turnstileToken = formData['cf-turnstile-response'] as string
        const ip = c.req.header('CF-Connecting-IP')

        if (!c.env.TURNSTILE_SECRET_KEY) return c.json({ success: false, message: 'server config error: missing turnstile key' }, 500)
        
        const verification = await verifyTurnstile(turnstileToken, c.env.TURNSTILE_SECRET_KEY, ip)
        if (!verification.success) {
            return c.json({ success: false, message: 'security check failed (turnstile)' }, 403)
        }

        const user = await c.env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(loginUsername).first<User>()
        if (!user) {
            return c.json({ success: false, message: 'invalid username or password' }, 403)
        }

        const isValid = await bcrypt.compare(password, user.password)
        if (!isValid) {
            return c.json({ success: false, message: 'invalid username or password' }, 403)
        }

        // 2FA Check
        if (user.two_factor_enabled) {
            const secret = new TextEncoder().encode(c.env.JWT_SECRET)
            const tempToken = await new SignJWT({ uid: user.uid, role: user.role, scope: '2fa_pending' })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setExpirationTime('5m')
                .sign(secret)
            
            return c.json({ success: true, message: '2fa required', '2fa_required': true, temp_token: tempToken })
        }

        // Create Session
        const sessionId = crypto.randomUUID()
        const userAgent = c.req.header('User-Agent') || 'unknown'
        const expiresAt = Date.now() + (7 * 24 * 60 * 60 * 1000)

        await c.env.DB.prepare('INSERT INTO sessions (id, uid, ip, user_agent, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
            .bind(sessionId, user.uid, ip || 'unknown', userAgent, Date.now(), expiresAt)
            .run()

        await setSessionCookie(c, user, sessionId)

        return c.json({ success: true, message: 'login successful' })

    } catch (e: any) {
        return c.json({ success: false, message: 'login error: ' + e.message }, 500)
    }
})

// POST /api/login/2fa
auth.post('/api/login/2fa', async (c) => {
    try {
        const formData = await c.req.parseBody()
        const tempToken = formData['temp_token'] as string
        const code = formData['code'] as string
        const type = formData['type'] as string // 'totp' or 'recovery'

        if (!tempToken || !code) return c.json({ success: false, message: 'missing parameters' }, 400)

        // 1. Verify temp_token
        let payload
        try {
            const secret = new TextEncoder().encode(c.env.JWT_SECRET)
            const { payload: p } = await jwtVerify(tempToken, secret)
            if (p.scope !== '2fa_pending') throw new Error('invalid scope')
            payload = p
        } catch (e) {
            return c.json({ success: false, message: 'session expired, please login again' }, 401)
        }

        const user = await c.env.DB.prepare('SELECT * FROM users WHERE uid = ?').bind(payload.uid).first<User>()
        if (!user) return c.json({ success: false, message: 'user not found' }, 404)

        // 2. Verify 2FA
        let isValid = false
        let usedRecoveryCode = false
        let decryptedSecret = null
        
        const shouldCheckTotp = !type || type === 'totp'
        const shouldCheckRecovery = !type || type === 'recovery'

        if (user.totp_secret && c.env.ENCRYPTION_KEY) {
            try {
                decryptedSecret = await decrypt(user.totp_secret, c.env.ENCRYPTION_KEY)
            } catch(e) {}
        }

        if (shouldCheckTotp && decryptedSecret) {
            try {
                const verifyResult: any = await verify({ token: code, secret: decryptedSecret, window: 1 } as any)
                if (typeof verifyResult === 'boolean') isValid = verifyResult
                else if (typeof verifyResult === 'object' && verifyResult !== null) isValid = (verifyResult as any).valid === true
            } catch (e) {}
        }

        if (!isValid && shouldCheckRecovery && user.recovery_codes && decryptedSecret) {
            try {
                const hashedCodes = JSON.parse(user.recovery_codes) as string[]
                const salt = user.uid + decryptedSecret
                const inputHash = await sha256(code + salt)
                
                const index = hashedCodes.indexOf(inputHash)
                if (index !== -1) {
                    isValid = true
                    usedRecoveryCode = true
                    hashedCodes.splice(index, 1)
                    await c.env.DB.prepare('UPDATE users SET recovery_codes = ? WHERE uid = ?').bind(JSON.stringify(hashedCodes), user.uid).run()
                }
            } catch (e) {}
        }

        if (!isValid) return c.json({ success: false, message: 'invalid verification code' }, 400)

        // Create Session
        const sessionId = crypto.randomUUID()
        const userAgent = c.req.header('User-Agent') || 'unknown'
        const ip = c.req.header('CF-Connecting-IP') || 'unknown'
        const expiresAt = Date.now() + (7 * 24 * 60 * 60 * 1000)

        await c.env.DB.prepare('INSERT INTO sessions (id, uid, ip, user_agent, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
            .bind(sessionId, user.uid, ip, userAgent, Date.now(), expiresAt)
            .run()

        await setSessionCookie(c, user, sessionId)

        return c.json({ success: true, message: 'login successful' + (usedRecoveryCode ? ' (recovery code used)' : '') })

    } catch (e: any) {
        return c.json({ success: false, message: 'server error: ' + e.message }, 500)
    }
})

// POST /api/signup/check-username
auth.post('/api/signup/check-username', async (c) => {
    try {
        const formData = await c.req.parseBody()
        const username = formData['username'] as string
        const password = formData['password'] as string

        if (!/^\w{4,16}$/.test(username)) {
            return c.json({ success: false, message: "username must be 4-16 valid chars" }, 400)
        }

        if (!password || password.length < 6) {
            return c.json({ success: false, message: "password must be at least 6 chars" }, 400)
        }

        const existing = await c.env.DB.prepare("SELECT uid FROM users WHERE username = ?").bind(username).first<{ uid: string }>()
        if (existing) {
            return c.json({ success: false, message: "username already taken" }, 400)
        }

        return c.json({ success: true, message: "valid" })
    } catch(e) {
        return c.json({ success: false, message: "Server Error" }, 500)
    }
})

// POST /api/signup
auth.post('/api/signup', async (c) => {
    try {
        const formData = await c.req.parseBody()
        const username = formData['username'] as string
        const password = formData['password'] as string
        const inviteCode = formData['invite-code'] as string
        const email = formData['email'] as string
        const turnstileToken = formData['cf-turnstile-response'] as string
        const ip = c.req.header('CF-Connecting-IP')

        if (!c.env.TURNSTILE_SECRET_KEY) return c.json({ success: false, message: 'server config error: missing turnstile key' }, 500)

        const verification = await verifyTurnstile(turnstileToken, c.env.TURNSTILE_SECRET_KEY, ip)
        if (!verification.success) return c.json({ success: false, message: 'security check failed (turnstile)' }, 403)

        if (!password || password.length < 6) return c.json({ success: false, message: 'password must be at least 6 characters' }, 400)
        if (!/^\w{4,16}$/.test(username)) return c.json({ success: false, message: 'username contains invalid characters' }, 400)

        const existing = await c.env.DB.prepare('SELECT uid FROM users WHERE username = ?').bind(username).first<{ uid: string }>()
        if (existing) return c.json({ success: false, message: 'username already taken' }, 400)

        if (!inviteCode && !email) return c.json({ success: false, message: 'verification method required' }, 400)

        // Invite Code Flow
        if (inviteCode && inviteCode.trim() !== "") {
            const invite = await c.env.DB.prepare('SELECT * FROM invites WHERE code = ?').bind(inviteCode).first<Invite>()
            if (!invite || invite.is_used) return c.json({ success: false, message: 'invalid or used invite code' }, 400)

            if (email && email.trim() !== "") {
                if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return c.json({ success: false, message: 'invalid email format' }, 400)
                const existingEmail = await c.env.DB.prepare('SELECT uid FROM users WHERE email = ? AND email_verified = 1').bind(email).first<{ uid: string }>()
                if (existingEmail) return c.json({ success: false, message: 'email already registered' }, 400)
            }

            const newUid = await generateNextUid(c.env)
            const hashedPassword = await bcrypt.hash(password, 10)
            const userEmail = (email && email.trim() !== "") ? email : null

            await c.env.DB.batch([
                c.env.DB.prepare('INSERT INTO users (uid, username, password, email, email_verified, signup_date, original_email) VALUES (?, ?, ?, ?, ?, ?, ?)')
                    .bind(newUid, username, hashedPassword, userEmail, 0, Date.now(), userEmail),
                c.env.DB.prepare('UPDATE invites SET is_used = 1, used_by_uid = ? WHERE code = ?').bind(newUid, inviteCode)
            ])

            if (userEmail) {
                const token = crypto.randomUUID()
                const now = Date.now()
                const verifyLink = `${new URL(c.req.url).origin}/auth/verify-email?token=${token}`
                
                await c.env.DB.prepare('INSERT INTO email_verifications (token, uid, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
                    .bind(token, newUid, userEmail, now, now + 86400000)
                    .run()

                c.executionCtx.waitUntil(sendEmail(c.env, userEmail, "Verify your email - coffeeroom", emailTemplates.getWelcomeEmailHtml(username, verifyLink)))
            }

            return c.json({ success: true, message: 'signup successful', redirect: '/auth/login.html' })
        } else {
            // Email Only Flow (Pending)
            if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return c.json({ success: false, message: 'invalid email format' }, 400)
            const existingEmail = await c.env.DB.prepare('SELECT uid FROM users WHERE email = ? AND email_verified = 1').bind(email).first<{ uid: string }>()
            if (existingEmail) return c.json({ success: false, message: 'email already registered' }, 400)

            const token = crypto.randomUUID()
            const hashedPassword = await bcrypt.hash(password, 10)
            const verifyLink = `${new URL(c.req.url).origin}/auth/verify-registration?token=${token}`

            await c.env.DB.prepare('INSERT INTO pending_registrations (token, username, password_hash, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
                .bind(token, username, hashedPassword, email, Date.now(), Date.now() + 86400000)
                .run()

            c.executionCtx.waitUntil(sendEmail(c.env, email, "Verify your registration - coffeeroom", emailTemplates.getVerifyRegistrationHtml(username, verifyLink)))

            return c.json({ success: true, message: 'verification email sent. please check your inbox and spam folder.' })
        }

    } catch (e: any) {
        return c.json({ success: false, message: 'signup error: ' + e.message }, 500)
    }
})

// POST /api/logout
auth.all('/api/logout', async (c) => {
    try {
        const sessionToken = getCookie(c, 'session')
        if (sessionToken && c.env.JWT_SECRET) {
            const secret = new TextEncoder().encode(c.env.JWT_SECRET)
            const { payload } = await jwtVerify(sessionToken, secret)
            if (payload.sessionId) {
                await c.env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(payload.sessionId).run()
            }
        }
    } catch (e) { /* ignore */ }

    deleteCookie(c, 'session', { path: '/', domain: c.env.COOKIE_DOMAIN })
    
    if (c.req.method === 'GET') {
        return c.redirect('/')
    }
    return c.text('Logged out')
})

// GET /auth/verify-email
auth.get('/auth/verify-email', async (c) => {
    const token = c.req.query('token')
    if (!token) return c.text('Missing token', 400)

    const record = await c.env.DB.prepare('SELECT * FROM email_verifications WHERE token = ?').bind(token).first<EmailVerification>() 
    if (!record) return c.text('Invalid or expired verification link.', 400)
    if (record.expires_at < Date.now()) {
        await c.env.DB.prepare('DELETE FROM email_verifications WHERE token = ?').bind(token).run()
        return c.text('Verification link expired.', 400)
    }

    await c.env.DB.batch([
        c.env.DB.prepare('UPDATE users SET email = ?, email_verified = 1 WHERE uid = ?').bind(record.email, record.uid),
        c.env.DB.prepare('DELETE FROM email_verifications WHERE token = ?').bind(token)
    ])

    return c.html(templates.getEmailVerifiedHtml(record.email))
})

// GET /auth/verify-registration
auth.get('/auth/verify-registration', async (c) => {
    const token = c.req.query('token')
    if (!token) return c.text('Missing token', 400)

    const record = await c.env.DB.prepare('SELECT * FROM pending_registrations WHERE token = ?').bind(token).first<PendingRegistration>()
    if (!record) return c.text('Invalid or expired registration link.', 400)
    if (record.expires_at < Date.now()) {
        await c.env.DB.prepare('DELETE FROM pending_registrations WHERE token = ?').bind(token).run()
        return c.text('Registration link expired. Please sign up again.', 400)
    }

    try {
        const newUid = await generateNextUid(c.env)
        await c.env.DB.batch([
            c.env.DB.prepare('INSERT INTO users (uid, username, password, email, email_verified, signup_date, original_email) VALUES (?, ?, ?, ?, 1, ?, ?)')
                .bind(newUid, record.username, record.password_hash, record.email, Date.now(), record.email),
            c.env.DB.prepare('DELETE FROM pending_registrations WHERE token = ?').bind(token)
        ])
        return c.html(templates.getRegistrationSuccessHtml(record.username))
    } catch (e) {
        return c.text('Error creating account', 500)
    }
})

// POST /api/auth/forgot-password
auth.post('/api/auth/forgot-password', async (c) => {
    try {
        const formData = await c.req.parseBody()
        const email = formData['email'] as string

        if (!email) return c.json({ success: false, message: 'email required' }, 400)

        const user = await c.env.DB.prepare('SELECT uid, username FROM users WHERE email = ? AND email_verified = 1').bind(email).first<User>()

        if (user) {
            const token = crypto.randomUUID()
            const now = Date.now()
            const expiresAt = now + 15 * 60 * 1000 // 15 mins

            await c.env.DB.prepare('INSERT OR REPLACE INTO password_resets (token, uid, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
                .bind(token, user.uid, email, now, expiresAt)
                .run()

            const resetLink = `${new URL(c.req.url).origin}/auth/reset-password.html?token=${token}`
            c.executionCtx.waitUntil(sendEmail(c.env, email, "Reset your password - coffeeroom", emailTemplates.getResetPasswordEmailHtml(user.username, resetLink)))
        }

        return c.json({ success: true, message: 'if that email exists, we\'ve sent a reset link.' })
    } catch (e: any) {
        return c.json({ success: false, message: 'server error' }, 500)
    }
})

// GET /auth/reset-password.html
auth.get('/auth/reset-password.html', async (c) => {
    const token = c.req.query('token')
    if (!token) return c.text('Missing token', 400)

    const record = await c.env.DB.prepare('SELECT * FROM password_resets WHERE token = ?').bind(token).first<PasswordReset>()
    if (!record || record.expires_at < Date.now()) {
        return c.html(templates.getResetExpiredHtml())
    }

    const user = await c.env.DB.prepare('SELECT two_factor_enabled FROM users WHERE uid = ?').bind(record.uid).first<User>()
    const is2FA = !!(user && user.two_factor_enabled)

    return c.html(templates.getResetPasswordFormHtml(token, is2FA))
})

// POST /api/auth/reset-password
auth.post('/api/auth/reset-password', async (c) => {
    try {
        const formData = await c.req.parseBody()
        const token = formData['token'] as string
        const password = formData['password'] as string
        const confirmPassword = formData['confirm-password'] as string
        const code = formData['code'] as string

        if (password !== confirmPassword) return c.text('Passwords do not match', 400)

        const record = await c.env.DB.prepare('SELECT * FROM password_resets WHERE token = ?').bind(token).first<PasswordReset>()
        if (!record || record.expires_at < Date.now()) return c.text('Invalid or expired token', 400)

        const user = await c.env.DB.prepare('SELECT * FROM users WHERE uid = ?').bind(record.uid).first<User>()
        if (user && user.two_factor_enabled) {
            if (!code) return c.text('2FA code required', 400)

            let isValid = false
            let decryptedSecret = null

            if (user.totp_secret && c.env.ENCRYPTION_KEY) {
                try {
                    decryptedSecret = await decrypt(user.totp_secret, c.env.ENCRYPTION_KEY)
                } catch (e) {}
            }

            if (decryptedSecret) {
                try {
                   const verifyResult: any = await verify({ token: code, secret: decryptedSecret, window: 1 } as any)
                   if (typeof verifyResult === 'boolean') isValid = verifyResult
                   else if (typeof verifyResult === 'object' && verifyResult !== null) isValid = (verifyResult as any).valid === true
                } catch (e) {}
            }

            // Recovery code check
            if (!isValid && user.recovery_codes && decryptedSecret) {
                 try {
                    const hashedCodes = JSON.parse(user.recovery_codes) as string[]
                    const salt = user.uid + decryptedSecret
                    const inputHash = await sha256(code + salt)
                    const index = hashedCodes.indexOf(inputHash)
                    if (index !== -1) {
                        isValid = true
                        hashedCodes.splice(index, 1)
                        await c.env.DB.prepare('UPDATE users SET recovery_codes = ? WHERE uid = ?').bind(JSON.stringify(hashedCodes), user.uid).run()
                    }
                 } catch (e) {}
            }

            if (!isValid) return c.text('Invalid 2FA code', 400)
        }

        const hashedPassword = await bcrypt.hash(password, 10)
        await c.env.DB.prepare('UPDATE users SET password = ? WHERE uid = ?').bind(hashedPassword, record.uid).run()
        await c.env.DB.prepare('DELETE FROM password_resets WHERE token = ?').bind(token).run()
        await c.env.DB.prepare('DELETE FROM sessions WHERE uid = ?').bind(record.uid).run()

        return c.html(templates.getResetSuccessHtml())

    } catch (e: any) {
        return c.text('Server Error', 500)
    }
})

export default auth
