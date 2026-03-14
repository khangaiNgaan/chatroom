import { Hono } from 'hono'
import bcrypt from 'bcryptjs'
import { generateSecret, generateURI, verify } from 'otplib'
import QRCode from 'qrcode'
import { Bindings, Variables } from '../types'
import { authMiddleware } from '../middleware/auth'
import { sendEmail } from '../utils/email'
import { encrypt, decrypt, sha256 } from '../utils/security'
import * as emailTemplates from '../templates/email'
import { User, Session, OatRecord } from '../models'

const user = new Hono<{ Bindings: Bindings, Variables: Variables }>()

user.use('*', authMiddleware)

// GET /api/user
user.get('/api/user', async (c) => {
    const payload = c.get('user')!
    
    // 从 DB 获取最新信息
    const user = await c.env.DB.prepare('SELECT uid, username, role, signup_date, email, email_verified, two_factor_enabled FROM users WHERE uid = ?')
        .bind(payload.uid)
        .first<User>()

    if (user) {
        return c.json(user)
    } else {
        return c.json(payload)
    }
})

// POST /api/user/change-password
user.post('/api/user/change-password', async (c) => {
    try {
        const payload = c.get('user')!
        if (payload.isOatLogin) return c.json({ success: false, message: 'action not permitted via OAT session' }, 403)
        
        const formData = await c.req.parseBody()
        const oldPassword = formData['old-password'] as string
        const newPassword = formData['new-password'] as string

        if (!oldPassword || !newPassword) return c.json({ success: false, message: 'missing parameters' }, 400)
        
        const user = await c.env.DB.prepare('SELECT password FROM users WHERE uid = ?').bind(payload.uid).first<User>()
        if (!user) return c.json({ success: false, message: 'user not found' }, 404)

        const isValid = await bcrypt.compare(oldPassword, user.password)
        if (!isValid) return c.json({ success: false, message: 'current password incorrect' }, 400)

        if (newPassword.length < 6) return c.json({ success: false, message: 'new password must be at least 6 characters' }, 400)

        const hashedNewPassword = await bcrypt.hash(newPassword, 10)
        await c.env.DB.prepare('UPDATE users SET password = ? WHERE uid = ?').bind(hashedNewPassword, payload.uid).run()

        return c.json({ success: true, message: 'password updated successfully' })
    } catch (e) {
        return c.json({ success: false, message: 'server error' }, 500)
    }
})

// POST /api/user/bind-email
user.post('/api/user/bind-email', async (c) => {
    try {
        const payload = c.get('user')!
        if (payload.isOatLogin) return c.json({ success: false, message: 'action not permitted via OAT session' }, 403)
        
        const formData = await c.req.parseBody()
        const email = formData['email'] as string

        if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return c.json({ success: false, message: 'invalid email format' }, 400)

        const existing = await c.env.DB.prepare('SELECT uid FROM users WHERE email = ? AND email_verified = 1').bind(email).first()
        if (existing) return c.json({ success: false, message: 'email already in use' }, 400)

        const currentUser = await c.env.DB.prepare('SELECT email, password, email_verified FROM users WHERE uid = ?').bind(payload.uid).first<User>()
        if (currentUser && currentUser.email && currentUser.email_verified) {
            const password = formData['password'] as string
            if (!password) return c.json({ success: false, message: 'password required to change email' }, 400)
            const isValid = await bcrypt.compare(password, currentUser.password)
            if (!isValid) return c.json({ success: false, message: 'incorrect password' }, 400)
        }

        const token = crypto.randomUUID()
        const now = Date.now()
        const verifyLink = `${new URL(c.req.url).origin}/auth/verify-email?token=${token}`

        await c.env.DB.prepare('INSERT OR REPLACE INTO email_verifications (token, uid, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
            .bind(token, payload.uid, email, now, now + 86400000)
            .run()

        c.executionCtx.waitUntil(sendEmail(c.env, email, "Verify your email - coffeeroom", emailTemplates.getVerifyEmailHtml(payload.username, verifyLink)))

        return c.json({ success: true, message: 'verification email sent' })

    } catch (e) {
        return c.json({ success: false, message: 'server error' }, 500)
    }
})

// POST /api/user/unbind-email
user.post('/api/user/unbind-email', async (c) => {
    try {
        const payload = c.get('user')!
        if (payload.isOatLogin) return c.json({ success: false, message: 'action not permitted via OAT session' }, 403)
        
        const formData = await c.req.parseBody()
        const password = formData['password'] as string
        
        if (!password) return c.json({ success: false, message: 'password required' }, 400)

        const user = await c.env.DB.prepare('SELECT password FROM users WHERE uid = ?').bind(payload.uid).first<User>()
        if (!user) return c.json({ success: false, message: 'user not found' }, 404)

        const isValid = await bcrypt.compare(password, user.password)
        if (!isValid) return c.json({ success: false, message: 'incorrect password' }, 400)

        await c.env.DB.prepare('UPDATE users SET email = NULL, email_verified = 0 WHERE uid = ?').bind(payload.uid).run()
        
        return c.json({ success: true, message: 'email removed' })

    } catch (e) {
        return c.json({ success: false, message: 'server error' }, 500)
    }
})

// 2FA Routes
user.post('/api/user/2fa/setup', async (c) => {
    const payload = c.get('user')!
    if (payload.isOatLogin) return c.json({ success: false, message: 'action not permitted via OAT session' }, 403)
    
    const secret = generateSecret()

    if (!c.env.ENCRYPTION_KEY) return c.json({ success: false, message: 'server config error' }, 500)
    
    const encryptedSecret = await encrypt(secret, c.env.ENCRYPTION_KEY)

    const otpauth = generateURI({
        secret: secret,
        label: payload.username,
        issuer: 'coffeeroom',
        algorithm: 'sha1',
        digits: 6,
        period: 30
    })

    const svgString = await QRCode.toString(otpauth, { type: 'svg' })
    const qrCodeDataUrl = `data:image/svg+xml;base64,${btoa(svgString)}`

    await c.env.DB.prepare('UPDATE users SET totp_secret = ? WHERE uid = ?').bind(encryptedSecret, payload.uid).run()

    return c.json({ success: true, secret: secret, qrCode: qrCodeDataUrl })
})

user.post('/api/user/2fa/enable', async (c) => {
    const payload = c.get('user')!
    if (payload.isOatLogin) return c.json({ success: false, message: 'action not permitted via OAT session' }, 403)
    
    const formData = await c.req.parseBody()
    const code = formData['code'] as string

    const user = await c.env.DB.prepare('SELECT totp_secret FROM users WHERE uid = ?').bind(payload.uid).first<User>()
    if (!user || !user.totp_secret) return c.json({ success: false, message: '2FA not set up' }, 400)

    if (!c.env.ENCRYPTION_KEY) return c.json({ success: false, message: 'server config error' }, 500)
    
    let decryptedSecret
    try {
        decryptedSecret = await decrypt(user.totp_secret, c.env.ENCRYPTION_KEY)
    } catch (e) {
        return c.json({ success: false, message: 'encryption error' }, 500)
    }

    try {
        const verifyResult: any = await verify({ token: code, secret: decryptedSecret, window: 1 } as any)
        let isValid = false
        if (typeof verifyResult === 'boolean') isValid = verifyResult
        else if (typeof verifyResult === 'object' && verifyResult !== null) isValid = (verifyResult as any).valid === true

        if (!isValid) return c.json({ success: false, message: 'invalid verification code' }, 400)
    } catch (e) {
        return c.json({ success: false, message: 'verification error' }, 500)
    }

    const recoveryCodes = []
    const hashedCodes = []
    const salt = payload.uid + decryptedSecret

    for (let i = 0; i < 10; i++) {
        const part1 = crypto.randomUUID().split('-')[0].substring(0, 5)
        const part2 = crypto.randomUUID().split('-')[0].substring(0, 5)
        const code = `${part1}-${part2}`
        recoveryCodes.push(code)
        hashedCodes.push(await sha256(code + salt))
    }

    const userInfo = await c.env.DB.prepare('SELECT email FROM users WHERE uid = ?').bind(payload.uid).first<User>()
    
    await c.env.DB.prepare('UPDATE users SET two_factor_enabled = 1, recovery_codes = ? WHERE uid = ?')
        .bind(JSON.stringify(hashedCodes), payload.uid)
        .run()

    return c.json({
        success: true,
        message: '2FA enabled',
        username: payload.username,
        email: userInfo ? userInfo.email : null,
        recoveryCodes: recoveryCodes,
        date: new Date().toISOString().split('T')[0]
    })
})

user.post('/api/user/2fa/disable', async (c) => {
    const payload = c.get('user')!
    if (payload.isOatLogin) return c.json({ success: false, message: 'action not permitted via OAT session' }, 403)
    
    const formData = await c.req.parseBody()
    const password = formData['password'] as string

    const user = await c.env.DB.prepare('SELECT password FROM users WHERE uid = ?').bind(payload.uid).first<User>()
    if (!user) return c.json({ success: false, message: 'user not found' }, 404)

    const isValid = await bcrypt.compare(password, user.password)
    if (!isValid) return c.json({ success: false, message: 'incorrect password' }, 400)

    await c.env.DB.prepare('UPDATE users SET two_factor_enabled = 0, totp_secret = NULL, recovery_codes = NULL WHERE uid = ?')
        .bind(payload.uid)
        .run()

    return c.json({ success: true, message: '2FA disabled' })
})

// Sessions
user.get('/api/sessions', async (c) => {
    const payload = c.get('user')!
    await c.env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(Date.now()).run()

    const sessions = await c.env.DB.prepare('SELECT * FROM sessions WHERE uid = ? ORDER BY created_at DESC').bind(payload.uid).all<Session>()
    
    const results = sessions.results.map(s => ({
        ...s,
        is_current: s.id === payload.sessionId
    }))

    return c.json({ success: true, sessions: results })
})

user.delete('/api/sessions', async (c) => {
    const payload = c.get('user')!
    if (payload.isOatLogin) return c.json({ success: false, message: 'action not permitted via OAT session' }, 403)
    
    const id = c.req.query('id')
    if (!id) return c.json({ success: false, message: 'missing id' }, 400)

    await c.env.DB.prepare('DELETE FROM sessions WHERE id = ? AND uid = ?').bind(id, payload.uid).run()
    return c.json({ success: true })
})

user.delete('/api/sessions/others', async (c) => {
    const payload = c.get('user')!
    if (payload.isOatLogin) return c.json({ success: false, message: 'action not permitted via OAT session' }, 403)

    await c.env.DB.batch([
        c.env.DB.prepare('DELETE FROM sessions WHERE uid = ? AND id != ?').bind(payload.uid, payload.sessionId),
        c.env.DB.prepare('DELETE FROM oats WHERE uid = ?').bind(payload.uid)
    ])

    return c.json({ success: true })
})

// OATs (Opaque Auth Tickets)
user.get('/api/oats', async (c) => {
    const payload = c.get('user')!
    const oats = await c.env.DB.prepare('SELECT id, label, created_at FROM oats WHERE uid = ? ORDER BY created_at DESC').bind(payload.uid).all<OatRecord>()
    return c.json({ success: true, oats: oats.results })
})

user.post('/api/oats', async (c) => {
    const payload = c.get('user')!
    const formData = await c.req.parseBody()
    const label = (formData['label'] as string) || 'New OAT'

    const countObj = await c.env.DB.prepare('SELECT COUNT(*) as count FROM oats WHERE uid = ?').bind(payload.uid).first<{ count: number }>()
    if (countObj && countObj.count >= 3) return c.json({ success: false, message: 'max 3 OATs allowed' }, 400)

    const rawHex = (crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, ''))
    const rawTicket = 'OAT-' + rawHex.substring(0, 32)
    const hashedTicket = await sha256(rawTicket)

    await c.env.DB.prepare('INSERT INTO oats (uid, hashed_ticket, label, created_at) VALUES (?, ?, ?, ?)')
        .bind(payload.uid, hashedTicket, label, Date.now())
        .run()

    return c.json({ success: true, ticket: rawTicket })
})

user.delete('/api/oats', async (c) => {
    const payload = c.get('user')!
    const id = c.req.query('id')
    if (!id) return c.json({ success: false, message: 'missing id' }, 400)
    
    await c.env.DB.prepare('DELETE FROM oats WHERE id = ? AND uid = ?').bind(id, payload.uid).run()
    return c.json({ success: true })
})

export default user
