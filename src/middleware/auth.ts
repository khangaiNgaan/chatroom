import { Context, Next } from 'hono'
import { getCookie } from 'hono/cookie'
import { jwtVerify } from 'jose'
import { Bindings, Variables } from '../types'
import { Session } from '../models'

export const authMiddleware = async (c: Context<{ Bindings: Bindings, Variables: Variables }>, next: Next) => {
    const sessionToken = getCookie(c, 'session')
    
    if (!sessionToken) {
        return c.body(null, 401)
    }

    if (!c.env.JWT_SECRET) {
        console.error('Missing JWT_SECRET')
        return c.json({ success: false, message: 'Server Configuration Error' }, 500)
    }

    try {
        const secret = new TextEncoder().encode(c.env.JWT_SECRET)
        const { payload } = await jwtVerify(sessionToken, secret)

        const userPayload = {
            uid: payload.uid as string,
            username: payload.username as string,
            role: payload.role as string,
            sessionId: payload.sessionId as string
        }

        // Check DB session if sessionId exists
        if (userPayload.sessionId) {
            const session = await c.env.DB.prepare('SELECT id FROM sessions WHERE id = ?')
                .bind(userPayload.sessionId)
                .first<Session>()

            if (!session) {
                throw new Error('Session invalid or revoked')
            }
        }

        c.set('user', userPayload)
        await next()

    } catch (e) {
        return c.body(null, 401)
    }
}
