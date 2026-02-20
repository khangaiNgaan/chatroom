import { Hono } from 'hono'
import { Bindings, Variables } from '../types'
import { authMiddleware } from '../middleware/auth'

const chat = new Hono<{ Bindings: Bindings, Variables: Variables }>()
const ALLOWED_CHATROOMS = ["bulletin", "general", "irl", "news", "debug", "minecraft"]

// Middleware for /api/room routes to check if room exists
const checkRoom = async (c: any, next: any) => {
    const room = c.req.param('room')
    if (!ALLOWED_CHATROOMS.includes(room)) {
        return c.text('room not found', 404)
    }
    await next()
}

// 1. Online Users (Aggregate from all rooms)
chat.get('/api/online-users', authMiddleware, async (c) => {
    const results: any[] = []
    
    await Promise.all(ALLOWED_CHATROOMS.map(async (roomName) => {
        const id = c.env.CHAT_ROOM.idFromName(roomName)
        const stub = c.env.CHAT_ROOM.get(id)
        // Internal DO API
        const response = await stub.fetch("http://internal/users")
        if (response.ok) {
            const roomUsers = await response.json() as any[]
            roomUsers.forEach(u => {
                results.push({
                    username: u.username,
                    uid: u.uid,
                    role: u.role,
                    channel: roomName
                })
            })
        }
    }))

    return c.json({ success: true, users: results })
})

// 2. Room History
chat.get('/api/room/:room/history', authMiddleware, checkRoom, async (c) => {
    const roomName = c.req.param('room')
    const id = c.env.CHAT_ROOM.idFromName(roomName)
    const stub = c.env.CHAT_ROOM.get(id)
    
    const url = new URL(c.req.url)
    const doUrl = new URL("http://internal/history")
    doUrl.search = url.search
    
    return stub.fetch(new Request(doUrl.toString(), c.req.raw))
})

// 3. Room Export
chat.get('/api/room/:room/export', authMiddleware, checkRoom, async (c) => {
    const roomName = c.req.param('room')
    const id = c.env.CHAT_ROOM.idFromName(roomName)
    const stub = c.env.CHAT_ROOM.get(id)
    
    const url = new URL(c.req.url)
    const doUrl = new URL("http://internal/export")
    doUrl.search = url.search
    
    return stub.fetch(new Request(doUrl.toString(), c.req.raw))
})

// 4. WebSocket (Public, DO handles auth)
chat.get('/websocket/:room', async (c) => {
    const roomName = c.req.param('room')
    if (!ALLOWED_CHATROOMS.includes(roomName)) {
        return c.text('room not found', 404)
    }
    
    const id = c.env.CHAT_ROOM.idFromName(roomName)
    const stub = c.env.CHAT_ROOM.get(id)
    
    return stub.fetch(c.req.raw)
})

export default chat
