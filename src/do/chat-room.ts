import { DurableObject } from 'cloudflare:workers'
import { jwtVerify } from 'jose'
import { Bindings } from '../types'

export class ChatRoom extends DurableObject {
    state: any
    env: Bindings
    sessions: any[]

    constructor(state: any, env: Bindings) {
        super(state, env)
        this.state = state
        this.env = env
        this.sessions = []
    }

    async fetch(request: Request) {
        const url = new URL(request.url)

        // 处理内部获取用户列表的请求
        if (url.pathname === "/users") {
            const uniqueUsers = new Map()   
            this.sessions.forEach(session => {
                if (session.readyState === WebSocket.READY_STATE_OPEN && session.userData) {
                    if (!uniqueUsers.has(session.userData.uid)) {
                        uniqueUsers.set(session.userData.uid, {
                            username: session.userData.username,
                            uid: session.userData.uid,
                            role: session.userData.role
                        })
                    }
                }
            })
            return new Response(JSON.stringify(Array.from(uniqueUsers.values())), {
                headers: { "Content-Type": "application/json" }
            })
        }
        if (url.pathname === "/history") {
            const cursor = url.searchParams.get("cursor")
            return this.getHistory(cursor)
        }
        if (url.pathname === "/export") {
            const limitParam = url.searchParams.get("limit")
            return this.exportHistory(limitParam)
        }
        if (request.headers.get("Upgrade") !== "websocket") {
            return new Response("Expected Upgrade: websocket", { status: 426 })
        }
        let username, role, uid
        try {
            const cookieHeader = request.headers.get("Cookie")
            if (!cookieHeader) throw new Error("Missing cookie header")
        
            // Simple cookie parse
            const getCookie = (name: string) => {
                const value = `; ${cookieHeader}`
                const parts = value.split(`; ${name}=`)
                if (parts.length === 2) return parts.pop()?.split(';').shift()
            }
            const sessionToken = getCookie('session')

            if (!sessionToken) throw new Error("Missing session cookie")
            if (!this.env.JWT_SECRET) {
                throw new Error("Server configuration error: JWT_SECRET missing")
            }
            const JWT_SECRET = new TextEncoder().encode(this.env.JWT_SECRET)
            const { payload } = await jwtVerify(sessionToken, JWT_SECRET)      
            if (!payload.uid || !payload.username) {
                throw new Error("Invalid session content")
            }

            username = payload.username
            role = payload.role || "user"
            uid = payload.uid

        } catch (e: any) {
            console.log("WebSocket Auth Failed:", e.message)
            return new Response("Unauthorized: Please login to access chatrooms", { status: 401 })
        }

        let roomName = "unknown"
        const pathParts = url.pathname.split("/")
        if (pathParts.length >= 3 && pathParts[1] === "websocket") {
            roomName = pathParts[2]
        }

        const { 0: client, 1: server } = new WebSocketPair()
        await this.handleSession(server as unknown as WebSocket, username, role, uid, roomName)
        return new Response(null, { status: 101, webSocket: client })
    }

    async handleSession(socket: any, username: any, role: any, uid: any, roomName: any) {
        socket.accept()
        socket.userData = { username, role, uid, roomName }
        this.sessions.push(socket)
        await this.pushRecentHistory(socket)
        socket.addEventListener("message", async (msg: any) => {
            const data = msg.data

            if (data.startsWith("/")) {
                console.log(`Received command from ${socket.userData.username}: ${data}`)
                const args = data.split(" ")
                const command = args[0]

                if (command === "/clear") {
                    if (socket.userData.role !== 'admin') {
                            socket.send(JSON.stringify({
                                sender_username: "system",
                                text: "permission denied.",
                                timestamp: Date.now()
                            }))
                            return
                    }

                    const list = await this.state.storage.list({ prefix: "msg-" })
                    const keys = Array.from(list.keys())
                    if (keys.length > 0) {
                        await this.state.storage.delete(keys)
                    }
            
                    const clearMsg = {
                        msg_id: this.generateMsgId(),
                        sender_username: "system",
                        sender_uid: "00001",
                        text: `chat history cleared by ${socket.userData.username}(${socket.userData.uid}).`,
                        timestamp: Date.now(),
                        channel: roomName
                    }
                    const clearMsgStr = JSON.stringify(clearMsg)
                    this.broadcast(clearMsgStr)
                    this.saveMessage(clearMsg)
                    return 
                }

                if (command === "/wipe") {
                    if (socket.userData.role !== 'admin') {
                            socket.send(JSON.stringify({
                                sender_username: "system",
                                text: "permission denied.",
                                timestamp: Date.now()
                            }))
                            return
                    }

                    const targetMsgId = args[1]
                    if (!targetMsgId || !targetMsgId.startsWith("msg-")) {
                        socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "usage: /wipe <msg-id>",
                            timestamp: Date.now()
                        }))
                        return
                    }

                    await this.state.storage.delete(targetMsgId)

                    const wipeMsg = {
                        sender_username: "system",
                        sender_uid: "00001",
                        channel: roomName,
                        text: `message ${targetMsgId} wiped by ${socket.userData.username}.`,
                        timestamp: Date.now()
                    }

                    socket.send(JSON.stringify(wipeMsg))
                    return
                }

                if (command === "/del") {
                    const targetMsgId = args[1]
                    if (!targetMsgId || !targetMsgId.startsWith("msg-")) {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "usage: /del <msg-id>",
                            timestamp: Date.now()
                        }))
                        return
                    }

                    const msg: any = await this.state.storage.get(targetMsgId)
                    if (!msg) {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "message not found.",
                            timestamp: Date.now()
                        }))
                        return
                    }

                    if (msg.sender_uid !== socket.userData.uid) {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "permission denied. you can only delete your own messages.",
                            timestamp: Date.now()
                        }))
                        return
                    }

                    const originalText = msg.text
                    const originalTime = msg.timestamp

                    msg.text = "<deleted>"
                    msg.is_deleted = true
                    await this.state.storage.put(targetMsgId, msg)

                    const delNotify = {
                        sender_username: "system",
                        sender_uid: "00001",
                        channel: roomName,
                        text: `message ${targetMsgId} (${originalText}) from ${new Date(originalTime).toISOString()} was deleted.`,
                        timestamp: Date.now()
                    }
                    
                    const notifyStr = JSON.stringify(delNotify)
                    socket.send(notifyStr)
                    
                    this.broadcast(JSON.stringify(msg))
                    return
                }

                if (command === "/censor") {
                    if (socket.userData.role !== 'admin') {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "permission denied.",
                            timestamp: Date.now()
                        }))
                        return
                    }

                    const targetMsgId = args[1]
                    const reason = args.slice(2).join(" ")

                    if (!targetMsgId || !targetMsgId.startsWith("msg-")) {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "usage: /censor <msg-id> <reason>",
                            timestamp: Date.now()
                        }))
                        return
                    }

                    const msg: any = await this.state.storage.get(targetMsgId)
                    if (!msg) {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "message not found.",
                            timestamp: Date.now()
                        }))
                        return
                    }

                    const censorText = reason 
                        ? `<censored by ${socket.userData.username}: ${reason}>` 
                        : `<censored by ${socket.userData.username}>`
                    
                    const originalText = msg.text
                    msg.text = censorText
                    msg.is_censored = true

                    await this.state.storage.put(targetMsgId, msg)

                    const censorNotify = {
                        sender_username: "system",
                        sender_uid: "00001",
                        channel: roomName,
                        text: `message ${targetMsgId} (${originalText}) was censored by ${socket.userData.username}.`,
                        timestamp: Date.now()
                    }
                    
                    const notifyStr = JSON.stringify(censorNotify)
                    socket.send(notifyStr)

                    this.broadcast(JSON.stringify(msg))
                    return
                }

                if (command === "/insert") {
                    if (socket.userData.role !== 'admin') {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "permission denied.",
                            timestamp: Date.now()
                        }))
                        return
                    }

                    const targetTimestamp = parseInt(args[1])
                    const text = args.slice(2).join(" ")

                    if (isNaN(targetTimestamp) || !text) {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "usage: /insert <timestamp> <text>",
                            timestamp: Date.now()
                        }))
                        return
                    }

                    const msgId = this.generateMsgId(targetTimestamp)
                    const msg = {
                        msg_id: msgId,
                        sender_username: socket.userData.username,
                        sender_uid: socket.userData.uid,
                        channel: roomName,
                        timestamp: targetTimestamp,
                        text: text
                    }

                    await this.saveMessage(msg)
                    this.broadcast(JSON.stringify(msg))
                    return
                }

                if (command === "/help") {
                    let helpText = "Commands:<br>"
                    helpText += "/del <msg-id> (soft delete your own message)<br>"
                    helpText += "/save (save chat history in this room)<br>"
                    
                    if (socket.userData.role === 'admin') {
                        helpText += "<br>Admin Commands:<br>"
                        helpText += "/clear (clear all messages in this room)<br>"
                        helpText += "/wipe <msg-id> (permanently remove a message)<br>"
                        helpText += "/censor <msg-id> <reason> (censor a message with optional reason)<br>"
                        helpText += "/insert <timestamp> <text> (insert a message at specific time)<br>"
                    }

                    socket.send(JSON.stringify({
                        sender_username: "system",
                        text: helpText,
                        timestamp: Date.now()
                    }))
                    return
                }

                socket.send(JSON.stringify({
                    sender: "system",
                    text: `unknown command: ${command}`,
                    timestamp: Date.now()
                }))
                return
            }
      
            const timestamp = Date.now()
            const msgId = this.generateMsgId(timestamp)

            const messageObj = {
                msg_id: msgId,
                sender_username: socket.userData.username,
                sender_uid: socket.userData.uid,
                channel: roomName,
                timestamp: timestamp,
                text: data
            }
      
            const messageString = JSON.stringify(messageObj)

            await this.saveMessage(messageObj)
            this.broadcast(messageString, socket)
        })

        const closeHandler = () => {
            this.sessions = this.sessions.filter(s => s !== socket)
        }
        socket.addEventListener("close", closeHandler)
        socket.addEventListener("error", closeHandler)
    }

    generateMsgId(timestamp = Date.now()) {
        const randomHex = Math.floor(Math.random() * 0xFFFFF).toString(16).padStart(5, '0')
        return `msg-${timestamp}-${randomHex}`
    }

    async saveMessage(messageObj: any) {
        await this.state.storage.put(messageObj.msg_id, messageObj)
    }

    async getHistory(cursor: any) {
        const options: any = {
            prefix: "msg-",
            limit: 20,
            reverse: true 
        }

        if (cursor) {
            options.end = cursor
        }

        const list: any = await this.state.storage.list(options)
        const messages = Array.from(list.values())
        
        messages.reverse()

        return new Response(JSON.stringify({ success: true, messages }), {
            headers: { "Content-Type": "application/json" }
        })
    }

    async exportHistory(limitParam: any) {
        let limit = Infinity
        if (limitParam && limitParam !== "all") {
            limit = parseInt(limitParam, 10)
            if (isNaN(limit) || limit <= 0) {
                 return new Response("Invalid limit", { status: 400 })
            }
        }
        
        const allMessages = []
        let cursor = null
        let hasMore = true

        while (hasMore) {
            const options: any = {
                prefix: "msg-",
                limit: 1000, 
                reverse: true 
            }
            
            if (limit !== Infinity) {
                const remaining = limit - allMessages.length
                if (remaining <= 0) break
                if (remaining < 1000) options.limit = remaining
            }

            if (cursor) {
                options.end = cursor
            }

            const list: any = await this.state.storage.list(options)
            const batch = Array.from(list.values())
            
            if (batch.length === 0) {
                hasMore = false
            } else {
                allMessages.push(...batch)
                cursor = Array.from(list.keys()).pop()
                
                if (batch.length < options.limit) {
                    hasMore = false
                }
            }
        }

        allMessages.reverse()

        return new Response(JSON.stringify({ success: true, messages: allMessages }), {
            headers: { "Content-Type": "application/json" }
        })
    }

    async pushRecentHistory(socket: any) {
        const list: any = await this.state.storage.list({
            prefix: "msg-",
            limit: 50,
            reverse: true 
        })
        const messages = Array.from(list.values()).reverse()

        for (const msg of messages) {
            const compatibleMsg = {
                ...(msg as any),
                sender: (msg as any).sender_username 
            }
            socket.send(JSON.stringify(compatibleMsg))
        }
    }

    broadcast(message: string, senderSocket?: any) {
        this.sessions.forEach(session => {
            if (session.readyState === WebSocket.READY_STATE_OPEN && session !== senderSocket) {
                try {
                    session.send(message)
                } catch (err) {
                    session.close()
                }
            }
        })
    }
}
