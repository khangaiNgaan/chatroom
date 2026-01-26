import bcrypt from 'bcryptjs';
import { serialize, parse } from 'cookie';
import { SignJWT, jwtVerify } from 'jose';

/* Worker 入口 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!env.JWT_SECRET) {
        return new Response("Internal Server Error: JWT_SECRET is not configured.", { status: 500 });
    }
    const JWT_SECRET = new TextEncoder().encode(env.JWT_SECRET);
    const ALLOWED_CHATROOMS = ["bulletin", "general", "irl", "news", "debug", "minecraft"];

    // ==================================================
    // 0. API: 获取当前用户信息 (GET /api/user)
    // ==================================================
    if (request.method === "GET" && url.pathname === "/api/user") {
        const cookieHeader = request.headers.get("Cookie");
        if (!cookieHeader) return new Response(null, { status: 401 });
        
        const cookies = parse(cookieHeader);
        if (!cookies.session) return new Response(null, { status: 401 });

        try {
            // 1. 验证 JWT
            const { payload } = await jwtVerify(cookies.session, JWT_SECRET);

            // Check DB session if sessionId exists in payload
            if (payload.sessionId) {
                const sessionRecord = await env.DB.prepare("SELECT id FROM sessions WHERE id = ?").bind(payload.sessionId).first();
                if (!sessionRecord) {
                    throw new Error("Session invalid");
                }
            }
            
            // 2. 从数据库获取详细信息
            // 这样可以获取到 signup_date 等不在 Token 里的信息
            const user = await env.DB.prepare("SELECT uid, username, role, signup_date, email FROM users WHERE uid = ?")
                .bind(payload.uid)
                .first();

            if (user) {
                 return new Response(JSON.stringify(user), {
                    headers: { "Content-Type": "application/json" }
                });
            } else {
                // 数据库查不到 (罕见)，降级返回 Token 里的信息
                return new Response(JSON.stringify(payload), {
                    headers: { "Content-Type": "application/json" }
                });
            }

        } catch (e) {
            // Token 无效或过期
            return new Response(null, { status: 401 });
        }
    }

    // ==================================================
    // 0. API: 登出 (POST /api/logout)
    // ==================================================
    if ((request.method === "POST" || request.method === "GET") && url.pathname === "/api/logout") {
        // Try to delete session from DB
        try {
            const cookieHeader = request.headers.get("Cookie");
            if (cookieHeader) {
                const cookies = parse(cookieHeader);
                if (cookies.session) {
                    const { payload } = await jwtVerify(cookies.session, JWT_SECRET);
                    if (payload.sessionId) {
                        await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(payload.sessionId).run();
                    }
                }
            }
        } catch (e) {
            // Ignore errors during logout (e.g. invalid token)
        }

        const isSecure = url.protocol === 'https:';
        const cookieHeader = serialize('session', '', {
            httpOnly: true,
            secure: isSecure,
            sameSite: 'lax',
            maxAge: 0, // 立即过期
            path: '/'
        });
        
        // 如果是 GET 请求，重定向回首页
        if (request.method === "GET") {
             return new Response(null, {
                status: 302,
                headers: { 
                    'Location': '/',
                    'Set-Cookie': cookieHeader
                }
            });
        }

        return new Response("Logged out", {
            status: 200,
            headers: { 'Set-Cookie': cookieHeader }
        });
    }

    // ==================================================
    // 1. 注册逻辑 (POST /api/signup)
    // ==================================================
    if (request.method === "POST" && url.pathname === "/api/signup") {
        try {
            const formData = await request.formData();
            const username = formData.get("username");
            const password = formData.get("password");
            const confirmPassword = formData.get("confirm-password");
            const inviteCode = formData.get("invite-code");
            const turnstileToken = formData.get("cf-turnstile-response");
            const ip = request.headers.get("CF-Connecting-IP");

            // 1.1 Turnstile 验证
            const SECRET_KEY = env.TURNSTILE_SECRET_KEY; 
            if (!SECRET_KEY) {
                return new Response(JSON.stringify({ success: false, message: "server config error: missing turnstile key" }), { 
                    status: 500,
                    headers: { "Content-Type": "application/json" }
                });
            }
            const verification = await verifyTurnstile(turnstileToken, SECRET_KEY, ip);
            if (!verification.success) {
                return new Response(JSON.stringify({ success: false, message: "security check failed (turnstile)" }), { 
                    status: 403,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // 1.2 基础验证
            if (password !== confirmPassword) {
                return new Response(JSON.stringify({ success: false, message: "passwords do not match" }), { 
                    status: 400,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // 验证用户名格式 (仅允许字母、数字、下划线) 4-16字符
            if (!/^\w{4,16}$/.test(username)) {
                return new Response(JSON.stringify({ success: false, message: "username contains invalid characters" }), { 
                    status: 400,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // 1.3 验证邀请码
            const invite = await env.DB.prepare("SELECT * FROM invites WHERE code = ?").bind(inviteCode).first();
            if (!invite) {
                return new Response(JSON.stringify({ success: false, message: "invalid invite code" }), { 
                    status: 400,
                    headers: { "Content-Type": "application/json" }
                });
            }
            if (invite.is_used === 1) {
                return new Response(JSON.stringify({ success: false, message: "invite code already used" }), { 
                    status: 400,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // 1.4 检查用户名是否已存在
            const existingUser = await env.DB.prepare("SELECT uid FROM users WHERE username = ?").bind(username).first();
            if (existingUser) {
                return new Response(JSON.stringify({ success: false, message: "username already taken" }), { 
                    status: 400,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // 1.5 生成 UID
            const newUid = await generateNextUid(env);

            // 1.6 密码加密
            const hashedPassword = await bcrypt.hash(password, 10);

            // 1.7 写入数据库 (事务: 创建用户 + 标记邀请码已用)
            await env.DB.batch([
                env.DB.prepare("INSERT INTO users (uid, username, password, email, signup_date) VALUES (?, ?, ?, ?, ?)")
                    .bind(newUid, username, hashedPassword, null, Date.now()),
                env.DB.prepare("UPDATE invites SET is_used = 1, used_by_uid = ? WHERE code = ?")
                    .bind(newUid, inviteCode)
            ]);

            return new Response(JSON.stringify({ success: true, message: "sign up successful! please login." }), { 
                status: 200,
                headers: { "Content-Type": "application/json" }
            });

        } catch (err) {
            return new Response(JSON.stringify({ success: false, message: "sign up error: " + err.message }), { 
                status: 500,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    // ==================================================
    // 2. 登录逻辑 (POST /api/login)
    // ==================================================
    if (request.method === "POST" && url.pathname === "/api/login") {
        try {
            const formData = await request.formData();
            
            // 2.0 Access Token 登录
            const accessToken = formData.get("access_token");
            const loginUsername = formData.get("username");

            if (accessToken) {
                // 获取 ID 和 UID
                const tokenRecord = await env.DB.prepare("SELECT id, uid FROM tokens WHERE token = ?").bind(accessToken).first();
                if (!tokenRecord) {
                    return new Response(JSON.stringify({ success: false, message: "invalid access token" }), { 
                        status: 403,
                        headers: { "Content-Type": "application/json" }
                    });
                }
                
                const user = await env.DB.prepare("SELECT * FROM users WHERE uid = ?").bind(tokenRecord.uid).first();
                if (!user) {
                    return new Response(JSON.stringify({ success: false, message: "user not found" }), { 
                        status: 404,
                        headers: { "Content-Type": "application/json" }
                    });
                }

                // 校验用户名是否匹配
                if (loginUsername && user.username !== loginUsername) {
                    return new Response(JSON.stringify({ success: false, message: "username does not match token owner" }), { 
                        status: 403,
                        headers: { "Content-Type": "application/json" }
                    });
                }

                // Create Session
                const sessionId = crypto.randomUUID();
                const ip = request.headers.get("CF-Connecting-IP") || "unknown";
                const userAgent = request.headers.get("User-Agent") || "unknown";
                const expiresAt = Date.now() + (90 * 24 * 60 * 60 * 1000); // 90 days

                await env.DB.prepare("INSERT INTO sessions (id, uid, ip, user_agent, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
                    .bind(sessionId, user.uid, ip, userAgent, Date.now(), expiresAt)
                    .run();

                // 生成 JWT (90天)
                const token = await new SignJWT({ 
                    uid: user.uid, 
                    username: user.username, 
                    role: user.role,
                    sessionId: sessionId
                })
                    .setProtectedHeader({ alg: 'HS256' })
                    .setIssuedAt()
                    .setExpirationTime('90d')
                    .sign(JWT_SECRET);

                const isSecure = url.protocol === 'https:';
                const cookieHeader = serialize('session', token, {
                    httpOnly: true,
                    secure: isSecure, 
                    domain: env.COOKIE_DOMAIN,
                    sameSite: 'lax',
                    maxAge: 60 * 60 * 24 * 90, 
                    path: '/'
                });

                // 销毁 Token (一次性使用)
                await env.DB.prepare("DELETE FROM tokens WHERE id = ?").bind(tokenRecord.id).run();

                return new Response(JSON.stringify({ success: true, message: "login successful" }), {
                    status: 200,
                    headers: {
                        'Set-Cookie': cookieHeader,
                        "Content-Type": "application/json"
                    }
                });
            }

            // 常规登录
            const username = formData.get("username");
            const password = formData.get("password");
            const turnstileToken = formData.get("cf-turnstile-response");
            const ip = request.headers.get("CF-Connecting-IP");

            // 2.1 Turnstile 验证
            const SECRET_KEY = env.TURNSTILE_SECRET_KEY;
            if (!SECRET_KEY) {
                return new Response(JSON.stringify({ success: false, message: "server config error: missing turnstile key" }), { 
                    status: 500,
                    headers: { "Content-Type": "application/json" }
                });
            }
            const verification = await verifyTurnstile(turnstileToken, SECRET_KEY, ip);
            if (!verification.success) {
                return new Response(JSON.stringify({ success: false, message: "security check failed (turnstile)" }), { 
                    status: 403,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // 2.2 查找用户
            const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
            if (!user) {
                return new Response(JSON.stringify({ success: false, message: "invalid username or password" }), { 
                    status: 403,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // 2.3 验证密码
            const isValid = await bcrypt.compare(password, user.password);
            if (!isValid) {
                return new Response(JSON.stringify({ success: false, message: "invalid username or password" }), { 
                    status: 403,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // 2.4 Create Session & Generate JWT
            const sessionId = crypto.randomUUID();
            // ip is already defined above in the function
            const userAgent = request.headers.get("User-Agent") || "unknown";
            const expiresAt = Date.now() + (7 * 24 * 60 * 60 * 1000); // 7 days

            await env.DB.prepare("INSERT INTO sessions (id, uid, ip, user_agent, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
                .bind(sessionId, user.uid, ip, userAgent, Date.now(), expiresAt)
                .run();

            const token = await new SignJWT({ 
                uid: user.uid, 
                username: user.username, 
                role: user.role,
                sessionId: sessionId
            })
                .setProtectedHeader({ alg: 'HS256' })
                .setIssuedAt()
                .setExpirationTime('7d')
                .sign(JWT_SECRET);

            // 2.5 设置 Session Cookie
            // 动态判断是否需要 Secure 标记 (Safari 本地 HTTP 不支持 Secure Cookie)
            const isSecure = url.protocol === 'https:';

            const cookieHeader = serialize('session', token, {
                httpOnly: true,
                secure: isSecure, 
                domain: env.COOKIE_DOMAIN,
                sameSite: 'lax',
                maxAge: 60 * 60 * 24 * 7, // 7天
                path: '/'
            });

            return new Response(JSON.stringify({ success: true, message: "login successful" }), {
                status: 200,
                headers: {
                    'Set-Cookie': cookieHeader,
                    "Content-Type": "application/json"
                }
            });

        } catch (err) {
            return new Response(JSON.stringify({ success: false, message: "login error: " + err.message }), { 
                status: 500,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    // ==================================================
    //  Access Token 管理 (GET/POST/DELETE /api/tokens)
    // ==================================================
    if (url.pathname === "/api/tokens") {
        // 鉴权
        let uid;
        try {
            const cookieHeader = request.headers.get("Cookie");
            if (!cookieHeader) throw new Error("No cookie");
            const cookies = parse(cookieHeader);
            if (!cookies.session) throw new Error("No session");
            const { payload } = await jwtVerify(cookies.session, JWT_SECRET);
            uid = payload.uid;
        } catch (e) {
            return new Response(null, { status: 401 });
        }

        // GET: 获取列表
        if (request.method === "GET") {
            const tokens = await env.DB.prepare("SELECT id, label, created_at, token FROM tokens WHERE uid = ? ORDER BY created_at DESC").bind(uid).all();
            return new Response(JSON.stringify({ success: true, tokens: tokens.results }), {
                headers: { "Content-Type": "application/json" }
            });
        }

        // POST: 创建 Token
        if (request.method === "POST") {
            const formData = await request.formData();
            const label = formData.get("label") || "New Token";

            // 检查数量限制
            const countObj = await env.DB.prepare("SELECT COUNT(*) as count FROM tokens WHERE uid = ?").bind(uid).first();
            if (countObj.count >= 3) {
                 return new Response(JSON.stringify({ success: false, message: "max 3 tokens allowed" }), { 
                    status: 400,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // 生成 Token
            const rawToken = crypto.randomUUID().replace(/-/g, '') + crypto.randomUUID().replace(/-/g, '');
            const newToken = "AT-" + rawToken.substring(0, 32);

            await env.DB.prepare("INSERT INTO tokens (uid, token, label, created_at) VALUES (?, ?, ?, ?)")
                .bind(uid, newToken, label, Date.now())
                .run();

            return new Response(JSON.stringify({ success: true, token: newToken }), {
                headers: { "Content-Type": "application/json" }
            });
        }

        // DELETE: 删除 Token
        if (request.method === "DELETE") {
            const urlParams = new URLSearchParams(url.search);
            const id = urlParams.get("id");
             
            if (!id) {
                return new Response(JSON.stringify({ success: false, message: "missing id" }), { status: 400 });
            }

            await env.DB.prepare("DELETE FROM tokens WHERE id = ? AND uid = ?")
                .bind(id, uid)
                .run();
            
            return new Response(JSON.stringify({ success: true }), {
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    // ==================================================
    //  API: 获取在线用户 (GET /api/online-users)
    // ==================================================
    if (request.method === "GET" && url.pathname === "/api/online-users") {
        // 鉴权
        const cookieHeader = request.headers.get("Cookie");
        if (!cookieHeader) return new Response(null, { status: 401 });
        const cookies = parse(cookieHeader);
        if (!cookies.session) return new Response(null, { status: 401 });
        try {
            // 验证 JWT
            await jwtVerify(cookies.session, JWT_SECRET);
        } catch (e) {
            return new Response(null, { status: 401 });
        }

        const results = [];
        
        await Promise.all(ALLOWED_CHATROOMS.map(async (roomName) => {
            const id = env.CHAT_ROOM.idFromName(roomName);
            const stub = env.CHAT_ROOM.get(id);
            // 调用 DO 内部 API 获取该房间用户
            const response = await stub.fetch("http://internal/users");
            if (response.ok) {
                const roomUsers = await response.json();
                // 将房间名附加到用户数据中
                roomUsers.forEach(u => {
                    results.push({
                        username: u.username,
                        uid: u.uid,
                        role: u.role,
                        channel: roomName
                    });
                });
            }
        }));

        return new Response(JSON.stringify({ success: true, users: results }), {
            headers: { "Content-Type": "application/json" }
        });
    }

    // ==================================================
    //  API: 会话管理 (GET/DELETE /api/sessions)
    // ==================================================
    if (url.pathname === "/api/sessions") {
        const cookieHeader = request.headers.get("Cookie");
        if (!cookieHeader) return new Response(null, { status: 401 });
        const cookies = parse(cookieHeader);
        if (!cookies.session) return new Response(null, { status: 401 });
        
        let payload;
        try {
            const jwtRes = await jwtVerify(cookies.session, JWT_SECRET);
            payload = jwtRes.payload;
        } catch (e) {
            return new Response(null, { status: 401 });
        }

        // GET: List Sessions
        if (request.method === "GET") {
            // Clean up expired sessions first (lazy cleanup)
            await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(Date.now()).run();

            const sessions = await env.DB.prepare("SELECT * FROM sessions WHERE uid = ? ORDER BY created_at DESC")
                .bind(payload.uid)
                .all();
            
            // Mark current session
            const results = sessions.results.map(s => ({
                ...s,
                is_current: s.id === payload.sessionId
            }));

            return new Response(JSON.stringify({ success: true, sessions: results }), {
                headers: { "Content-Type": "application/json" }
            });
        }

        // DELETE: Revoke Session
        if (request.method === "DELETE") {
            const urlParams = new URLSearchParams(url.search);
            const id = urlParams.get("id");
            if (!id) return new Response("Missing id", { status: 400 });

            await env.DB.prepare("DELETE FROM sessions WHERE id = ? AND uid = ?")
                .bind(id, payload.uid)
                .run();
             
            return new Response(JSON.stringify({ success: true }), {
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    // ==================================================
    // 4. API: 历史记录 (GET /api/room/:room/history)
    // ==================================================
    const historyMatch = url.pathname.match(/^\/api\/room\/([^/]+)\/history$/);
    if (request.method === "GET" && historyMatch) {
        const roomName = historyMatch[1];
        if (!ALLOWED_CHATROOMS.includes(roomName)) {
            return new Response("room not found", { status: 404 });
        }
        const id = env.CHAT_ROOM.idFromName(roomName);
        const stub = env.CHAT_ROOM.get(id);
        
        // 转发请求到 DO (内部路径 /history)
        const doUrl = new URL("http://internal/history");
        doUrl.search = url.search; // 保留 cursor 参数
        
        return stub.fetch(new Request(doUrl, request));
    }

    // ==================================================
    // 3. 聊天室 WebSocket 路由
    // ==================================================
    const pathnameParts = url.pathname.split("/").filter(part => part.length > 0);

    if (pathnameParts[0] === "websocket") {
        const roomName = pathnameParts[1] || "general";
        if (!ALLOWED_CHATROOMS.includes(roomName)) {
            return new Response("Chatroom not found", { status: 404 });
        }
        const id = env.CHAT_ROOM.idFromName(roomName);
        const stub = env.CHAT_ROOM.get(id);
        return stub.fetch(request);
    }

    return new Response("Not found", { status: 404 });
  }
};

// ==================================================
// 辅助函数
// ==================================================

// 验证 Cloudflare Turnstile
async function verifyTurnstile(token, secretKey, ip) {
    const formData = new FormData();
    formData.append('secret', secretKey);
    formData.append('response', token);
    formData.append('remoteip', ip);

    const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        body: formData,
        method: 'POST',
    });

    return await result.json();
}


// 生成下一个 UID
// 规则: 系统 01xxx, 用户 02xxx
// 查找以 02 开头的最大 UID，+1。如果没有，从 02001 开始。

async function generateNextUid(env) {
    const prefix = "02";
    // 查找当前最大的 02 开头的 UID
    // 注意: 这里的 SQL 假设 UID 是 TEXT 类型，但内容是数字，我们可以用字符串排序
    const lastUser = await env.DB.prepare("SELECT uid FROM users WHERE uid LIKE ? ORDER BY uid DESC LIMIT 1")
        .bind(`${prefix}%`)
        .first();

    let nextId = 2001; // 默认起点

    if (lastUser) {
        // 解析 '02001' -> 2001
        const currentId = parseInt(lastUser.uid, 10);
        if (!isNaN(currentId)) {
            nextId = currentId + 1;
        }
    }

    // 格式化回 5位字符串: 2002 -> "02002"
    return nextId.toString().padStart(5, '0');
}

/* Durable Object 类 */


export class ChatRoom {
    constructor(state, env) {
        this.state = state; 
        this.env = env; // 保存 env 以便访问 JWT_SECRET
        this.sessions = [];
    }

    async fetch(request) {
        const url = new URL(request.url);

        // 处理内部获取用户列表的请求
        if (url.pathname === "/users") {
            // 提取当前会话中的唯一用户
            const uniqueUsers = new Map();
        
            this.sessions.forEach(session => {
                if (session.readyState === WebSocket.READY_STATE_OPEN && session.userData) {
                    // 使用 uid 作为 key 去重
                    if (!uniqueUsers.has(session.userData.uid)) {
                        uniqueUsers.set(session.userData.uid, {
                            username: session.userData.username,
                            uid: session.userData.uid,
                            role: session.userData.role
                        });
                    }
                }
            });

            return new Response(JSON.stringify(Array.from(uniqueUsers.values())), {
                headers: { "Content-Type": "application/json" }
            });
        }

        // API 获取历史记录
        if (url.pathname === "/history") {
            const cursor = url.searchParams.get("cursor");
            return this.getHistory(cursor);
        }

        if (request.headers.get("Upgrade") !== "websocket") {
            return new Response("Expected Upgrade: websocket", { status: 426 });
        }

        // 1. 获取用户信息并验证
        let username, role, uid;
        try {
            const cookieHeader = request.headers.get("Cookie");
            if (!cookieHeader) throw new Error("Missing cookie header");
        
            const cookies = parse(cookieHeader);
            if (!cookies.session) throw new Error("Missing session cookie");

            if (!this.env.JWT_SECRET) {
                throw new Error("Server configuration error: JWT_SECRET missing");
            }

            const JWT_SECRET = new TextEncoder().encode(this.env.JWT_SECRET);
            const { payload } = await jwtVerify(cookies.session, JWT_SECRET);
        
            if (!payload.uid || !payload.username) {
                throw new Error("Invalid session content");
            }

            username = payload.username;
            role = payload.role || "user";
            uid = payload.uid;

        } catch (e) {
            console.log("WebSocket Auth Failed:", e.message);
            return new Response("Unauthorized: Please login to access chatrooms", { status: 401 });
        }

        // 2. 解析房间名 (从 URL /websocket/:roomName 中提取)
        let roomName = "unknown";
        const pathParts = url.pathname.split("/");
        // url.pathname 类似 /websocket/general
        // split 后: ["", "websocket", "general"]
        if (pathParts.length >= 3 && pathParts[1] === "websocket") {
            roomName = pathParts[2];
        }

        const [client, server] = Object.values(new WebSocketPair());
        
        // 3. 将用户信息传递给 Session 处理函数
        await this.handleSession(server, username, role, uid, roomName);
        
        return new Response(null, { status: 101, webSocket: client });
    }

    async handleSession(socket, username, role, uid, roomName) {
        socket.accept();
        
        // 附加上用户信息
        socket.userData = { username, role, uid, roomName };
        this.sessions.push(socket);
        
        // 推送最近的历史消息
        await this.pushRecentHistory(socket);

        socket.addEventListener("message", async (msg) => {
            const data = msg.data;

            // 命令处理
            if (data.startsWith("/")) {
                console.log(`Received command from ${socket.userData.username}: ${data}`);
                const args = data.split(" ");
                const command = args[0];

                if (command === "/clear") {
                    if (socket.userData.role !== 'admin') {
                            socket.send(JSON.stringify({
                                sender_username: "system",
                                text: "permission denied.",
                                timestamp: Date.now()
                            }));
                            return;
                    }

                    const list = await this.state.storage.list({ prefix: "msg-" });
                    const keys = Array.from(list.keys());
                    if (keys.length > 0) {
                        await this.state.storage.delete(keys);
                    }
                    await this.state.storage.delete("history");
            
                    const clearMsg = {
                        msg_id: this.generateMsgId(),
                        sender_username: "system",
                        sender_uid: "00001",
                        text: `chat history cleared by ${socket.userData.username}(${socket.userData.uid}).`,
                        timestamp: Date.now(),
                        channel: roomName
                    };
                    const clearMsgStr = JSON.stringify(clearMsg);
                    this.broadcast(clearMsgStr);
                    this.saveMessage(clearMsg);
                    return; 
                }

                if (command === "/wipe") {
                    if (socket.userData.role !== 'admin') {
                            socket.send(JSON.stringify({
                                sender_username: "system",
                                text: "permission denied.",
                                timestamp: Date.now()
                            }));
                            return;
                    }

                    const targetMsgId = args[1];
                    if (!targetMsgId || !targetMsgId.startsWith("msg-")) {
                        socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "usage: /wipe <msg-id>",
                            timestamp: Date.now()
                        }));
                        return;
                    }

                    await this.state.storage.delete(targetMsgId);

                    const wipeMsg = {
                        sender_username: "system",
                        sender_uid: "00001",
                        channel: roomName,
                        text: `message ${targetMsgId} wiped by ${socket.userData.username}.`,
                        timestamp: Date.now()
                    };

                    socket.send(JSON.stringify(wipeMsg));
                    return;
                }

                if (command === "/del") {
                    const targetMsgId = args[1];
                    if (!targetMsgId || !targetMsgId.startsWith("msg-")) {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "usage: /del <msg-id>",
                            timestamp: Date.now()
                        }));
                        return;
                    }

                    const msg = await this.state.storage.get(targetMsgId);
                    if (!msg) {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "message not found.",
                            timestamp: Date.now()
                        }));
                        return;
                    }

                    // 鉴权：仅限本人
                    if (msg.sender_uid !== socket.userData.uid) {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "permission denied. you can only delete your own messages.",
                            timestamp: Date.now()
                        }));
                        return;
                    }

                    const originalText = msg.text;
                    const originalTime = msg.timestamp;

                    msg.text = "<deleted>";
                    msg.is_deleted = true;
                    await this.state.storage.put(targetMsgId, msg);

                    const delNotify = {
                        sender_username: "system",
                        sender_uid: "00001",
                        channel: roomName,
                        text: `message ${targetMsgId} (${originalText}) from ${new Date(originalTime).toISOString()} was deleted.`,
                        timestamp: Date.now()
                    };
                    
                    const notifyStr = JSON.stringify(delNotify);
                    socket.send(notifyStr);
                    
                    // 广播更新后的原消息
                    this.broadcast(JSON.stringify(msg));
                    return;
                }

                if (command === "/censor") {
                    if (socket.userData.role !== 'admin') {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "permission denied.",
                            timestamp: Date.now()
                        }));
                        return;
                    }

                    const targetMsgId = args[1];
                    const reason = args.slice(2).join(" "); // 获取剩余部分作为理由

                    if (!targetMsgId || !targetMsgId.startsWith("msg-")) {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "usage: /censor <msg-id> <reason>",
                            timestamp: Date.now()
                        }));
                        return;
                    }

                    const msg = await this.state.storage.get(targetMsgId);
                    if (!msg) {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "message not found.",
                            timestamp: Date.now()
                        }));
                        return;
                    }

                    // 修改内容
                    const censorText = reason 
                        ? `<censored by ${socket.userData.username}: ${reason}>` 
                        : `<censored by ${socket.userData.username}>`;
                    
                    const originalText = msg.text;
                    msg.text = censorText;
                    msg.is_censored = true;

                    await this.state.storage.put(targetMsgId, msg);

                    // 发送操作反馈
                    const censorNotify = {
                        sender_username: "system",
                        sender_uid: "00001",
                        channel: roomName,
                        text: `message ${targetMsgId} (${originalText}) was censored by ${socket.userData.username}.`,
                        timestamp: Date.now()
                    };
                    
                    const notifyStr = JSON.stringify(censorNotify);
                    socket.send(notifyStr);

                    // 广播更新
                    this.broadcast(JSON.stringify(msg));
                    return;
                }

                if (command === "/insert") {
                    if (socket.userData.role !== 'admin') {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "permission denied.",
                            timestamp: Date.now()
                        }));
                        return;
                    }

                    const targetTimestamp = parseInt(args[1]);
                    const text = args.slice(2).join(" ");

                    if (isNaN(targetTimestamp) || !text) {
                         socket.send(JSON.stringify({
                            sender_username: "system",
                            text: "usage: /insert <timestamp> <text>",
                            timestamp: Date.now()
                        }));
                        return;
                    }

                    // 生成消息
                    const msgId = this.generateMsgId(targetTimestamp);
                    const msg = {
                        msg_id: msgId,
                        sender_username: socket.userData.username,
                        sender_uid: socket.userData.uid,
                        channel: roomName,
                        timestamp: targetTimestamp,
                        text: text
                    };

                    // 保存并广播
                    await this.saveMessage(msg);
                    this.broadcast(JSON.stringify(msg));
                    return;
                }

                if (command === "/help") {
                    let helpText = "Commands:<br>";
                    helpText += "/del <msg-id> (soft delete your own message)<br>";
                    
                    if (socket.userData.role === 'admin') {
                        helpText += "<br>Admin Commands:<br>";
                        helpText += "/clear (clear all messages in this room)<br>";
                        helpText += "/wipe <msg-id> (permanently remove a message)<br>";
                        helpText += "/censor <msg-id> <reason> (censor a message with optional reason)<br>";
                        helpText += "/insert <timestamp> <text> (insert a message at specific time)<br>";
                    }

                    socket.send(JSON.stringify({
                        sender_username: "system",
                        text: helpText,
                        timestamp: Date.now()
                    }));
                    return;
                }

                socket.send(JSON.stringify({
                    sender: "system",
                    text: `unknown command: ${command}`,
                    timestamp: Date.now()
                }));
                return;
            }
      
            // 构建消息对象
            const timestamp = Date.now();
            const msgId = this.generateMsgId(timestamp);

            const messageObj = {
                msg_id: msgId,
                sender_username: socket.userData.username,
                sender_uid: socket.userData.uid,
                channel: roomName,
                timestamp: timestamp,
                text: data
            };
      
            const messageString = JSON.stringify(messageObj);

            // 保存并广播
            await this.saveMessage(messageObj);
            this.broadcast(messageString, socket);
        });

        const closeHandler = () => {
            this.sessions = this.sessions.filter(s => s !== socket);
        };
        socket.addEventListener("close", closeHandler);
        socket.addEventListener("error", closeHandler);
    }

    // 生成 MsgID: msg-{timestamp}-{hex}
    generateMsgId(timestamp = Date.now()) {
        const randomHex = Math.floor(Math.random() * 0xFFFFF).toString(16).padStart(5, '0');
        return `msg-${timestamp}-${randomHex}`;
    }

    // 辅助函数: 处理存储逻辑
    async saveMessage(messageObj) {
        await this.state.storage.put(messageObj.msg_id, messageObj);
    }

    // 辅助函数: 获取历史消息
    async getHistory(cursor) {
        const options = {
            prefix: "msg-",
            limit: 20,
            reverse: true // 获取最新的
        };

        if (cursor) {
            // 修正: 在 reverse: true (从新到旧) 模式下，我们要找比 cursor 更老(字典序更小)的消息
            // 所以 cursor 应该是 exclusive end
            options.end = cursor;
        }

        const list = await this.state.storage.list(options);
        const messages = Array.from(list.values());
        
        // 按时间正序返回
        messages.reverse();

        return new Response(JSON.stringify({ success: true, messages }), {
            headers: { "Content-Type": "application/json" }
        });
    }

    // 辅助函数: 推送最近历史记录给新连接的用户
    async pushRecentHistory(socket) {
        const list = await this.state.storage.list({
            prefix: "msg-",
            limit: 50,
            reverse: true 
        });
        const messages = Array.from(list.values()).reverse(); // 按时间正序

        for (const msg of messages) {
            const compatibleMsg = {
                ...msg,
                sender: msg.sender_username 
            };
            socket.send(JSON.stringify(compatibleMsg));
        }
    }

    broadcast(message, senderSocket) {
        this.sessions.forEach(session => {
            if (session.readyState === WebSocket.READY_STATE_OPEN && session !== senderSocket) {
                try {
                    session.send(message);
                } catch (err) {
                    session.close();
                }
            }
        });
    }
}
