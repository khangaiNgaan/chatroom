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
        const isSecure = url.protocol === 'https:';
        const cookieHeader = serialize('session', '', {
            httpOnly: true,
            secure: isSecure,
            sameSite: 'lax',
            maxAge: 0, // 立即过期
            path: '/'
        });
        
        // 如果是 GET 请求 (比如链接点击)，重定向回首页
        
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

        // 验证用户名格式 (仅允许字母、数字、下划线、减号)
        if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
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

        // 2.4 生成 JWT
        const token = await new SignJWT({ 
            uid: user.uid, 
            username: user.username, 
            role: user.role 
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
    // 3. 聊天室 WebSocket 路由
    // ==================================================
    const ALLOWED_CHATROOMS = ["bulletin", "general", "irl", "news", "debug", "minecraft"];
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

/**
 * 验证 Cloudflare Turnstile
 */
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

/**
 * 生成下一个 UID
 * 规则: 系统 01xxx, 用户 02xxx
 * 查找以 02 开头的最大 UID，+1。如果没有，从 02001 开始。
 */
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
    this.history = [];  

    this.state.blockConcurrencyWhile(async () => {
      let stored = await this.state.storage.get("history");
      this.history = stored || [];
    });
  }

  async fetch(request) {
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

    const [client, server] = Object.values(new WebSocketPair());
    
    // 2. 将用户信息传递给 Session 处理函数
    await this.handleSession(server, username, role, uid);
    
    return new Response(null, { status: 101, webSocket: client });
  }

  async handleSession(socket, username, role, uid) {
    socket.accept();
    
    // 附加上用户信息
    socket.userData = { username, role, uid };
    this.sessions.push(socket);

    // 发送历史记录 (确保历史记录是 JSON 字符串)
    this.history.forEach(msg => {
      // 兼容旧的历史记录格式
      // 为了前端方便，最好统一发 JSON 字符串
      if (typeof msg === 'string' && !msg.startsWith('{')) {
          socket.send(JSON.stringify({ 
              sender: "anonymous", 
              text: msg, 
              timestamp: 0 
          }));
      } else {
          socket.send(msg); 
      }
    });

    socket.addEventListener("message", async (msg) => {
      const data = msg.data;

      // 命令处理
      if (data === "/clear") {
        if (socket.userData.role !== 'admin') {
          socket.send(JSON.stringify({
            sender: "system",
            text: "permission denied.",
            timestamp: Date.now()
          }));
          return;
        }

        this.history = [];
        await this.state.storage.delete("history");
        
        const clearMsg = JSON.stringify({
            sender: "system",
            text: `chat history cleared by ${socket.userData.username}(${socket.userData.uid}).`,
            timestamp: Date.now()
        });

        this.broadcast(clearMsg);
        this.saveMessage(clearMsg);
        return; 
      }
      
      // 构建消息对象
      const messageObj = {
          sender: socket.userData.username,
          text: data,
          timestamp: Date.now()
      };
      
      const messageString = JSON.stringify(messageObj);

      // 保存并广播
      this.saveMessage(messageString);
      this.broadcast(messageString, socket);
    });

    const closeHandler = () => {
      this.sessions = this.sessions.filter(s => s !== socket);
    };
    socket.addEventListener("close", closeHandler);
    socket.addEventListener("error", closeHandler);
  }

  // 辅助函数: 处理存储逻辑
  async saveMessage(message) {
    // message 已经是 JSON 字符串了
    this.history.push(message);

    if (this.history.length > 20) {
      this.history.shift(); 
    }

    await this.state.storage.put("history", this.history);
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