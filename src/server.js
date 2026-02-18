import bcrypt from 'bcryptjs';
import { serialize, parse } from 'cookie';
import { SignJWT, jwtVerify } from 'jose';
import { generateSecret, generateURI, verify, generate } from 'otplib';
import QRCode from 'qrcode';

/* Worker 入口 */

export default {
  async fetch(request, env, ctx) {
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
            const user = await env.DB.prepare("SELECT uid, username, role, signup_date, email, email_verified, two_factor_enabled FROM users WHERE uid = ?")
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
    // 0.1 API: 修改密码 (POST /api/user/change-password)
    // ==================================================
    if (request.method === "POST" && url.pathname === "/api/user/change-password") {
        const cookieHeader = request.headers.get("Cookie");
        if (!cookieHeader) return new Response(null, { status: 401 });
        const cookies = parse(cookieHeader);
        if (!cookies.session) return new Response(null, { status: 401 });

        try {
            const { payload } = await jwtVerify(cookies.session, JWT_SECRET);
            const formData = await request.formData();
            const oldPassword = formData.get("old-password");
            const newPassword = formData.get("new-password");

            if (!oldPassword || !newPassword) {
                return new Response(JSON.stringify({ success: false, message: "missing parameters" }), { status: 400 });
            }

            // 获取用户当前密码
            const user = await env.DB.prepare("SELECT password FROM users WHERE uid = ?").bind(payload.uid).first();
            if (!user) return new Response(null, { status: 404 });

            // 验证旧密码
            const isValid = await bcrypt.compare(oldPassword, user.password);
            if (!isValid) {
                return new Response(JSON.stringify({ success: false, message: "current password incorrect" }), { status: 400 });
            }

            // 密码强度基本验证 (例如不少于 6 位)
            if (newPassword.length < 6) {
                return new Response(JSON.stringify({ success: false, message: "new password must be at least 6 characters" }), { status: 400 });
            }

            // 哈希新密码
            const hashedNewPassword = await bcrypt.hash(newPassword, 10);
            
            // 更新数据库
            await env.DB.prepare("UPDATE users SET password = ? WHERE uid = ?").bind(hashedNewPassword, payload.uid).run();

            return new Response(JSON.stringify({ success: true, message: "password updated successfully" }), {
                headers: { "Content-Type": "application/json" }
            });

        } catch (e) {
            return new Response(JSON.stringify({ success: false, message: "session invalid or expired" }), { status: 401 });
        }
    }

    // ==================================================
    // 0.2 API: 绑定邮箱 (POST /api/user/bind-email)
    // ==================================================
    if (request.method === "POST" && url.pathname === "/api/user/bind-email") {
        const cookieHeader = request.headers.get("Cookie");
        if (!cookieHeader) return new Response(null, { status: 401 });
        const cookies = parse(cookieHeader);
        if (!cookies.session) return new Response(null, { status: 401 });

        try {
            const { payload } = await jwtVerify(cookies.session, JWT_SECRET);
            const formData = await request.formData();
            const email = formData.get("email");

            if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                 return new Response(JSON.stringify({ success: false, message: "invalid email format" }), { status: 400 });
            }

            // 检查邮箱是否已被使用 (全局)
            const existing = await env.DB.prepare("SELECT uid FROM users WHERE email = ? AND email_verified = 1").bind(email).first();
            if (existing) {
                return new Response(JSON.stringify({ success: false, message: "email already in use" }), { status: 400 });
            }
            
            // 检查当前用户是否已有邮箱（如果有，则为 Change Email 操作，需验证密码）
            const currentUser = await env.DB.prepare("SELECT email, password, email_verified FROM users WHERE uid = ?").bind(payload.uid).first();
            if (currentUser && currentUser.email && currentUser.email_verified) {
                // 需要验证密码
                const password = formData.get("password");
                if (!password) {
                     return new Response(JSON.stringify({ success: false, message: "password required to change email" }), { status: 400 });
                }
                const isValid = await bcrypt.compare(password, currentUser.password);
                if (!isValid) {
                    return new Response(JSON.stringify({ success: false, message: "incorrect password" }), { status: 400 });
                }
            }

            const token = crypto.randomUUID();
            const now = Date.now();
            const expiresAt = now + 24 * 60 * 60 * 1000; // 24 hrs

            // 存入临时表
            await env.DB.prepare("INSERT OR REPLACE INTO email_verifications (token, uid, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?)")
                .bind(token, payload.uid, email, now, expiresAt)
                .run();

            // 发送邮件
            const verifyLink = `${url.origin}/auth/verify-email?token=${token}`;
            const htmlContent = `
                <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2>Verify your email</h2>
                    <p>Hi ${payload.username},</p>
                    <p>Please click the link below to verify your email address for your coffeeroom account.</p>
                    <p><a href="${verifyLink}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
                    <p>Or copy this link: ${verifyLink}</p>
                    <p>This link will expire in 24 hours.</p>
                    <p>If you didn't request this change, please ignore this email.</p>
                    <p>Support: <a href="mailto:support@caffeine.ink">support@caffeine.ink</a></p>
                </div>
            `;

            const sent = await sendEmail(env, email, "Verify your email - coffeeroom", htmlContent);
            
            if (sent) {
                return new Response(JSON.stringify({ success: true, message: "verification email sent" }), {
                    headers: { "Content-Type": "application/json" }
                });
            } else {
                 return new Response(JSON.stringify({ success: false, message: "failed to send email" }), { status: 500 });
            }

        } catch (e) {
            console.error(e);
            return new Response(JSON.stringify({ success: false, message: "session invalid or server error" }), { status: 401 });
        }
    }

    // ==================================================
    // 0.3 API: 验证邮箱 (GET /auth/verify-email)
    // ==================================================
    if (request.method === "GET" && url.pathname === "/auth/verify-email") {
        const token = url.searchParams.get("token");
        if (!token) return new Response("Missing token", { status: 400 });

        const record = await env.DB.prepare("SELECT * FROM email_verifications WHERE token = ?").bind(token).first();

        if (!record) {
             return new Response("Invalid or expired verification link.", { status: 400 });
        }

        if (record.expires_at < Date.now()) {
            await env.DB.prepare("DELETE FROM email_verifications WHERE token = ?").bind(token).run();
            return new Response("Verification link expired.", { status: 400 });
        }

        // 验证通过，更新用户表
        await env.DB.batch([
            env.DB.prepare("UPDATE users SET email = ?, email_verified = 1 WHERE uid = ?").bind(record.email, record.uid),
            env.DB.prepare("DELETE FROM email_verifications WHERE token = ?").bind(token)
        ]);

        return new Response(`
            <!DOCTYPE html>
            <html>
                <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta http-equiv="refresh" content="5;url=/user/settings.html" />
                <title>email verified - coffeeroom</title>
                <meta name="theme-color" content="#d8e3ed" media="(prefers-color-scheme: light)">
                <meta name="theme-color" content="#242931" media="(prefers-color-scheme: dark)">
                <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
                <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
                <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
                <link rel="manifest" href="/site.webmanifest">
                <style>
                    @font-face {
                        font-family: unifont;
                        src: url(../fonts/unifont.otf);
                    }
                    @font-face {
                        font-family: sentient;
                        font-weight: bold;
                        src: url(../fonts/Sentient-Bold.otf);
                    }

                    :root {
                        --bg-color: #d8e3ed;
                        --chat-bg-color: #eff3f7;
                        --popup-bg-color: rgba(255, 255, 255, 0.5);
                        --border-color: #808ea1;
                        --note-color: #69727d;
                        --text-color: #444f5d;
                        --highlight-color: #b7c2d0;
                        --pre-code-color: #ced9e3;
                        --button-color: #f4f7f9;
                        --button-hover-color: #ecf1f4;
                        --button-active-color: #dee4e8;
                        --msg-bg-color: #e1eaf1;
                        --connection-green: #347b68;
                        --connection-red: #c05858;
                        --success-color: #347b68;
                        --error-color: #c05858;
                        --my-nom-color: #5d8dc7;
                        --admin-nom-color: #d79a40;
                        --nom-color: #d868a3;
                    }
                    [data-theme="dark"] {
                        --bg-color: #242931;
                        --chat-bg-color: #2e3640;
                        --popup-bg-color: rgba(46, 54, 64, 0.5);
                        --border-color: #555c68;
                        --note-color: #888e9d;
                        --text-color: #e9f0f5;
                        --highlight-color: #444f5d;
                        --pre-code-color: #2e3640;
                        --button-color: #2e3640;
                        --button-hover-color: #444f5d;
                        --button-active-color: #39424e;
                        --msg-bg-color: #444f5d;
                        --connection-green: #A7D3A6;
                        --connection-red: #D67A85;
                        --success-color: #A7D3A6;
                        --error-color: #D67A85;
                        --my-nom-color: #A7C6EC;
                        --admin-nom-color: #F9E1BD; /* #C5E4C0 */
                        --nom-color: #E8A5C8;
                    }
                    [data-theme="mono"] {
                        --bg-color: #ffffff;
                        --chat-bg-color: #ffffff;
                        --popup-bg-color: #ffffff;
                        --border-color: #777777;
                        --note-color: #777777;
                        --text-color: #000000;
                        --highlight-color: #cccccc;
                        --pre-code-color: #dddddd;
                        --button-color: #ffffff;
                        --button-hover-color: #ffffff;
                        --button-active-color: #eeeeee;
                        --msg-bg-color: #ffffff;
                        --connection-green: #000000;
                        --connection-red: #000000;
                        --success-color: #000000;
                        --error-color: #000000;
                        --my-nom-color: #000000;
                        --admin-nom-color: #000000;
                        --nom-color: #000000;
                    }

                    body {
                        background-color: var(--bg-color);
                        color: var(--text-color);
                        max-width: 800px;
                        margin: 0 auto;
                        display: flex;
                        flex-direction: column;
                        min-height: 100vh;
                        box-sizing: border-box;
                    }

                    html {
                        background-color: var(--bg-color);
                    }

                    @media (max-width: 800px) {
                        body {
                            padding: 30px 15px 60px 15px;
                            margin: 0;
                        }
                    }

                    a {
                        color: var(--text-color);
                        cursor: pointer;
                        font-family: 'unifont', sans-serif;
                    }

                    a:hover {
                        background-color: var(--text-color);
                        color: var(--bg-color);
                    }

                    ::selection {
                        background-color: var(--text-color);
                        color: var(--bg-color);
                    }
                </style>
                <script>
                    (function() {
                        const savedMode = localStorage.getItem('theme-mode') || 'auto';
                        let isDark = false;
                        let isMono = false;
                        if (savedMode === 'auto') {
                            isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                        } else if (savedMode === 'mono') {
                            isMono = true;
                        } else {
                            isDark = (savedMode === 'dark');
                        }
                        if (isDark) {
                            document.documentElement.setAttribute('data-theme', 'dark');
                        } else if (isMono) {
                            document.documentElement.setAttribute('data-theme', 'mono');
                        }
                    })();
                </script>
                </head>
                <body>
                    <div style="height: 100vh; width: 100%; max-width: 500px; margin: 0 auto; display: flex; align-items: center; justify-content: center; box-sizing: border-box;">
                        <div style="border: 1px solid var(--border-color); background-color: var(--chat-bg-color); border-radius: 5px; padding: 20px; width: 100%; box-sizing: border-box; text-align: center;">
                            <div style="color: var(--success-color); font-size: 16px; margin-bottom: 10px; font-family: 'unifont', sans-serif;">Email Verified</div>
                            <div style="font-size: 14px; margin-bottom: 20px; font-family: 'unifont', sans-serif;">Your email <strong>${record.email}</strong> has been bound to your account.</div>
                            <div style="font-size: 12px; color: var(--note-color); font-family: 'unifont', sans-serif;">Redirecting to settings in 5 seconds...</div>
                            <br>
                            <div style="font-size: 14px;"><a href="/user/settings.html">Click here if not redirected</a></div>
                        </div>
                    </div>
                <script src="/scripts/theme.js"></script>
                </body>
            </html>
        `, {
            headers: { "Content-Type": "text/html" }
        });
    }

    // ==================================================
    // 0.3b API: 验证注册 (GET /auth/verify-registration)
    // ==================================================
    if (request.method === "GET" && url.pathname === "/auth/verify-registration") {
        const token = url.searchParams.get("token");
        if (!token) return new Response("Missing token", { status: 400 });

        const record = await env.DB.prepare("SELECT * FROM pending_registrations WHERE token = ?").bind(token).first();

        if (!record) {
             return new Response("Invalid or expired registration link.", { status: 400 });
        }

        if (record.expires_at < Date.now()) {
            await env.DB.prepare("DELETE FROM pending_registrations WHERE token = ?").bind(token).run();
            return new Response("Registration link expired. Please sign up again.", { status: 400 });
        }

        try {
            // 创建用户
            const newUid = await generateNextUid(env);
            
            await env.DB.batch([
                env.DB.prepare("INSERT INTO users (uid, username, password, email, email_verified, signup_date, original_email) VALUES (?, ?, ?, ?, 1, ?, ?)")
                    .bind(newUid, record.username, record.password_hash, record.email, Date.now(), record.email),
                env.DB.prepare("DELETE FROM pending_registrations WHERE token = ?").bind(token)
            ]);

            return new Response(`
                <!DOCTYPE html>
                <html>
                    <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <meta http-equiv="refresh" content="5;url=/auth/login.html" />
                    <title>email verified - coffeeroom</title>
                    <meta name="theme-color" content="#d8e3ed" media="(prefers-color-scheme: light)">
                    <meta name="theme-color" content="#242931" media="(prefers-color-scheme: dark)">
                    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
                    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
                    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
                    <link rel="manifest" href="/site.webmanifest">
                    <style>
                        @font-face {
                            font-family: unifont;
                            src: url(../fonts/unifont.otf);
                        }
                        @font-face {
                            font-family: sentient;
                            font-weight: bold;
                            src: url(../fonts/Sentient-Bold.otf);
                        }

                        :root {
                            --bg-color: #d8e3ed;
                            --chat-bg-color: #eff3f7;
                            --popup-bg-color: rgba(255, 255, 255, 0.5);
                            --border-color: #808ea1;
                            --note-color: #69727d;
                            --text-color: #444f5d;
                            --highlight-color: #b7c2d0;
                            --pre-code-color: #ced9e3;
                            --button-color: #f4f7f9;
                            --button-hover-color: #ecf1f4;
                            --button-active-color: #dee4e8;
                            --msg-bg-color: #e1eaf1;
                            --connection-green: #347b68;
                            --connection-red: #c05858;
                            --success-color: #347b68;
                            --error-color: #c05858;
                            --my-nom-color: #5d8dc7;
                            --admin-nom-color: #d79a40;
                            --nom-color: #d868a3;
                        }
                        [data-theme="dark"] {
                            --bg-color: #242931;
                            --chat-bg-color: #2e3640;
                            --popup-bg-color: rgba(46, 54, 64, 0.5);
                            --border-color: #555c68;
                            --note-color: #888e9d;
                            --text-color: #e9f0f5;
                            --highlight-color: #444f5d;
                            --pre-code-color: #2e3640;
                            --button-color: #2e3640;
                            --button-hover-color: #444f5d;
                            --button-active-color: #39424e;
                            --msg-bg-color: #444f5d;
                            --connection-green: #A7D3A6;
                            --connection-red: #D67A85;
                            --success-color: #A7D3A6;
                            --error-color: #D67A85;
                            --my-nom-color: #A7C6EC;
                            --admin-nom-color: #F9E1BD; /* #C5E4C0 */
                            --nom-color: #E8A5C8;
                        }
                        [data-theme="mono"] {
                            --bg-color: #ffffff;
                            --chat-bg-color: #ffffff;
                            --popup-bg-color: #ffffff;
                            --border-color: #777777;
                            --note-color: #777777;
                            --text-color: #000000;
                            --highlight-color: #cccccc;
                            --pre-code-color: #dddddd;
                            --button-color: #ffffff;
                            --button-hover-color: #ffffff;
                            --button-active-color: #eeeeee;
                            --msg-bg-color: #ffffff;
                            --connection-green: #000000;
                            --connection-red: #000000;
                            --success-color: #000000;
                            --error-color: #000000;
                            --my-nom-color: #000000;
                            --admin-nom-color: #000000;
                            --nom-color: #000000;
                        }

                        body {
                            background-color: var(--bg-color);
                            color: var(--text-color);
                            max-width: 800px;
                            margin: 0 auto;
                            display: flex;
                            flex-direction: column;
                            min-height: 100vh;
                            box-sizing: border-box;
                        }

                        html {
                            background-color: var(--bg-color);
                        }

                        @media (max-width: 800px) {
                            body {
                                padding: 30px 15px 60px 15px;
                                margin: 0;
                            }
                        }

                        a {
                            color: var(--text-color);
                            cursor: pointer;
                            font-family: 'unifont', sans-serif;
                        }

                        a:hover {
                            background-color: var(--text-color);
                            color: var(--bg-color);
                        }

                        ::selection {
                            background-color: var(--text-color);
                            color: var(--bg-color);
                        }
                    </style>
                    <script>
                        (function() {
                            const savedMode = localStorage.getItem('theme-mode') || 'auto';
                            let isDark = false;
                            let isMono = false;
                            if (savedMode === 'auto') {
                                isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                            } else if (savedMode === 'mono') {
                                isMono = true;
                            } else {
                                isDark = (savedMode === 'dark');
                            }
                            if (isDark) {
                                document.documentElement.setAttribute('data-theme', 'dark');
                            } else if (isMono) {
                                document.documentElement.setAttribute('data-theme', 'mono');
                            }
                        })();
                    </script>
                    </head>
                    <body>
                        <div style="height: 100vh; width: 100%; max-width: 500px; margin: 0 auto; display: flex; align-items: center; justify-content: center; box-sizing: border-box;">
                            <div style="border: 1px solid var(--border-color); background-color: var(--chat-bg-color); border-radius: 5px; padding: 20px; width: 100%; box-sizing: border-box; text-align: center;">
                                <div style="color: var(--success-color); font-size: 16px; margin-bottom: 10px; font-family: 'unifont', sans-serif;">Registration Successful</div>
                                <div style="font-size: 14px; margin-bottom: 20px; font-family: 'unifont', sans-serif;">Your account <strong>${record.username}</strong> has been created.</div>
                                <div style="font-size: 12px; color: var(--note-color); font-family: 'unifont', sans-serif;">Redirecting to login in 5 seconds...</div>
                                <br>
                                <div style="font-size: 14px;"><a href="/auth/login.html">Click here if not redirected</a></div>
                            </div>
                        </div>
                    <script src="/scripts/theme.js"></script>
                    </body>
                </html>
            `, {
                headers: { "Content-Type": "text/html" }
            });
        } catch(e) {
            console.error(e);
            return new Response("Error creating account", { status: 500 });
        }
    }

    // ==================================================
    // 0.4 API: 解绑邮箱 (POST /api/user/unbind-email)
    // ==================================================
    if (request.method === "POST" && url.pathname === "/api/user/unbind-email") {
        const cookieHeader = request.headers.get("Cookie");
        if (!cookieHeader) return new Response(null, { status: 401 });
        const cookies = parse(cookieHeader);
        if (!cookies.session) return new Response(null, { status: 401 });

        try {
            const { payload } = await jwtVerify(cookies.session, JWT_SECRET);
            const formData = await request.formData();
            const password = formData.get("password");

            if (!password) return new Response(JSON.stringify({ success: false, message: "password required" }), { status: 400 });

            // 验证密码
            const user = await env.DB.prepare("SELECT password FROM users WHERE uid = ?").bind(payload.uid).first();
            if (!user) return new Response(null, { status: 404 });

            const isValid = await bcrypt.compare(password, user.password);
            if (!isValid) {
                return new Response(JSON.stringify({ success: false, message: "incorrect password" }), { status: 400 });
            }

            // 更新数据库: 清空邮箱
            await env.DB.prepare("UPDATE users SET email = NULL, email_verified = 0 WHERE uid = ?").bind(payload.uid).run();

            return new Response(JSON.stringify({ success: true, message: "email removed" }), {
                headers: { "Content-Type": "application/json" }
            });

        } catch (e) {
            return new Response(JSON.stringify({ success: false, message: "session invalid or server error" }), { status: 401 });
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
    // 1.1a API: 注册预检查 (POST /api/signup/check-username)
    // ==================================================
    if (request.method === "POST" && url.pathname === "/api/signup/check-username") {
                    try {
                    const formData = await request.formData();
                    const username = formData.get("username");
                    const password = formData.get("password"); // 新增：获取密码进行验证
        
                    // 基础格式验证
                    if (!/^\w{4,16}$/.test(username)) {
                        return new Response(JSON.stringify({ success: false, message: "username must be 4-16 valid chars" }), { status: 400 });
                    }
        
                    if (!password || password.length < 6) {
                        return new Response(JSON.stringify({ success: false, message: "password must be at least 6 chars" }), { status: 400 });
                    }
        
                    // 检查用户名是否存在            
                    const existing = await env.DB.prepare("SELECT uid FROM users WHERE username = ?").bind(username).first();
            if (existing) {
                return new Response(JSON.stringify({ success: false, message: "username already taken" }), { status: 400 });
            }

            return new Response(JSON.stringify({ success: true, message: "valid" }), { headers: { "Content-Type": "application/json" } });
        } catch(e) {
            return new Response("Error", { status: 500 });
        }
    }

    // ==================================================
    // 1. 注册逻辑 (POST /api/signup)
    // ==================================================
    if (request.method === "POST" && url.pathname === "/api/signup") {
        try {
            const formData = await request.formData();
            const username = formData.get("username");
            const password = formData.get("password");
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
            if (!password || password.length < 6) {
                return new Response(JSON.stringify({ success: false, message: "password must be at least 6 characters" }), { 
                    status: 400,
                    headers: { "Content-Type": "application/json" }
                });
            }

            if (!/^\w{4,16}$/.test(username)) {
                return new Response(JSON.stringify({ success: false, message: "username contains invalid characters" }), { 
                    status: 400,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // 检查用户名是否已存在
            const existingUser = await env.DB.prepare("SELECT uid FROM users WHERE username = ?").bind(username).first();
            if (existingUser) {
                 return new Response(JSON.stringify({ success: false, message: "username already taken" }), { 
                    status: 400,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // 1.3 混合验证逻辑
            const inviteCode = formData.get("invite-code");
            const email = formData.get("email");

            if (!inviteCode && !email) {
                return new Response(JSON.stringify({ success: false, message: "verification method required" }), { status: 400 });
            }

            // 优先处理邀请码 (直接注册)
            if (inviteCode && inviteCode.trim() !== "") {
                const invite = await env.DB.prepare("SELECT * FROM invites WHERE code = ?").bind(inviteCode).first();
                if (!invite) {
                    return new Response(JSON.stringify({ success: false, message: "invalid invite code" }), { status: 400 });
                }
                if (invite.is_used === 1) {
                    return new Response(JSON.stringify({ success: false, message: "invite code already used" }), { status: 400 });
                }

                // 如果同时填了邮箱，检查邮箱占用情况
                if (email && email.trim() !== "") {
                    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                        return new Response(JSON.stringify({ success: false, message: "invalid email format" }), { status: 400 });
                    }
                    const existingEmail = await env.DB.prepare("SELECT uid FROM users WHERE email = ? AND email_verified = 1").bind(email).first();
                    if (existingEmail) {
                        return new Response(JSON.stringify({ success: false, message: "email already registered" }), { status: 400 });
                    }
                }

                // 创建用户
                const newUid = await generateNextUid(env);
                const hashedPassword = await bcrypt.hash(password, 10);
                const userEmail = (email && email.trim() !== "") ? email : null;
                
                await env.DB.batch([
                    env.DB.prepare("INSERT INTO users (uid, username, password, email, email_verified, signup_date, original_email) VALUES (?, ?, ?, ?, ?, ?, ?)")
                        .bind(newUid, username, hashedPassword, userEmail, 0, Date.now(), userEmail), // email_verified=0
                    env.DB.prepare("UPDATE invites SET is_used = 1, used_by_uid = ? WHERE code = ?").bind(newUid, inviteCode)
                ]);

                // 如果有邮箱，发送验证邮件 (异步)
                if (userEmail) {
                    const token = crypto.randomUUID();
                    const now = Date.now();
                    const expiresAt = now + 24 * 60 * 60 * 1000; // 24 hrs
                    
                    // 存入 email_verifications
                    await env.DB.prepare("INSERT OR REPLACE INTO email_verifications (token, uid, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?)")
                        .bind(token, newUid, userEmail, now, expiresAt)
                        .run();

                    const verifyLink = `${url.origin}/auth/verify-email?token=${token}`;
                    const htmlContent = `<div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2>Welcome to coffeeroom!</h2>
                            <p>Hi ${username},</p>
                            <p>You have successfully registered using an invite code.</p>
                            <p>Please verify your email address to secure your account.</p>
                            <p><a href="${verifyLink}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Verify Email</a></p>
                            <p>Or copy this link: ${verifyLink}</p>
                            <p>This link will expire in 24 hours.</p>
                            <p>If you didn't sign up for coffeeroom, please ignore this email.</p>
                            <p>Support: <a href="mailto:support@caffeine.ink">support@caffeine.ink</a></p>
                        </div>
                    `;
                    ctx.waitUntil(sendEmail(env, userEmail, "Verify your email - coffeeroom", htmlContent));
                }

                return new Response(JSON.stringify({ success: true, message: "signup successful", redirect: "/auth/login.html" }), {
                    status: 200,
                    headers: { "Content-Type": "application/json" }
                });

            } else {
                // 仅邮箱验证 (Pending 流程)
                if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
                    return new Response(JSON.stringify({ success: false, message: "invalid email format" }), { status: 400 });
                }

                const existingEmail = await env.DB.prepare("SELECT uid FROM users WHERE email = ? AND email_verified = 1").bind(email).first();
                if (existingEmail) {
                    return new Response(JSON.stringify({ success: false, message: "email already registered" }), { status: 400 });
                }

                const token = crypto.randomUUID();
                const hashedPassword = await bcrypt.hash(password, 10);
                const now = Date.now();
                const expiresAt = now + 24 * 60 * 60 * 1000; // 24 hrs

                await env.DB.prepare("INSERT OR REPLACE INTO pending_registrations (token, username, password_hash, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)")
                    .bind(token, username, hashedPassword, email, now, expiresAt)
                    .run();

                const verifyLink = `${url.origin}/auth/verify-registration?token=${token}`;
                const htmlContent = `
                    <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2>Welcome to coffeeroom!</h2>
                        <p>Hi ${username},</p>
                        <p>Please click the link below to verify your email and complete your registration.</p>
                        <p><a href="${verifyLink}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Verify and Sign Up</a></p>
                        <p>Or copy this link: ${verifyLink}</p>
                        <p>This link will expire in 24 hours.</p>
                        <p>If you didn't sign up for coffeeroom, please ignore this email.</p>
                        <p>Support: <a href="mailto:support@caffeine.ink">support@caffeine.ink</a></p>
                    </div>
                `;

                ctx.waitUntil(sendEmail(env, email, "Verify your registration - coffeeroom", htmlContent));
                
                return new Response(JSON.stringify({ success: true, message: "verification email sent. please check your inbox and spam folder." }), {
                    headers: { "Content-Type": "application/json" }
                });
            }

        } catch (err) {
            return new Response(JSON.stringify({ success: false, message: "sign up error: " + err.message }), { 
                status: 500,
                headers: { "Content-Type": "application/json" }
            });
        }
    }

    // ==================================================
    // 1.1 API: 忘记密码 (POST /api/auth/forgot-password)
    // ==================================================
    if (request.method === "POST" && url.pathname === "/api/auth/forgot-password") {
        try {
            const formData = await request.formData();
            const email = formData.get("email");

            if (!email) {
                return new Response(JSON.stringify({ success: false, message: "email required" }), { status: 400 });
            }

            // 查找用户 (必须是已验证邮箱)
            const user = await env.DB.prepare("SELECT uid, username FROM users WHERE email = ? AND email_verified = 1").bind(email).first();

            if (user) {
                // 生成 Token
                const token = crypto.randomUUID();
                const now = Date.now();
                const expiresAt = now + 15 * 60 * 1000; // 15分钟有效

                // 存入 password_resets
                await env.DB.prepare("INSERT OR REPLACE INTO password_resets (token, uid, email, created_at, expires_at) VALUES (?, ?, ?, ?, ?)")
                    .bind(token, user.uid, email, now, expiresAt)
                    .run();

                // 发送邮件
                const resetLink = `${url.origin}/auth/reset-password.html?token=${token}`;
                const htmlContent = `
                    <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2>Reset your password</h2>
                        <p>Hi ${user.username},</p>
                        <p>We received a request to reset your password. If you didn't make this request, just ignore this email.</p>
                        <p><a href="${resetLink}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
                        <p>Or copy this link: ${resetLink}</p>
                        <p>This link will expire in 15 minutes.</p>
                        <p>If you didn't request a password reset, please ignore this email.</p>
                        <p>Support: <a href="mailto:support@caffeine.ink">support@caffeine.ink</a></p>
                    </div>
                `;

                ctx.waitUntil(sendEmail(env, email, "Reset your password - coffeeroom", htmlContent));
            }

            // 无论是否存在，都返回通用消息
            return new Response(JSON.stringify({ success: true, message: "if that email exists, we've sent a reset link." }), {
                headers: { "Content-Type": "application/json" }
            });

        } catch (e) {
            console.error(e);
            return new Response(JSON.stringify({ success: false, message: "server error" }), { status: 500 });
        }
    }

    // ==================================================
    // 1.2 页面: 重置密码页面 (GET /auth/reset-password.html)
    // ==================================================
    if (request.method === "GET" && url.pathname === "/auth/reset-password.html") {
        const token = url.searchParams.get("token");
        if (!token) return new Response("Missing token", { status: 400 });

        // 验证 Token
        const record = await env.DB.prepare("SELECT * FROM password_resets WHERE token = ?").bind(token).first();
        if (!record || record.expires_at < Date.now()) {
             return new Response(`
                <!DOCTYPE html>
                <html>
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>error - coffeeroom</title>
                        <link rel="stylesheet" href="/css/auth.css">
                        <script>
                            (function() {
                                const savedMode = localStorage.getItem('theme-mode') || 'auto';
                                let isDark = false;
                                let isMono = false;
                                if (savedMode === 'auto') {
                                    isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                                } else if (savedMode === 'mono') {
                                    isMono = true;
                                } else {
                                    isDark = (savedMode === 'dark');
                                }
                                if (isDark) {
                                    document.documentElement.setAttribute('data-theme', 'dark');
                                } else if (isMono) {
                                    document.documentElement.setAttribute('data-theme', 'mono');
                                }
                            })();
                        </script>
                    </head>
                    <body>
                        <div class="box">
                            <div class="content">
                                <div class="title-auth">Link Expired</div>
                                <div class="container">
                                    <div class="authbox">
                                        <span class="text">This reset link is invalid or has expired.</span><br>
                                        <span class="text"><a href="/auth/forgot.html">Request a new one</a>.</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </body>
                </html>
             `, { headers: { "Content-Type": "text/html" } });
        }

        // Get User 2FA Status
        const user = await env.DB.prepare("SELECT two_factor_enabled FROM users WHERE uid = ?").bind(record.uid).first();
        const is2FA = user && user.two_factor_enabled === 1;

        // 返回重置表单
        return new Response(`
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>reset password - coffeeroom</title>
                <link rel="stylesheet" href="/css/auth.css">
                <script src="/scripts/theme.js"></script>
                <script>const is2FAEnabled = ${is2FA};</script>
            </head>
            <body>
                <div class="box">
                    <div class="content">
                    <div class="header"><span class="title">caffeineId</span></div>
                    <br>
                    <div class="title-auth">Reset Password</div>
                    <div class="container">
                        <div class="authbox">
                            <span class="text">Enter your new password below.</span>
                        </div>
                        <div class="authbox">
                            <div id="auth-message" class="auth-message"></div>
                            <br>
                            <form id="reset-password-form">
                                <input type="hidden" name="token" value="${token}">
                                <div class="input-group"><input type="password" name="password" placeholder="new password" required /></div>
                                <div class="input-group"><input type="password" name="confirm-password" placeholder="confirm new password" required /></div>
                                
                                <div class="input-group" id="2fa-group" style="display: none;">
                                    <input type="text" name="code" placeholder="2FA / recovery code" autocomplete="off" />
                                </div>

                                <button type="submit">reset password</button>
                            </form>
                            <br>
                        </div>
                    </div>
                    </div>
                </div>
                <script>
                    if (is2FAEnabled) {
                        const group = document.getElementById('2fa-group');
                        group.style.display = 'block';
                        group.querySelector('input').required = true;
                    }

                    const form = document.getElementById('reset-password-form');
                    const msgBox = document.getElementById('auth-message');

                    form.querySelectorAll('input').forEach(input => {
                        input.addEventListener('invalid', function(e) {
                            e.preventDefault();
                            const oldTip = this.parentNode.querySelector('.error-tip');
                            if (oldTip) oldTip.remove();

                            const tip = document.createElement('div');
                            tip.className = 'error-tip';
                            tip.innerText = this.validationMessage;
                            this.parentNode.appendChild(tip);
                            setTimeout(() => { tip.remove(); }, 2000);
                        });
                    });

                    form.addEventListener('submit', async function(e) {
                        e.preventDefault();
                        msgBox.style.display = 'none';
                        msgBox.className = 'auth-message';

                        const formData = new FormData(form);
                        try {
                            const res = await fetch('/api/auth/reset-password', {
                                method: 'POST',
                                body: formData
                            });
                            
                            const text = await res.text();
                            
                            if (res.ok) {
                                // If success, backend returns a success HTML page
                                document.open();
                                document.write(text);
                                document.close();
                            } else {
                                msgBox.innerText = text || "Error resetting password";
                                msgBox.className = "auth-message error";
                                msgBox.style.display = 'block';
                            }
                        } catch (err) {
                            msgBox.innerText = "Network error";
                            msgBox.className = "auth-message error";
                            msgBox.style.display = 'block';
                        }
                    });
                </script>
            </body>
            </html>
        `, { headers: { "Content-Type": "text/html" } });
    }

    // ==================================================
    // 1.3 API: 执行重置密码 (POST /api/auth/reset-password)
    // ==================================================
    if (request.method === "POST" && url.pathname === "/api/auth/reset-password") {
        try {
            const formData = await request.formData();
            const token = formData.get("token");
            const password = formData.get("password");
            const confirmPassword = formData.get("confirm-password");
            const code = formData.get("code");

            if (password !== confirmPassword) {
                return new Response("Passwords do not match", { status: 400 });
            }

            const record = await env.DB.prepare("SELECT * FROM password_resets WHERE token = ?").bind(token).first();
            if (!record || record.expires_at < Date.now()) {
                return new Response("Invalid or expired token", { status: 400 });
            }

            // 检查 2FA
            const user = await env.DB.prepare("SELECT * FROM users WHERE uid = ?").bind(record.uid).first();
            if (user && user.two_factor_enabled) {
                if (!code) {
                    return new Response("2FA code required", { status: 400 });
                }

                let isValid = false;
                let decryptedSecret = null;

                if (user.totp_secret && env.ENCRYPTION_KEY) {
                    try {
                        decryptedSecret = await decrypt(user.totp_secret, env.ENCRYPTION_KEY);
                    } catch(e) {}
                }

                // 1. Try TOTP
                if (decryptedSecret) {
                    try {
                        const verifyResult = await verify({ 
                            token: code, 
                            secret: decryptedSecret,
                            window: 1 
                        });
                        if (typeof verifyResult === 'boolean') isValid = verifyResult;
                        else if (typeof verifyResult === 'object' && verifyResult !== null) isValid = verifyResult.valid === true;
                    } catch (e) {}
                }

                // 2. Try Recovery Code
                if (!isValid && user.recovery_codes && decryptedSecret) {
                    try {
                        const hashedCodes = JSON.parse(user.recovery_codes);
                        
                        const salt = user.uid + decryptedSecret;
                        const inputHash = await sha256(code + salt);

                        const index = hashedCodes.indexOf(inputHash);
                        if (index !== -1) {
                            isValid = true;
                            // 移除已使用的码
                            hashedCodes.splice(index, 1);
                            await env.DB.prepare("UPDATE users SET recovery_codes = ? WHERE uid = ?")
                                .bind(JSON.stringify(hashedCodes), user.uid)
                                .run();
                        }
                    } catch (e) { console.error("Error parsing recovery codes", e); }
                }

                if (!isValid) {
                    return new Response("Invalid 2FA code", { status: 400 });
                }
            }

            // 更新密码
            const hashedPassword = await bcrypt.hash(password, 10);
            await env.DB.prepare("UPDATE users SET password = ? WHERE uid = ?").bind(hashedPassword, record.uid).run();
            
            // 删除 Token
            await env.DB.prepare("DELETE FROM password_resets WHERE token = ?").bind(token).run();

            // 删除所有 Session (强制下线)
            await env.DB.prepare("DELETE FROM sessions WHERE uid = ?").bind(record.uid).run();

            return new Response(`
                <!DOCTYPE html>
                <html>
                    <head>
                        <meta charset="UTF-8">
                        <meta http-equiv="refresh" content="5;url=/auth/login.html" />
                        <title>success</title>
                        <link rel="stylesheet" href="/css/auth.css">
                        <script>
                            (function() {
                                const savedMode = localStorage.getItem('theme-mode') || 'auto';
                                let isDark = false;
                                let isMono = false;
                                if (savedMode === 'auto') {
                                    isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                                } else if (savedMode === 'mono') {
                                    isMono = true;
                                } else {
                                    isDark = (savedMode === 'dark');
                                }
                                if (isDark) {
                                    document.documentElement.setAttribute('data-theme', 'dark');
                                } else if (isMono) {
                                    document.documentElement.setAttribute('data-theme', 'mono');
                                }
                            })();
                        </script>
                        <script src="/scripts/theme.js"></script>
                    </head>
                    <body>
                        <div class="box">
                            <div class="content">
                                <div class="title-auth">Success</div>
                                <div class="container">
                                    <div class="authbox">
                                        <span class="text">Password reset successfully! Redirecting to login...</span><br>
                                        <span class="text">If you are not redirected, please click <a href="/auth/login.html">here</a>.</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </body>
                </html>
            `, { headers: { "Content-Type": "text/html" } });

        } catch (e) {
            console.error(e);
            return new Response("Server Error", { status: 500 });
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

            // 2.3.1 检查 2FA
            if (user.two_factor_enabled) {
                // 生成临时 Token (5分钟有效)
                const tempToken = await new SignJWT({ 
                    uid: user.uid, 
                    role: user.role,
                    scope: '2fa_pending'
                })
                    .setProtectedHeader({ alg: 'HS256' })
                    .setIssuedAt()
                    .setExpirationTime('5m')
                    .sign(JWT_SECRET);

                return new Response(JSON.stringify({ 
                    success: true, 
                    message: "2fa required",
                    "2fa_required": true,
                    temp_token: tempToken
                }), {
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
    // 2.2 登录验证第二步 (POST /api/login/2fa)
    // ==================================================
    if (request.method === "POST" && url.pathname === "/api/login/2fa") {
        try {
            const formData = await request.formData();
            const tempToken = formData.get("temp_token");
            const code = formData.get("code");

            if (!tempToken || !code) {
                return new Response(JSON.stringify({ success: false, message: "missing parameters" }), { 
                    status: 400,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // 1. 验证 temp_token
            let payload;
            try {
                const { payload: p } = await jwtVerify(tempToken, JWT_SECRET);
                if (p.scope !== '2fa_pending') throw new Error('invalid scope');
                payload = p;
            } catch (e) {
                return new Response(JSON.stringify({ success: false, message: "session expired, please login again" }), { 
                    status: 401,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // 2. 获取用户 Secret 和 Recovery Codes
            const user = await env.DB.prepare("SELECT * FROM users WHERE uid = ?").bind(payload.uid).first();
            if (!user) return new Response(JSON.stringify({ success: false, message: "user not found" }), { 
                status: 404,
                headers: { "Content-Type": "application/json" }
            });

            // 3. 验证 TOTP 或 Recovery Code
            let isValid = false;
            let usedRecoveryCode = false;
            let decryptedSecret = null;
            const type = formData.get("type"); // 'totp' or 'recovery'
            
            const shouldCheckTotp = !type || type === 'totp';
            const shouldCheckRecovery = !type || type === 'recovery';

            if (user.totp_secret && env.ENCRYPTION_KEY) {
                try {
                    decryptedSecret = await decrypt(user.totp_secret, env.ENCRYPTION_KEY);
                } catch(e) {}
            }

            // 3.1 尝试 TOTP
            if (shouldCheckTotp && decryptedSecret) {
                try {
                    // Only try TOTP verify if it looks somewhat like a token, or let verify fail gracefully
                    // verify throws if token length is not digits (default 6)
                    const verifyResult = await verify({ 
                        token: code, 
                        secret: decryptedSecret,
                        window: 1 
                    });
                    
                    if (typeof verifyResult === 'boolean') isValid = verifyResult;
                    else if (typeof verifyResult === 'object' && verifyResult !== null) isValid = verifyResult.valid === true;
                } catch (e) {
                    // Ignore TOTP verification errors (e.g. if code is a recovery code)
                    // console.log("TOTP check skipped/failed:", e.message);
                }
            }

            // 3.2 尝试 Recovery Code
            if (!isValid && shouldCheckRecovery && user.recovery_codes && decryptedSecret) {
                try {
                    const hashedCodes = JSON.parse(user.recovery_codes);
                    
                    const salt = user.uid + decryptedSecret;
                    const inputHash = await sha256(code + salt);
                    
                    const index = hashedCodes.indexOf(inputHash);
                    if (index !== -1) {
                        isValid = true;
                        usedRecoveryCode = true;
                        // 移除已使用的码
                        hashedCodes.splice(index, 1);
                        await env.DB.prepare("UPDATE users SET recovery_codes = ? WHERE uid = ?")
                            .bind(JSON.stringify(hashedCodes), user.uid)
                            .run();
                    }
                } catch (e) { console.error("Error parsing recovery codes", e); }
            }

            if (!isValid) {
                return new Response(JSON.stringify({ success: false, message: "invalid verification code" }), { 
                    status: 400,
                    headers: { "Content-Type": "application/json" }
                });
            }

            // 4. 创建正式 Session
            const sessionId = crypto.randomUUID();
            const ip = request.headers.get("CF-Connecting-IP") || "unknown";
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

            const isSecure = url.protocol === 'https:';
            const cookieHeader = serialize('session', token, {
                httpOnly: true,
                secure: isSecure, 
                domain: env.COOKIE_DOMAIN,
                sameSite: 'lax',
                maxAge: 60 * 60 * 24 * 7, 
                path: '/'
            });

            return new Response(JSON.stringify({ 
                success: true, 
                message: "login successful" + (usedRecoveryCode ? " (recovery code used)" : "")
            }), {
                status: 200,
                headers: {
                    'Set-Cookie': cookieHeader,
                    "Content-Type": "application/json"
                }
            });

        } catch (e) {
            return new Response(JSON.stringify({ success: false, message: "server error: " + e.message }), { 
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
    //  2FA 管理 (POST /api/user/2fa/...)
    // ==================================================
    if (url.pathname.startsWith("/api/user/2fa/")) {
        const cookieHeader = request.headers.get("Cookie");
        if (!cookieHeader) return new Response(null, { status: 401 });
        const cookies = parse(cookieHeader);
        if (!cookies.session) return new Response(null, { status: 401 });

        let payload;
        try {
            const { payload: p } = await jwtVerify(cookies.session, JWT_SECRET);
            payload = p;
        } catch (e) {
            return new Response(null, { status: 401 });
        }

        // 1. Setup: 生成密钥和二维码
        if (request.method === "POST" && url.pathname === "/api/user/2fa/setup") {
            const secret = generateSecret();
            
            // 加密存储 Secret
            if (!env.ENCRYPTION_KEY) {
                return new Response(JSON.stringify({ success: false, message: "server config error: encryption key missing" }), { status: 500 });
            }
            const encryptedSecret = await encrypt(secret, env.ENCRYPTION_KEY);

            const otpauth = generateURI({
                secret: secret,
                label: payload.username,
                issuer: "coffeeroom",
                algorithm: "SHA1",
                digits: 6,
                period: 30
            });

            // Cloudflare Workers don't support Canvas, so we generate SVG
            const svgString = await QRCode.toString(otpauth, { type: 'svg' });
            const qrCodeDataUrl = `data:image/svg+xml;base64,${btoa(svgString)}`;

            // 暂存 secret，但不开启 2FA
            await env.DB.prepare("UPDATE users SET totp_secret = ? WHERE uid = ?")
                .bind(encryptedSecret, payload.uid)
                .run();

            return new Response(JSON.stringify({ 
                success: true, 
                secret: secret, 
                qrCode: qrCodeDataUrl 
            }), { headers: { "Content-Type": "application/json" } });
        }

        // 2. Enable: 验证并正式开启
        if (request.method === "POST" && url.pathname === "/api/user/2fa/enable") {
            const formData = await request.formData();
            const code = formData.get("code");

            const user = await env.DB.prepare("SELECT totp_secret FROM users WHERE uid = ?").bind(payload.uid).first();
            if (!user || !user.totp_secret) {
                return new Response(JSON.stringify({ success: false, message: "2FA not set up" }), { status: 400 });
            }

            // 解密 Secret
            if (!env.ENCRYPTION_KEY) return new Response("server config error", { status: 500 });
            let decryptedSecret;
            try {
                decryptedSecret = await decrypt(user.totp_secret, env.ENCRYPTION_KEY);
            } catch (e) {
                return new Response(JSON.stringify({ success: false, message: "encryption error, please reset 2FA" }), { status: 500 });
            }
            
            try {
                // verify: { token, secret }
                const verifyResult = await verify({ 
                    token: code, 
                    secret: decryptedSecret,
                    window: 1 // Default to 1 step drift
                });
                
                let isValid = false;
                if (typeof verifyResult === 'boolean') {
                    isValid = verifyResult;
                } else if (typeof verifyResult === 'object' && verifyResult !== null) {
                    isValid = verifyResult.valid === true; 
                }

                if (!isValid) {
                    return new Response(JSON.stringify({ success: false, message: "invalid verification code" }), { status: 400 });
                }
            } catch (err) {
                 console.error("[2FA Enable] Verify Error:", err);
                 return new Response(JSON.stringify({ success: false, message: "verification error" }), { status: 500 });
            }

            // 生成恢复码 (10个 xxxxx-xxxxx 格式) 并哈希化存储
            const recoveryCodes = [];
            const hashedCodes = [];
            // 使用解密后的 Secret 作为 Salt，保证 Salt 的稳定性
            const salt = payload.uid + decryptedSecret;

            for (let i = 0; i < 10; i++) {
                const part1 = crypto.randomUUID().split('-')[0].substring(0, 5);
                const part2 = crypto.randomUUID().split('-')[0].substring(0, 5);
                const code = `${part1}-${part2}`;
                recoveryCodes.push(code);
                
                // Hash the code with salt
                hashedCodes.push(await sha256(code + salt));
            }

            // 获取用户信息以提供下载所需的数据
            const userInfo = await env.DB.prepare("SELECT email FROM users WHERE uid = ?").bind(payload.uid).first();

            await env.DB.prepare("UPDATE users SET two_factor_enabled = 1, recovery_codes = ? WHERE uid = ?")
                .bind(JSON.stringify(hashedCodes), payload.uid)
                .run();

            return new Response(JSON.stringify({ 
                success: true, 
                message: "2FA enabled", 
                username: payload.username,
                email: userInfo ? userInfo.email : null,
                recoveryCodes: recoveryCodes,
                date: new Date().toISOString().split('T')[0]
            }), { headers: { "Content-Type": "application/json" } });
        }

        // 3. Disable: 关闭 2FA
        if (request.method === "POST" && url.pathname === "/api/user/2fa/disable") {
            const formData = await request.formData();
            const password = formData.get("password");

            const user = await env.DB.prepare("SELECT password FROM users WHERE uid = ?").bind(payload.uid).first();
            const isPasswordValid = await bcrypt.compare(password, user.password);
            
            if (!isPasswordValid) {
                return new Response(JSON.stringify({ success: false, message: "incorrect password" }), { status: 400 });
            }

            await env.DB.prepare("UPDATE users SET two_factor_enabled = 0, totp_secret = NULL, recovery_codes = NULL WHERE uid = ?")
                .bind(payload.uid)
                .run();

            return new Response(JSON.stringify({ success: true, message: "2FA disabled" }), {
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
    // 5. API: 导出记录 (GET /api/room/:room/export)
    // ==================================================
    const exportMatch = url.pathname.match(/^\/api\/room\/([^/]+)\/export$/);
    if (request.method === "GET" && exportMatch) {
        const roomName = exportMatch[1];
        if (!ALLOWED_CHATROOMS.includes(roomName)) {
            return new Response("room not found", { status: 404 });
        }
        
        // 鉴权
        const cookieHeader = request.headers.get("Cookie");
        if (!cookieHeader) return new Response("Unauthorized", { status: 401 });
        const cookies = parse(cookieHeader);
        if (!cookies.session) return new Response("Unauthorized", { status: 401 });
        try {
            await jwtVerify(cookies.session, JWT_SECRET);
        } catch (e) {
            return new Response("Unauthorized", { status: 401 });
        }

        const id = env.CHAT_ROOM.idFromName(roomName);
        const stub = env.CHAT_ROOM.get(id);
        
        // 转发请求到 DO (内部路径 /export)
        const doUrl = new URL("http://internal/export");
        doUrl.search = url.search; // 保留 limit 参数
        
        return stub.fetch(new Request(doUrl, request));
    }

    // ==================================================
    // 3. 聊天室 WebSocket 路由
    // ==================================================
    const pathnameParts = url.pathname.split("/").filter(part => part.length > 0);

    if (pathnameParts[0] === "websocket") {
        const roomName = pathnameParts[1] || "general";
        if (!ALLOWED_CHATROOMS.includes(roomName)) {
            return new Response("room not found", { status: 404 });
        }
        const id = env.CHAT_ROOM.idFromName(roomName);
        const stub = env.CHAT_ROOM.get(id);
        return stub.fetch(request);
    }

    // 静态资源处理 (ASSETS)
    if (env.ASSETS) {
        try {
            const response = await env.ASSETS.fetch(request);
            if (response.status === 404) {
                 // not found -> 404 page
                 return new Response(HTML_404, {
                     status: 404,
                     headers: { "Content-Type": "text/html; charset=utf-8" }
                 });
            }
            return response;
        } catch (e) {
            // ignore ASSETS error
        }
    }

    // 404 page content
    return new Response(HTML_404, {
        status: 404,
        headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  }
};

const HTML_404 = `<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - caffeine-Ink</title>
    <meta name="theme-color" content="#d8e3ed" media="(prefers-color-scheme: light)">
    <meta name="theme-color" content="#242931" media="(prefers-color-scheme: dark)">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <link rel="manifest" href="/site.webmanifest">
    <script defer src="/scripts/favicon.js"></script>
    <link rel="stylesheet" href="/css/style.css">
    <link rel="stylesheet" href="/css/main.css">
    <script>
      (function() {
          const savedMode = localStorage.getItem('theme-mode') || 'auto';
          let isDark = false;
          let isMono = false;
          if (savedMode === 'auto') {
              isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
          } else if (savedMode === 'mono') {
              isMono = true;
          } else {
              isDark = (savedMode === 'dark');
          }
          if (isDark) {
              document.documentElement.setAttribute('data-theme', 'dark');
          } else if (isMono) {
              document.documentElement.setAttribute('data-theme', 'mono');
          }
      })();
    </script>
	<script defer src="https://cloud.umami.is/script.js" data-website-id="cf3f6b51-a212-4d89-bad2-8d83e259075d"></script>
  </head>
  <body>
    <div class="box">
        <div class="content">
          <div class="header">  
          <span class="title">caffeine-Ink</span>
          <span class="date"></span>
          </div>
          <br>
          <p>Error 404: Not Found</p>
          <br>
        </div>
        <div class="back"><a href="/">&lt; back to home</a></div>
        <footer>
          <br>
          <div class="copyright"></div>
        </footer>
    </div>
    <script src="/scripts/theme.js"></script>
  </body>
</html>`;

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

// 邮件发送 helper
async function sendEmail(env, to, subject, htmlContent) {
    if (!env.RESEND_API_KEY) {
        console.error('Missing RESEND_API_KEY');
        return false;
    }
    
    try {
        const res = await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${env.RESEND_API_KEY}`
            },
            body: JSON.stringify({
                from: 'coffeeroom <noreply@caffeine.ink>',
                to: [to],
                subject: subject,
                html: htmlContent
            })
        });

        if (res.ok) {
            return true;
        } else {
            try {
                const data = await res.json();
                console.error('Resend API Error:', data);
            } catch(e) {}
            return false;
        }
    } catch (e) {
        console.error('Send Email Exception:', e);
        return false;
    }
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

        // API 导出历史记录 (用于 /save 命令)
        if (url.pathname === "/export") {
            const limitParam = url.searchParams.get("limit");
            return this.exportHistory(limitParam);
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
                    helpText += "/save (save chat history in this room)<br>";
                    
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

    // 辅助函数: 导出历史消息 (全量或指定数量)
    async exportHistory(limitParam) {
        let limit = Infinity;
        if (limitParam && limitParam !== "all") {
            limit = parseInt(limitParam, 10);
            if (isNaN(limit) || limit <= 0) {
                 return new Response("Invalid limit", { status: 400 });
            }
        }

        // DO storage.list 有单次返回限制
        // 请求 all 可能需分页拉取全部
        
        const allMessages = [];
        let cursor = null;
        let hasMore = true;

        while (hasMore) {
            const options = {
                prefix: "msg-",
                limit: 1000, 
                reverse: true // 从新到旧
            };
            
            // 如果有限制，且剩余需要的数量小于 1000，则只取需要的
            if (limit !== Infinity) {
                const remaining = limit - allMessages.length;
                if (remaining <= 0) break;
                if (remaining < 1000) options.limit = remaining;
            }

            if (cursor) {
                options.end = cursor;
            }

            const list = await this.state.storage.list(options);
            const batch = Array.from(list.values());
            
            if (batch.length === 0) {
                hasMore = false;
            } else {
                allMessages.push(...batch);
                // 更新 cursor 为这批里最旧的一条的 key
                // 因为是 reverse: true, 所以 list 是按 key 倒序排列的
                // 下一次 list(end=cursor) 会从这个 key 之前开始找
                cursor = Array.from(list.keys()).pop();
                
                // 到底了
                if (batch.length < options.limit) {
                    hasMore = false;
                }
            }
        }

        // 此时 allMessages 是按时间倒序的 (新 -> 旧)
        // 导出通常按时间正序 (旧 -> 新)
        allMessages.reverse();

        return new Response(JSON.stringify({ success: true, messages: allMessages }), {
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

// Helper: SHA-256 Hash
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper: AES-256-GCM Encryption
async function encrypt(text, keyString) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(text);
    
    // Derive a 32-byte key from the input string using SHA-256
    const keyBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(keyString));
    
    const key = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );

    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoded
    );

    // Return IV:CipherText (Hex encoded)
    const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
    const cipherHex = Array.from(new Uint8Array(ciphertext)).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${ivHex}:${cipherHex}`;
}

async function decrypt(text, keyString) {
    const [ivHex, cipherHex] = text.split(':');
    if (!ivHex || !cipherHex) throw new Error("Invalid cipher format");

    const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const ciphertext = new Uint8Array(cipherHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    const keyBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(keyString));
    const key = await crypto.subtle.importKey(
        "raw",
        keyBuffer,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv },
        key,
        ciphertext
    );

    return new TextDecoder().decode(decrypted);
}
