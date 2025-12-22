// --- 第一部分：Worker 入口 (接待员) ---
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. 拦截 WebSocket 请求
    if (url.pathname === "/websocket") {
      // 这里的 "CHAT_ROOM" 对应 wrangler.toml 里的绑定名称
      // 这里的 "GLOBAL_CHAT" 是房间名。因为写死了这个字符串，
      // 所以无论谁来，都会被分配到同一个唯一的房间 ID。
      const id = env.CHAT_ROOM.idFromName("GLOBAL_CHAT");
      
      // 获取这个房间的 "存根" (Stub)，准备发起调用
      const stub = env.CHAT_ROOM.get(id);
      
      // 把请求转交给 Durable Object 处理
      return stub.fetch(request);
    }

    // 2. 如果是普通 HTTP 请求 (且没有被静态资源拦截)
    return new Response("Not found", { status: 404 });
  }
};

// --- 第二部分：Durable Object 类 (会议室) ---
export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    // 用来存储所有当前的连接
    this.sessions = [];
  }

  // 当 Worker 调用 stub.fetch(request) 时，会运行这里的代码
  async fetch(request) {
    // 1. 检查是不是 WebSocket 升级请求
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected Upgrade: websocket", { status: 426 });
    }

    // 2. 创建一对 WebSocket (客户端 <-> 服务器)
    const [client, server] = Object.values(new WebSocketPair());

    // 3. 服务器端接受连接
    await this.handleSession(server);

    // 4. 把客户端那一头返回给用户
    return new Response(null, { status: 101, webSocket: client });
  }

  // 处理单个连接的逻辑
  async handleSession(socket) {
    socket.accept();
    this.sessions.push(socket);

    // 当收到消息时
    socket.addEventListener("message", async (msg) => {
      // 广播给房间里的其他人
      this.broadcast(msg.data, socket);
    });

    // 当连接关闭或出错时
    const closeHandler = () => {
      // 从列表中移除这个连接
      this.sessions = this.sessions.filter(s => s !== socket);
    };
    socket.addEventListener("close", closeHandler);
    socket.addEventListener("error", closeHandler);
  }

  // 广播功能
  broadcast(message, senderSocket) {
    // 遍历所有连接
    this.sessions.forEach(session => {
      // 1. 只有连接是打开状态才发送
      // 2. (可选) 不发给发送者自己，因为前端 client.js 已经在本地显示了自己的话
      if (session.readyState === WebSocket.READY_STATE_OPEN && session !== senderSocket) {
        try {
          session.send(message);
        } catch (err) {
          // 如果发送失败（比如连接断了），就忽略
          session.close();
        }
      }
    });
  }
}