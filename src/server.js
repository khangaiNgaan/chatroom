// src/server.js

/* Worker 入口 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    const ALLOWED_CHATROOMS = ["general", "irl", "news", "debug", "minecraft"];
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

/* Durable Object 类 */

export class ChatRoom {
  constructor(state, env) {
    this.state = state; // 这里面包含了 storage API
    this.sessions = [];
    this.history = [];  // 用来在内存里缓存历史记录

    // 关键步骤: 初始化时，从硬盘恢复数据
    // blockConcurrencyWhile 保证在读取完数据库之前，不会处理任何请求
    this.state.blockConcurrencyWhile(async () => {
      // 尝试从硬盘获取名为 "history" 的数据
      let stored = await this.state.storage.get("history");
      // 如果硬盘里有，就赋值给 this.history；如果是空的，就给个空数组
      this.history = stored || [];
    });
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected Upgrade: websocket", { status: 426 });
    }
    const [client, server] = Object.values(new WebSocketPair());
    await this.handleSession(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  async handleSession(socket) {
    socket.accept();
    this.sessions.push(socket);

    // 把历史记录发给新连接的用户
    this.history.forEach(msg => {
      socket.send(msg); 
    });

    // 监听消息
    socket.addEventListener("message", async (msg) => {
      const data = msg.data;

      if (data === "/clear") {
        // 1. 清空内存
        this.history = [];
    
        // 2. 清空硬盘 (Storage)
        await this.state.storage.delete("history");


        // 4. 不把 "/clear" 本身存进去
        return; 
      }

      // 保存历史记录
      this.saveMessage(data);

      // 广播给其他人
      this.broadcast(data, socket);
    });

    // 监听断开
    const closeHandler = () => {
      this.sessions = this.sessions.filter(s => s !== socket);
    };
    socket.addEventListener("close", closeHandler);
    socket.addEventListener("error", closeHandler);
  }

  // 辅助函数: 处理存储逻辑
  async saveMessage(message) {
    // 1. 推入内存数组
    this.history.push(message);

    // 2. 限制长度 (比如只存最近 20 条)
    if (this.history.length > 20) {
      // 如果超过20条，删掉最旧的那条 (也就是数组的第一个)
      this.history.shift(); 
    }

    // 3. 写持久化存储
    // "history" 是 Key，this.history 数组是 Value
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