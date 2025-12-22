// 这是一个标准的 Worker 写法
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 如果前端请求 WebSocket 连接
    if (url.pathname === "/websocket") {
      // 获取 Durable Object 的 ID (例如所有人都进同一个 'lobby' 房间)
      const id = env.CHAT_ROOM.idFromName("lobby");
      const stub = env.CHAT_ROOM.get(id);
      return stub.fetch(request); // 把请求转交给下面的 ChatRoom 类处理
    }

    // 对于普通网页请求，Cloudflare 会自动优先通过 [assets] 配置返回 index.html
    // 如果没有找到静态文件，才会走到这里
    return new Response("Not found", { status: 404 });
  }
};

// 定义 Durable Object 类 (实际处理聊天逻辑的地方)
export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.sessions = []; // 存储所有在线用户的连接
  }

  async fetch(request) {
    // 1. 处理 WebSocket 握手
    const [client, server] = Object.values(new WebSocketPair());
    
    server.accept();
    this.sessions.push(server);

    // 2. 监听消息
    server.addEventListener("message", event => {
      // 广播给所有人
      this.sessions.forEach(session => {
        session.send(event.data);
      });
    });

    return new Response(null, { status: 101, webSocket: client });
  }
}