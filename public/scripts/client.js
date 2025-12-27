// 1. 获取元素
const chatWindow = document.getElementById('chat-window');
const chatForm = document.getElementById('chat-form');
const messageInput = document.getElementById('message-input');
const statusText = document.getElementById('status');

// 2. 连接 WebSocket
const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const host = window.location.host;
const wsUrl = `${protocol}//${host}/websocket`;

console.log("正在连接:", wsUrl);
let ws = new WebSocket(wsUrl);

// WebSocket 事件 

ws.onopen = () => {
    console.log("连接成功");
    statusText.innerText = "Connected";
    statusText.style.color = "var(--connection-green)";
};

ws.onmessage = (event) => {
    // 收到别人的消息
    console.log("收到:", event.data);
    addMessage("anonymous", event.data, "received");
};

ws.onclose = () => {
    statusText.innerText = "Connection Interrupted";
    statusText.style.color = "var(--connection-red)";
};

// 核心函数：发送逻辑 

chatForm.addEventListener('submit', (e) => {
    e.preventDefault(); // 阻止页面刷新
    
    const text = messageInput.value;
    if (!text) return; // 如果是空的就不发

    // 不等服务器回应，直接显示在发送者屏幕上
    addMessage("me", text, "sent");

    // 3. 发送给服务器 (如果连接正常)
    if (ws.readyState === WebSocket.OPEN) {
        ws.send(text);
        console.log("已发送:", text);
    } else {
        console.warn("未连接，无法发送");
        alert("Connection Interrupted");
    }

    // 清空输入框
    messageInput.value = '';
});

// 辅助函数：清洗异体字控制符
function cleanMessage(text) {
  return text.replace(/\uFE0F/g, '');
}

// 辅助函数：添加消息到屏幕
function addMessage(sender, text, type) {
    const div = document.createElement('div');
    div.className = 'message';
    
    text = cleanMessage(text);
    
    // 样式判断
    if (type === "sent") {
		div.style.background = "var(--message-bg-color)";
    } else {

    }

    // 安全的构建 DOM 节点（之前粘贴了一段<script></script>进去直接被解析了已畏惧）
    
    // 1. 创建名字部分
    const senderSpan = document.createElement('span');
    senderSpan.textContent = `${sender}:`; 

    // 2. 创建消息内容部分
    // document.createTextNode 会自动把 <script> 变成纯文字显示，不会执行
    const textNode = document.createTextNode(" " + text); 

    // 3. 拼装
    div.appendChild(senderSpan); // 名字
    div.appendChild(textNode);   // 内容

    // 4. 上墙
    chatWindow.appendChild(div);
    chatWindow.scrollTop = chatWindow.scrollHeight;
}