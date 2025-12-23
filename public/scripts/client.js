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

// --- WebSocket 事件 ---

ws.onopen = () => {
    console.log("连接成功");
    statusText.innerText = "Connected";
    statusText.style.color = "green";
};

ws.onmessage = (event) => {
    // 收到别人的消息
    console.log("收到:", event.data);
    addMessage("anonymous", event.data, "received");
};

ws.onclose = () => {
    statusText.innerText = "Connection Interrupted";
    statusText.style.color = "red";
};

// --- 核心：发送逻辑 ---

chatForm.addEventListener('submit', (e) => {
    e.preventDefault(); // 1. 阻止页面刷新
    
    const text = messageInput.value;
    if (!text) return; // 如果是空的就不发

    // 2. 【关键】不等服务器回应，直接显示在自己的屏幕上
    // 这叫 "Optimistic UI" (乐观UI)
    addMessage("me", text, "sent");

    // 3. 发送给服务器 (如果连接正常)
    if (ws.readyState === WebSocket.OPEN) {
        ws.send(text);
        console.log("已发送:", text);
    } else {
        console.warn("未连接，无法发送");
        alert("Connection Interrupted");
    }

    // 4. 清空输入框
    messageInput.value = '';
});

// 清洗异体字控制符
function cleanMessage(text) {
  return text.replace(/\uFE0F/g, '');
}

// --- 辅助函数：添加消息到屏幕 ---
function addMessage(sender, text, type) {
    const div = document.createElement('div');
    div.className = 'message';
    
    text = cleanMessage(text);
    
    // --- 样式判断 ---
    if (type === "sent") {
		div.style.background = "#d8e3ed";
    } else {

    }

    // --- 安全的构建 DOM 节点 ---
    
    // 1. 创建名字部分 (这是我们自己生成的，相对安全，但也建议用 textContent)
    const senderSpan = document.createElement('span');
    senderSpan.textContent = `${sender}:`; 

    // 2. 创建消息内容部分 (这是用户输入的，必须用 TextNode)
    // document.createTextNode 会自动把 <script> 变成纯文字显示，不会执行
    const textNode = document.createTextNode(" " + text); 

    // 3. 把它们拼装起来
    div.appendChild(senderSpan); // 先放名字
    div.appendChild(textNode);   // 再放内容

    // 4. 上墙
    chatWindow.appendChild(div);
    chatWindow.scrollTop = chatWindow.scrollHeight;
}