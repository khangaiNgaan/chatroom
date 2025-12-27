// 1. 获取元素
const chatWindow = document.getElementById('chat-window');
const chatForm = document.getElementById('chat-form');
const roomList = document.getElementById('room-list');
const messageInput = document.getElementById('message-input');
const statusText = document.getElementById('status');

const ROOMS = ["general", "irl", "news", "debug", "minecraft"];
const ROOM_PLACEHOLDERS = {
    "general": "input...",
    "irl": "life with gas meter...",
    "news": "what's happening...",
    "debug": "debug the world...",
    "minecraft": "baked potatoes...",
};

let currentSocket = null;
let currentRoom = "general";

function init() {
    renderRoomList();
    joinRoom(currentRoom);
}

function renderRoomList() {
    roomList.innerHTML = "";

    ROOMS.forEach(roomName => {
    const div = document.createElement("div");
    div.textContent = roomName;
    div.className = "room-item";
    div.dataset.room = roomName; // 保存房间名

    // 点击事件
    div.addEventListener("click", () => {
      if (currentRoom !== roomName) {
        joinRoom(roomName);
      }
    });

    roomList.appendChild(div);
  });

}

function joinRoom(roomName) {
  // 1. 如果已有连接，先断开
  if (currentSocket) {
    console.log(`断开 ${currentRoom} 的连接...`);
    currentSocket.close();
  }

  // 2. 更新 UI 状态
  currentRoom = roomName;
  updateActiveRoomUI(roomName);

  messageInput.placeholder = ROOM_PLACEHOLDERS[roomName] || "input...";
  
  // 3. 清空聊天界面
  chatWindow.innerHTML = ""; 
  statusText.innerText = "Connecting...";
  statusText.style.color = "var(--border-color)";

  // 4. 建立新连接
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/websocket/${roomName}`;
  
  currentSocket = new WebSocket(wsUrl);

  // 5. 绑定事件监听
  setupSocketListeners(currentSocket);
}

function updateActiveRoomUI(activeRoom) {
  const items = document.querySelectorAll(".room-item");
  items.forEach(item => {
    if (item.dataset.room === activeRoom) {
      item.classList.add("active");
    } else {
      item.classList.remove("active");
    }
  });
}


// WebSocket 事件监听绑定函数
function setupSocketListeners(socket) {
  socket.onopen = () => {
    console.log("连接成功");
    statusText.innerText = "Connected";
    statusText.style.color = "var(--connection-green)";
  };

  socket.onmessage = (event) => {
    console.log("收到:", event.data);
    addMessage("anonymous", event.data, "received");
  };

  socket.onclose = () => {
    statusText.innerText = "Disconnected";
    statusText.style.color = "var(--connection-red)";
  };

  socket.onerror = (error) => {
    console.error("WebSocket 错误:", error);
  };
}


// 核心函数：发送逻辑 
chatForm.addEventListener('submit', (e) => {
    e.preventDefault(); // 阻止页面刷新
    
    const text = messageInput.value;
    if (!text) return; // 如果是空的则不发送

    // 不等服务器回应，直接显示在发送者屏幕上，乐观 UI
    addMessage("me", text, "sent");

    // 发送给服务器 (如果连接正常)
    if (currentSocket.readyState === WebSocket.OPEN) {
        currentSocket.send(text);
        console.log("已发送:", text);
    } else {
        console.warn("未连接，无法发送");
        alert("Not connected to the server.");
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

init();