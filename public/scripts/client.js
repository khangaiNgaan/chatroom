// public/scripts/client.js

/* 获取元素 */

const chatWindow = document.getElementById('chat-window');
const chatForm = document.getElementById('chat-form');
const roomList = document.getElementById('room-list');
const messageInput = document.getElementById('message-input');
const statusText = document.getElementById('status');
const retryButton = document.getElementById('retryButton');
const reloadButton = document.getElementById('reloadButton');

/* 房间列表和占位符 */

const ROOMS = ["bulletin", "general", "irl", "news", "debug", "minecraft"];
const ROOM_PLACEHOLDERS = {
    "general": "input...",
    "irl": "life with gas meter...",
    "news": "what's happening...",
    "debug": "debug the world...",
    "minecraft": "baked potatoes...",
    "bulletin": "continuous iteration..."
};

let currentSocket = null;
let currentRoom = "general";
let currentUser = null; // 保存当前登录用户名

/* 函数 */

// 函数：初始化
async function init() {
    // 1. 强制登录检查
    try {
        const res = await fetch('/api/user');
        if (res.status === 401) {
            window.location.href = '/auth/login.html';
            return;
        }
        if (res.ok) {
            const user = await res.json();
            currentUser = user.username;
            console.log("Logged in as:", currentUser);
            
            // 更新页面上的用户名显示 (如果 index.html 里有对应元素)
            const userDisplay = document.getElementById('user-display');
            if (userDisplay) {
                userDisplay.innerHTML = `Hi, <a href="/user/profile.html">${currentUser}</a> (<a href="/api/logout">logout</a>) `;
            }
        }
    } catch (e) {
        console.error("Auth check failed:", e);
        // 网络错误是否要踢出？暂时保守点不踢，或者显示重试
    }

    renderRoomList();
    
    if (retryButton) {
        retryButton.style.display = 'none';
        retryButton.addEventListener('click', () => {
            console.log("手动重连中...");
            retryButton.style.display = 'none';
            joinRoom(currentRoom);
        });
    }
    if (reloadButton) {
        reloadButton.style.display = 'none';
        reloadButton.addEventListener('click', () => {
            console.log("页面重载中...");
            window.location.reload();
        });
    }

    joinRoom(currentRoom);
}

// 函数：渲染房间列表
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

// 函数：切换房间
function joinRoom(roomName) {

  // 1. 隐藏重连按钮
  if (retryButton) retryButton.style.display = 'none';
  if (reloadButton) reloadButton.style.display = 'none';
  
  // 2. 断开当前连接
  if (currentSocket) {
    console.log(`断开 ${currentRoom} 的连接...`);
    currentSocket.close();
  }

  // 3. 更新 UI 状态
  currentRoom = roomName;
  updateActiveRoomUI(roomName);

  messageInput.placeholder = ROOM_PLACEHOLDERS[roomName] || "input...";
  
  // 4. 清空聊天界面
  chatWindow.innerHTML = ""; 
  statusText.innerText = "Connecting...";
  statusText.style.color = "var(--border-color)";

  // 5. 建立新连接
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/websocket/${roomName}`;
  
  currentSocket = new WebSocket(wsUrl);

  // 6. 绑定事件监听
  setupSocketListeners(currentSocket);
}

// 函数：高亮活跃房间
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


// 函数：WebSocket 事件监听绑定
function setupSocketListeners(socket) {
  socket.onopen = () => {
    console.log("连接成功");
    statusText.innerText = "Connected";
    statusText.style.color = "var(--connection-green)";
  };

  socket.onmessage = (event) => {
    console.log("收到:", event.data);
    try {
        const msg = JSON.parse(event.data);
        addMessage(msg.sender, msg.text, "received", msg.timestamp);
    } catch (e) {
        // 向后兼容
        addMessage("anonymous", event.data, "received");
    }
  };

  socket.onclose = () => {
    statusText.innerText = "Disconnected";
    statusText.style.color = "var(--connection-red)";
    console.log("连接断开");
    
    // 显示重连按钮
    if (retryButton) {
      retryButton.style.display = 'inline';
    }
    if (reloadButton) {
      reloadButton.style.display = 'inline';
    }
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

    // 乐观 UI: 使用真实用户名
    addMessage(currentUser, text, "sent", Date.now());

    // 发送给服务器
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

// 辅助函数：格式化时间 YYYY-MM-DD HH:MM:SS
function formatDate(timestamp) {
    const date = new Date(timestamp);
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    const h = String(date.getHours()).padStart(2, '0');
    const min = String(date.getMinutes()).padStart(2, '0');
    const s = String(date.getSeconds()).padStart(2, '0');
    return `${y}-${m}-${d} ${h}:${min}:${s}`;
}

// 辅助函数：添加消息到屏幕
function addMessage(sender, text, type, timestamp = Date.now()) {
    const div = document.createElement('div');
    div.className = 'message';
    div.style.marginBottom = "10px"; // 增加一点消息间距
    
    text = cleanMessage(text);
    
    // 样式判断

    // --- 第一行：名字 + 时间 ---
    const headerDiv = document.createElement('div');
    headerDiv.style.marginBottom = "3px";
    headerDiv.style.lineHeight = "1.4";

    // 名字
    const senderSpan = document.createElement('span');
    senderSpan.textContent = sender; 
    senderSpan.style.marginRight = "10px";
    senderSpan.style.fontWeight = "bold";
    
    if (sender === currentUser) {
        senderSpan.style.color = "var(--my-nom-color)";

    } else if (sender === "system" || sender === "caffeine") {
        senderSpan.style.color = "var(--admin-nom-color)";
    } else {
        senderSpan.style.color = "var(--nom-color)";
    }

    // 时间
    const timeSpan = document.createElement('span');
    timeSpan.textContent = formatDate(timestamp);
    timeSpan.style.color = "var(--border-color)";
    timeSpan.style.fontSize = "0.85em";
    timeSpan.style.fontFamily = "'unifont', monospace";

    headerDiv.appendChild(senderSpan);
    headerDiv.appendChild(timeSpan);

    // --- 第二行：内容 ---
    const contentDiv = document.createElement('div');
    contentDiv.style.wordBreak = "break-word"; // 防止长单词撑破
    contentDiv.style.lineHeight = "1.4";
    contentDiv.style.fontWeight = "normal";
    
    // 使用 createTextNode 防止 XSS
    const textNode = document.createTextNode(text); 
    contentDiv.appendChild(textNode);

    // --- 拼装 ---
    div.appendChild(headerDiv);
    div.appendChild(contentDiv);

    // 上墙
    chatWindow.appendChild(div);
    chatWindow.scrollTop = chatWindow.scrollHeight;
}

/* 启动 */

init();