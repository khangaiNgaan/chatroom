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
    "bulletin": "iteration..."
};

let currentSocket = null;
let currentRoom = "general";
let currentUser = null; // 保存当前登录用户名
let oldestMsgId = null; // 分页加载
let isLoadingHistory = false; // 防抖

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

    // 绑定滚动事件 (load more)
    chatWindow.addEventListener('scroll', () => {
        if (chatWindow.scrollTop === 0 && !isLoadingHistory && oldestMsgId) {
            loadMoreMessages();
        }
    });

    joinRoom(currentRoom);

    // 在线人数轮询
    fetchOnlineCount();
    setInterval(fetchOnlineCount, 10000);

    // 绑定 popup 点击事件
    const onlineBtn = document.getElementById('online-users');
    const onlinePopup = document.getElementById('online-users-popup');
    
    if (onlineBtn && onlinePopup) {
        onlineBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const isShowing = onlinePopup.classList.toggle('show');
            // 高亮状态
            onlineBtn.classList.toggle('active', isShowing);
        });

        // 点击外部关闭
        document.addEventListener('click', (e) => {
            if (!onlineBtn.contains(e.target) && !onlinePopup.contains(e.target)) {
                onlinePopup.classList.remove('show');
                onlineBtn.classList.remove('active');
            }
        });
    }
}

// 函数: 加载历史记录
async function loadMoreMessages() {
    if (isLoadingHistory || !oldestMsgId) return;
    isLoadingHistory = true;

    try {
        const res = await fetch(`/api/room/${currentRoom}/history?cursor=${oldestMsgId}`);
        if (res.ok) {
            const data = await res.json();
            if (data.success && data.messages.length > 0) {
                // 记录当前的滚动高度和位置
                const oldScrollHeight = chatWindow.scrollHeight;
                const oldScrollTop = chatWindow.scrollTop;

                // 更新 cursor 为这批数据中最老的一条
                // data.messages 是 [Oldest, ..., Newest]
                oldestMsgId = data.messages[0].msg_id;

                // 倒序遍历
                for (let i = data.messages.length - 1; i >= 0; i--) {
                    const msg = data.messages[i];
                    const senderName = msg.sender_username || msg.sender || "anonymous";
                    addMessage(senderName, msg.text, "received", msg.timestamp, msg.msg_id, "prepend", msg.is_deleted, msg.is_censored);
                }

                // 恢复滚动位置
                // 新的 scrollHeight - 旧的 scrollHeight = 增加的高度
                const newScrollHeight = chatWindow.scrollHeight;
                chatWindow.scrollTop = newScrollHeight - oldScrollHeight;

            } else {
                console.log("No more history.");
                oldestMsgId = null; 
            }
        }
    } catch (e) {
        console.error("Load history failed:", e);
    } finally {
        isLoadingHistory = false;
    }
}

// 函数：获取并更新在线人数及列表
async function fetchOnlineCount() {
    const onlineDisplay = document.getElementById('online-users');
    const onlinePopup = document.getElementById('online-users-popup');
    if (!onlineDisplay) return;

    try {
        const res = await fetch('/api/online-users');
        if (res.ok) {
            const data = await res.json();
            if (data.success) {
                const users = data.users;
                onlineDisplay.textContent = `${users.length} online`;
                onlineDisplay.style.color = "var(--text-color)";

                if (onlinePopup) {
                    renderOnlineUsersPopup(onlinePopup, users);
                }
            }
        } else if (res.status === 401) {
            onlineDisplay.textContent = "auth required";
        }
    } catch (e) {
        console.error("Failed to fetch online users:", e);
        onlineDisplay.textContent = "error";
        onlineDisplay.style.color = "var(--text-color)";
    }
}

// 辅助函数：渲染 online user popup 内容
function renderOnlineUsersPopup(container, users) {
    container.innerHTML = "";
    
    if (users.length === 0) {
        container.textContent = "no one online";
        return;
    }

    // 分组逻辑
    const currentRoomUsers = [];
    const otherRoomUsers = {};

    users.forEach(u => {
        if (u.channel === currentRoom) {
            currentRoomUsers.push(u);
        } else {
            if (!otherRoomUsers[u.channel]) {
                otherRoomUsers[u.channel] = [];
            }
            otherRoomUsers[u.channel].push(u);
        }
    });

    if (currentRoomUsers.length > 0) {
        const title = document.createElement("div");
        title.className = "user-group-title";
        title.textContent = "current room";
        container.appendChild(title);

        currentRoomUsers.forEach(u => {
            const item = document.createElement("div");
            item.className = "user-list-item";
            item.textContent = u.username;
            container.appendChild(item);
        });
    }

    for (const [channel, channelUsers] of Object.entries(otherRoomUsers)) {
        const title = document.createElement("div");
        title.className = "user-group-title";
        title.textContent = `${channel}`;
        container.appendChild(title);

        channelUsers.forEach(u => {
            const item = document.createElement("div");
            item.className = "user-list-item";
            item.textContent = u.username;
            container.appendChild(item);
        });
    }
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
  oldestMsgId = null; // 重置分页 cursor
  isLoadingHistory = false;
  updateActiveRoomUI(roomName);

  messageInput.placeholder = ROOM_PLACEHOLDERS[roomName] || "input...";
  
  // 4. 清空聊天界面
  chatWindow.innerHTML = ""; 
  statusText.innerText = "connecting...";
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
    if (socket !== currentSocket) return;
    console.log("连接成功");
    statusText.innerText = "connected";
    statusText.style.color = "var(--connection-green)";
    setTimeout(fetchOnlineCount, 500);
  };

  socket.onmessage = (event) => {
    console.log("收到:", event.data);
    try {
        const msg = JSON.parse(event.data);
        // 初始化 cursor: 记录收到的第一条消息 ID (最老的一条)
        if (oldestMsgId === null && msg.msg_id) {
            oldestMsgId = msg.msg_id;
        }

        const senderName = msg.sender_username || msg.sender || "anonymous";
        addMessage(senderName, msg.text, "received", msg.timestamp, msg.msg_id, "append", msg.is_deleted, msg.is_censored);
    } catch (e) {
        // 向后兼容
        addMessage("anonymous", event.data, "received");
    }
  };

  socket.onclose = () => {
    if (socket !== currentSocket) return;
    statusText.innerText = "disconnected";
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

    // 乐观 UI
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

// 辅助函数: 解析换行并安全添加到元素
function appendTextWithBr(container, text) {
    const parts = text.split('<br>');
    parts.forEach((part, index) => {
        if (index > 0) {
            container.appendChild(document.createElement('br'));
        }
        container.appendChild(document.createTextNode(part));
    });
}

// 辅助函数：添加消息到屏幕
function addMessage(sender, text, type, timestamp = Date.now(), msgId = null, method = "append", isDeleted = false, isCensored = false) {
    // 检查是否存在: 如果存在则更新内容
    if (msgId) {
        const existingDiv = document.querySelector(`.message[data-msg-id="${msgId}"]`);
        if (existingDiv) {
            const contentDiv = existingDiv.lastElementChild;
            if (contentDiv) {
                const cleanedText = cleanMessage(text);
                contentDiv.innerHTML = ""; // 清空
                appendTextWithBr(contentDiv, cleanedText);
                
                if (isDeleted || isCensored) {
                    contentDiv.style.color = "var(--border-color)";
                }
            }
            return;
        }
    }

    const div = document.createElement('div');
    div.className = 'message';
    div.style.marginBottom = "10px"; // 增加一点消息间距
    if (msgId) {
        div.dataset.msgId = msgId;
    }
    
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

    } else if (sender === "system" || sender === "caffeine" || sender === "console") {
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

    // copy msg-id 按钮
    const copySpan = document.createElement('span');
    copySpan.textContent = "#";
    copySpan.className = "msg-id-copy";
    copySpan.title = "msg-id";
    
    if (msgId) {
        copySpan.addEventListener('click', () => {
            navigator.clipboard.writeText(msgId).then(() => {
                const originalText = copySpan.textContent;
                copySpan.textContent = "✓";
                setTimeout(() => {
                    copySpan.textContent = originalText;
                }, 1000);
            }).catch(err => {
                console.error('Failed to copy:', err);
            });
        });
    }

    headerDiv.appendChild(senderSpan);
    headerDiv.appendChild(timeSpan);
    if (msgId) headerDiv.appendChild(copySpan);

    // --- 第二行：内容 ---
    const contentDiv = document.createElement('div');
    contentDiv.style.wordBreak = "break-word"; // 防止长单词撑破
    contentDiv.style.lineHeight = "1.4";
    contentDiv.style.fontWeight = "normal";
    
    if (isDeleted || isCensored) {
        contentDiv.style.color = "var(--border-color)";
    }

    // 解析换行
    appendTextWithBr(contentDiv, text);

    // --- 拼装 ---
    div.appendChild(headerDiv);
    div.appendChild(contentDiv);

    // 上墙
    if (method === "prepend") {
        chatWindow.prepend(div);
    } else {
        // append: 智能滚动
        // 如果用户已经在底部附近 (<100px)，或者消息是自己发的，就自动滚动
        const isNearBottom = chatWindow.scrollHeight - chatWindow.scrollTop - chatWindow.clientHeight < 100;
        
        chatWindow.appendChild(div);
        
        if (type === "sent" || isNearBottom) {
            chatWindow.scrollTop = chatWindow.scrollHeight;
        }
    }
}

/* 启动 */

init();