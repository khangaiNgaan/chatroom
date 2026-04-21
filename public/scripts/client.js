// public/scripts/client.js

/* UI Elements */

const chatWindow = document.getElementById('chat-window');
const chatForm = document.getElementById('chat-form');
const roomList = document.getElementById('room-list');
const messageInput = document.getElementById('message-input');
const statusText = document.getElementById('status');
const retryButton = document.getElementById('retryButton');
const reloadButton = document.getElementById('reloadButton');

/* Room Configuration */

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
let currentUser = null;
let oldestMsgId = null;
let isLoadingHistory = false;

/* Functions */

// initialize application state
async function init() {
    // enforce login check
    try {
        const res = await fetch('/api/user');
        if (res.status === 401) {
            window.location.href = '/auth/login';
            return;
        }
        if (res.ok) {
            const user = await res.json();
            currentUser = user.username;
            console.log("Logged in as:", currentUser);
            
            // update username display
            const userDisplay = document.getElementById('user-display');
            if (userDisplay) {
                userDisplay.innerHTML = `Hi, <a href="/user/profile">${currentUser}</a> (<a href="/api/logout">logout</a>) `;
            }
        }
    } catch (e) {
        console.error("Auth check failed:", e);
    }

    renderRoomList();
    
    if (retryButton) {
        retryButton.style.display = 'none';
        retryButton.addEventListener('click', () => {
            console.log("reconnecting...");
            retryButton.style.display = 'none';
            joinRoom(currentRoom);
        });
    }
    if (reloadButton) {
        reloadButton.style.display = 'none';
        reloadButton.addEventListener('click', () => {
            console.log("reloading...");
            window.location.reload();
        });
    }

    // bind scroll for pagination
    chatWindow.addEventListener('scroll', () => {
        if (chatWindow.scrollTop === 0 && !isLoadingHistory && oldestMsgId) {
            loadMoreMessages();
        }
    });

    joinRoom(currentRoom);

    // poll online user count
    fetchOnlineCount();
    setInterval(fetchOnlineCount, 10000);

    // bind popup click events
    const onlineBtn = document.getElementById('online-users');
    const onlinePopup = document.getElementById('online-users-popup');
    const channelBtn = document.getElementById('channel-menu-btn');
    const channelPopup = document.getElementById('channel-popup');
    
    if (onlineBtn && onlinePopup) {
        onlineBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const isShowing = onlinePopup.classList.toggle('show');
            onlineBtn.classList.toggle('active', isShowing);
            
            if (channelPopup) {
                channelPopup.classList.remove('show');
                channelBtn.classList.remove('active');
            }
        });
    }

    if (channelBtn) {
        channelBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            if (roomList) {
                roomList.classList.toggle('show');
            }
            if (onlinePopup) {
                onlinePopup.classList.remove('show');
                onlineBtn.classList.remove('active');
            }
        });
    }

    // close popups on outside click
    document.addEventListener('click', (e) => {
        if (onlineBtn && onlinePopup && !onlineBtn.contains(e.target) && !onlinePopup.contains(e.target)) {
            onlinePopup.classList.remove('show');
            onlineBtn.classList.remove('active');
        }
        if (roomList && roomList.classList.contains('show') && !roomList.contains(e.target) && channelBtn && !channelBtn.contains(e.target)) {
            roomList.classList.remove('show');
        }
    });
}

// load more chat history
async function loadMoreMessages() {
    if (isLoadingHistory || !oldestMsgId) return;
    isLoadingHistory = true;

    try {
        const res = await fetch(`/api/room/${currentRoom}/history?cursor=${oldestMsgId}`);
        if (res.ok) {
            const data = await res.json();
            if (data.success && data.messages.length > 0) {
                // record scroll position
                const oldScrollHeight = chatWindow.scrollHeight;
                const oldScrollTop = chatWindow.scrollTop;

                // update cursor to oldest message
                oldestMsgId = data.messages[0].msg_id;

                // prepend messages in reverse order
                for (let i = data.messages.length - 1; i >= 0; i--) {
                    const msg = data.messages[i];
                    const senderName = msg.sender_username || msg.sender || "anonymous";
                    addMessage(senderName, msg.text, "received", msg.timestamp, msg.msg_id, "prepend", msg.is_deleted, msg.is_censored, msg.is_bridged);
                }

                // restore scroll position
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

// update online user list
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
        console.error("failed to fetch online users:", e);
        onlineDisplay.textContent = "error";
        onlineDisplay.style.color = "var(--text-color)";
    }
}

// render online users popup
function renderOnlineUsersPopup(container, users) {
    container.innerHTML = "";
    
    if (users.length === 0) {
        container.textContent = "no one online";
        return;
    }

    // group users by channel
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

// render chat room list
function renderRoomList() {
    roomList.innerHTML = "";

    ROOMS.forEach(roomName => {
    const div = document.createElement("div");
    div.textContent = roomName;
    div.className = "room-item";
    div.dataset.room = roomName;

    div.addEventListener("click", () => {
      if (currentRoom !== roomName) {
        joinRoom(roomName);
      }
    });

    roomList.appendChild(div);
  });

}

// switch active chat room
function joinRoom(roomName) {

  if (retryButton) retryButton.style.display = 'none';
  if (reloadButton) reloadButton.style.display = 'none';
  
  // disconnect current session
  if (currentSocket) {
    console.log(`disconnecting from ${currentRoom}...`);
    currentSocket.close();
  }

  // update UI state
  currentRoom = roomName;
  oldestMsgId = null; 
  isLoadingHistory = false;
  updateActiveRoomUI(roomName);

  const channelBtn = document.getElementById('channel-menu-btn');
  if (channelBtn) {
    channelBtn.textContent = roomName;
  }

  messageInput.placeholder = ROOM_PLACEHOLDERS[roomName] || "input...";
  
  // clear chat interface
  chatWindow.innerHTML = ""; 
  statusText.innerText = "connecting...";
  statusText.style.color = "var(--comment-color)";

  // establish new connection
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${protocol}//${window.location.host}/websocket/${roomName}`;
  
  currentSocket = new WebSocket(wsUrl);

  setupSocketListeners(currentSocket);
}

// highlight active room
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


// bind websocket event listeners
function setupSocketListeners(socket) {
  socket.onopen = () => {
    if (socket !== currentSocket) return;
    console.log("connected successfully");
    statusText.innerText = "connected";
    statusText.style.color = "var(--connection-green)";
    setTimeout(fetchOnlineCount, 500);
  };

  socket.onmessage = (event) => {
    console.log("received:", event.data);
    try {
        const msg = JSON.parse(event.data);

        // handle bridge status notification
        if (msg.type === "bridge_status" && msg.status === "success" && msg.msg_id) {
            const existingDiv = document.querySelector(`.message[data-msg-id="${msg.msg_id}"]`);
            if (existingDiv) {
                const headerDiv = existingDiv.firstElementChild;
                const copySpan = existingDiv.querySelector('.msg-id-copy');
                if (headerDiv && copySpan && !existingDiv.querySelector('.bridge-success-mark')) {
                    const checkmark = document.createElement('span');
                    checkmark.className = "bridge-success-mark";
                    checkmark.textContent = "✓";
                    checkmark.style.color = "var(--success-color, #347b68)";
                    checkmark.style.marginLeft = "5px";
                    checkmark.style.fontSize = "0.85em";
                    checkmark.title = "synced";
                    headerDiv.insertBefore(checkmark, copySpan);
                }
            }
            return;
        }

        // initialize cursor with first message
        if (oldestMsgId === null && msg.msg_id) {
            oldestMsgId = msg.msg_id;
        }

        const senderName = msg.sender_username || msg.sender || "anonymous";
        addMessage(senderName, msg.text, "received", msg.timestamp, msg.msg_id, "append", msg.is_deleted, msg.is_censored, msg.is_bridged);
    } catch (e) {
        addMessage("anonymous", event.data, "received");
    }
  };

  socket.onclose = () => {
    if (socket !== currentSocket) return;
    statusText.innerText = "disconnected";
    statusText.style.color = "var(--connection-red)";
    console.log("connection lost");
    
    if (retryButton) {
      retryButton.style.display = 'inline';
    }
    if (reloadButton) {
      reloadButton.style.display = 'inline';
    }
  };

  socket.onerror = (error) => {
    console.error("WebSocket error:", error);
  };
}

// format date to ISO string
function formatLocalISOString(date) {
    const pad = (n) => n.toString().padStart(2, '0');
    const year = date.getFullYear();
    const month = pad(date.getMonth() + 1);
    const day = pad(date.getDate());
    const hour = pad(date.getHours());
    const minute = pad(date.getMinutes());
    const second = pad(date.getSeconds());
    
    const timezoneOffset = -date.getTimezoneOffset();
    const diffSign = timezoneOffset >= 0 ? '+' : '-';
    const diffHour = pad(Math.floor(Math.abs(timezoneOffset) / 60));
    const diffMin = pad(Math.abs(timezoneOffset) % 60);
    
    return `${year}-${month}-${day}T${hour}:${minute}:${second}${diffSign}${diffHour}:${diffMin}`;
}

// process chat export command
async function handleSaveCommand(text) {
    const args = text.trim().split(/\s+/);
    const cmd = args[0];
    const param = args[1];

    if (cmd !== "/save") return false;

    let limit = "all";
    if (!param) {
        addMessage("system", "usage: /save all OR /save <num>", "received");
        return true;
    }
    if (param === "all") {
        limit = "all";
    } else if (/^\d+$/.test(param)) {
        const count = parseInt(param, 10);
        if (count > 0) {
            limit = count;
        } else {
            addMessage("system", "Number must be greater than 0.<br>usage: /save all OR /save <num>", "received");
            return true;
        }
    } else {
        addMessage("system", "Invalid parameter.<br>usage: /save all OR /save <num>", "received");
        return true;
    }

    addMessage("system", `Exporting ${limit === 'all' ? 'all' : limit} messages, please wait...`, "received");

    try {
        const res = await fetch(`/api/room/${currentRoom}/export?limit=${limit}`);
        if (!res.ok) {
            throw new Error(`Server returned ${res.status}`);
        }
        
        const data = await res.json();
        if (!data.success || !data.messages || data.messages.length === 0) {
            addMessage("system", "No messages found to save.", "received");
            return true;
        }

        const messagesToSave = data.messages;

        // generate csv content
        let csvContent = "msg-timestamp-hex,datetime,uid,username,text\n";

        messagesToSave.forEach(msg => {
            const date = new Date(msg.timestamp);
            const timeStr = formatLocalISOString(date);
            
            const safeText = `"${(msg.text || "").replace(/"/g, '""')}"`;
            
            const uid = msg.sender_uid;
            const username = msg.sender_username;

            csvContent += `${msg.msg_id},${timeStr},${uid},${username},${safeText}\n`;
        });

        // define export filename
        const rawNowStr = formatLocalISOString(new Date());
        const nowStr = rawNowStr.replace(/:/g, '');
        const filename = `${currentRoom}_${nowStr}(${messagesToSave.length}).txt`;

        // trigger file download
        const blob = new Blob([csvContent], { type: 'text/plain;charset=utf-8;' }); 
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.setAttribute("href", url);
        link.setAttribute("download", filename);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);

        addMessage("system", `Saved ${messagesToSave.length} messages to ${filename}`, "received");

    } catch (e) {
        console.error("Export failed:", e);
        addMessage("system", `Export failed: ${e.message}`, "received");
    }

    return true;
}

// handle chat form submission
chatForm.addEventListener('submit', async (e) => {
    e.preventDefault(); 
    
    const text = messageInput.value;
    if (!text) return; 

    // intercept /save command
    if (text.startsWith("/save")) {
        messageInput.value = '';
        await handleSaveCommand(text);
        return;
    }

    // transmit message via websocket
    if (currentSocket.readyState === WebSocket.OPEN) {
        currentSocket.send(text);
        console.log("sent:", text);
    } else {
        console.warn("not connected");
        alert("Not connected to the server.");
    }

    messageInput.value = '';
});

// remove variation selector characters
function cleanMessage(text) {
  return text.replace(/\uFE0F/g, '');
}

// format timestamp to readable date
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

// decode html entities
function decodeHtmlEntities(text) {
    return text.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}

// parse formatting tags safely
function appendParsedText(container, text) {
    const regex = /(<br>|<b>|<\/b>|<a\s+href="[^"]*">|<\/a>)/gi;
    const parts = text.split(regex);
    
    let currentContainer = container;
    const stack = []; 

    for (let i = 0; i < parts.length; i++) {
        let part = parts[i];
        if (part === undefined || part === "") continue;

        if (i % 2 === 1) { 
            const matchStr = part.toLowerCase();
            
            if (matchStr === '<br>') {
                currentContainer.appendChild(document.createElement('br'));
            } else if (matchStr === '<b>') {
                const b = document.createElement('b');
                currentContainer.appendChild(b);
                stack.push({ type: 'b', element: b, parent: currentContainer });
                currentContainer = b;
            } else if (matchStr === '</b>') {
                let found = false;
                for (let j = stack.length - 1; j >= 0; j--) {
                    if (stack[j].type === 'b') {
                        const popped = stack.splice(j);
                        currentContainer = popped[0].parent;
                        found = true;
                        break;
                    }
                }
                if (!found) currentContainer.appendChild(document.createTextNode(decodeHtmlEntities(part)));
            } else if (matchStr.startsWith('<a ')) {
                const urlMatch = part.match(/^<a\s+href="([^"]*)">$/i);
                if (urlMatch) {
                    const url = urlMatch[1];
                    const a = document.createElement('a');
                    a.href = `/redirect.html?url=${encodeURIComponent(url)}`;
                    a.target = "_blank";
                    currentContainer.appendChild(a);
                    stack.push({ type: 'a', element: a, parent: currentContainer });
                    currentContainer = a;
                } else {
                    currentContainer.appendChild(document.createTextNode(decodeHtmlEntities(part)));
                }
            } else if (matchStr === '</a>') {
                let found = false;
                for (let j = stack.length - 1; j >= 0; j--) {
                    if (stack[j].type === 'a') {
                        const popped = stack.splice(j);
                        currentContainer = popped[0].parent;
                        found = true;
                        break;
                    }
                }
                if (!found) currentContainer.appendChild(document.createTextNode(decodeHtmlEntities(part)));
            } else {
                currentContainer.appendChild(document.createTextNode(decodeHtmlEntities(part)));
            }
        } else { 
            currentContainer.appendChild(document.createTextNode(decodeHtmlEntities(part)));
        }
    }
}

// render message to chat window
function addMessage(sender, text, type, timestamp = Date.now(), msgId = null, method = "append", isDeleted = false, isCensored = false, isBridged = false) {
    // update existing message if found
    if (msgId) {
        const existingDiv = document.querySelector(`.message[data-msg-id="${msgId}"]`);
        if (existingDiv) {
            const contentDiv = existingDiv.lastElementChild;
            if (contentDiv) {
                const cleanedText = cleanMessage(text);
                contentDiv.innerHTML = ""; 
                appendParsedText(contentDiv, cleanedText);
                
                if (isDeleted || isCensored) {
                    contentDiv.style.color = "var(--comment-color)";
                }
            }
            return;
        }
    }

    const div = document.createElement('div');
    div.className = 'message';
    div.style.marginBottom = "10px"; 
    if (msgId) {
        div.dataset.msgId = msgId;
    }
    
    text = cleanMessage(text);
    
    // create message header
    const headerDiv = document.createElement('div');
    headerDiv.style.marginBottom = "3px";
    headerDiv.style.lineHeight = "1.4";

    const senderSpan = document.createElement('span');
    senderSpan.textContent = sender; 
    senderSpan.style.marginRight = "10px";
    senderSpan.style.fontWeight = "bold";
    
    if (sender === currentUser) {
        senderSpan.style.color = "var(--my-nom-color)";

    } else if (sender === "system" || sender === "caffeine" || sender === "console") {
        senderSpan.style.color = "var(--admin-nom-color)";
    } else if (sender === "EnderDragon") {
        senderSpan.style.color = "var(--dragon-nom-color)";
    } else {
        senderSpan.style.color = "var(--nom-color)";
    }

    const timeSpan = document.createElement('span');
    timeSpan.textContent = formatDate(timestamp);
    timeSpan.style.color = "var(--comment-color)";
    timeSpan.style.fontSize = "0.85em";
    timeSpan.style.fontFamily = "'unifont', monospace";

    let bridgeCheckmark = null;
    if (isBridged) {
        bridgeCheckmark = document.createElement('span');
        bridgeCheckmark.className = "bridge-success-mark";
        bridgeCheckmark.textContent = "✓";
        bridgeCheckmark.style.color = "var(--success-color, #347b68)";
        bridgeCheckmark.style.marginLeft = "5px";
        bridgeCheckmark.style.fontSize = "0.85em";
        bridgeCheckmark.title = "synced";
    }

    const copySpan = document.createElement('span');
    copySpan.textContent = "#";
    copySpan.className = "msg-id-copy";
    
    if (msgId) {
        copySpan.addEventListener('click', () => {
            navigator.clipboard.writeText(msgId).then(() => {
                const originalText = copySpan.textContent;
                copySpan.textContent = "✓";
                setTimeout(() => {
                    copySpan.textContent = originalText;
                }, 1000);
            }).catch(err => {
                console.error('failed to copy:', err);
            });
        });
    }

    headerDiv.appendChild(senderSpan);
    headerDiv.appendChild(timeSpan);
    if (bridgeCheckmark) headerDiv.appendChild(bridgeCheckmark);
    if (msgId) headerDiv.appendChild(copySpan);

    // create message content
    const contentDiv = document.createElement('div');
    contentDiv.style.wordBreak = "break-word"; 
    contentDiv.style.lineHeight = "1.4";
    contentDiv.style.fontWeight = "normal";
    
    if (isDeleted || isCensored) {
        contentDiv.style.color = "var(--comment-color)";
    }

    appendParsedText(contentDiv, text);

    div.appendChild(headerDiv);
    div.appendChild(contentDiv);

    if (method === "prepend") {
        chatWindow.prepend(div);
    } else {
        // smart auto-scroll logic
        const isNearBottom = chatWindow.scrollHeight - chatWindow.scrollTop - chatWindow.clientHeight < 100;
        
        chatWindow.appendChild(div);
        
        if (isNearBottom || sender === currentUser) {
            chatWindow.scrollTop = chatWindow.scrollHeight;
        }
    }
}

/* Entry Point */

init();