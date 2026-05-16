// public/scripts/client/api.js

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
