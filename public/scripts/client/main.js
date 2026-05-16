// public/scripts/client/main.js

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

/* Entry Point */
init();
