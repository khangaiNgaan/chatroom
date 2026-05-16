// public/scripts/client/ui.js

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

    } else if (sender === "system" || sender === "caffeine" || sender === "console" || sender === "newsbot") {
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
