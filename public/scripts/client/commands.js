// public/scripts/client/commands.js

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
