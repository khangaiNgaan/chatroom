function formatDate(timestamp) {
    if ((timestamp ?? null) === null) return 'unknown';
    const date = new Date(timestamp);
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const d = String(date.getDate()).padStart(2, '0');
    const h = String(date.getHours()).padStart(2, '0');
    const min = String(date.getMinutes()).padStart(2, '0');
    const s = String(date.getSeconds()).padStart(2, '0');
    return `${y}-${m}-${d} ${h}:${min}:${s}`;
}

(async function() {
    const userDisplay = document.getElementById('user-display');
    const pUid = document.getElementById('p-uid');
    const pUsername = document.getElementById('p-username');
    const pRole = document.getElementById('p-role');
    const pDate = document.getElementById('p-date');

    try {
        const res = await fetch('/api/user');
        
        if (res.status === 401) {
            window.location.href = '/auth/login.html';
            return;
        }

        if (res.ok) {
            const user = await res.json();
            
            userDisplay.innerHTML = `Hi, ${user.username} (<a href="/api/logout">logout</a>) `;
            
            pUid.innerText = user.uid || '-';
            pUid.classList.remove('loading-text');

            pUsername.innerText = user.username || '-';
            pUsername.classList.remove('loading-text');

            pRole.innerText = user.role || 'user';
            pRole.classList.remove('loading-text');

            pDate.innerText = formatDate(user.signup_date);
            pDate.classList.remove('loading-text');
        }
    } catch (e) {
        console.error(e);
        userDisplay.innerText = "error loading profile";
    }
})();