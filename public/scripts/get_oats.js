// Utils
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

// Main
(async function() {
    const userDisplay = document.getElementById('user-display');
    const listDiv = document.getElementById('tokens-list');
    const createForm = document.getElementById('create-token-form');
    const newTokenDisplay = document.getElementById('new-token-display');
    const tokenSecretText = document.getElementById('token-secret-text');
    const copyBtn = document.getElementById('copy-token-button');
    const closeBtn = document.getElementById('close-token-button');

    // 0. Button Listeners
    copyBtn.addEventListener('click', () => {
        const text = tokenSecretText.textContent;
        navigator.clipboard.writeText(text).then(() => {
            const originalText = copyBtn.textContent;
            copyBtn.textContent = 'done';
            setTimeout(() => { copyBtn.textContent = originalText; }, 2000);
        });
    });

    closeBtn.addEventListener('click', () => {
        newTokenDisplay.style.display = 'none';
    });

    // 1. Auth Check
    try {
        const res = await fetch('/api/user');
        if (res.status === 401) {
            window.location.href = '/auth/login.html';
            return;
        }
        if (res.ok) {
            const user = await res.json();
            userDisplay.innerHTML = `Hi, ${user.username} (<a href="/api/logout">logout</a>) `;
            loadOats();
        }
    } catch (e) {
        console.error(e);
        userDisplay.innerText = "error loading profile";
    }

    createForm.querySelectorAll('input').forEach(input => {
        input.addEventListener('invalid', function(e) {
            e.preventDefault();
            const tip = document.createElement('div');
            tip.className = 'error-tip';
            tip.innerText = this.validationMessage;
            this.parentNode.appendChild(tip);
            setTimeout(() => { tip.remove(); }, 2000);
        });
    });

    // 2. Load OATs
    async function loadOats() {
        try {
            const res = await fetch('/api/oats');
            const data = await res.json();
            
            if (data.success) {
                renderList(data.oats);
            } else {
                listDiv.innerHTML = `<div class="alert" style="color: var(--connection-red);">Error: ${data.message}</div>`;
            }
        } catch (e) {
            listDiv.innerHTML = `<div class="alert" style="color: var(--connection-red);">Network error</div>`;
        }
    }

    // 3. Render List
    function renderList(oats) {
        if (oats.length === 0) {
            listDiv.innerHTML = `<div class="alert">No active OATs</div>`;
            return;
        }

        listDiv.innerHTML = '';
        oats.forEach(t => {
            const div = document.createElement('div');
            div.className = 'token-item';
            
            div.innerHTML = `
                <div class="token-info">
                    <span class="token-label">${escapeHtml(t.label || 'Unnamed')}</span>
                    <span class="token-mask">${formatDate(t.created_at)}</span>
                </div>
                <button class="btn-delete" data-id="${t.id}">delete</button>
            `;
            
            // Bind delete event
            div.querySelector('.btn-delete').addEventListener('click', () => deleteOat(t.id));
            listDiv.appendChild(div);
        });
    }

    // 4. Create OAT
    createForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(createForm);
        
        try {
            const res = await fetch('/api/oats', {
                method: 'POST',
                body: formData
            });
            const data = await res.json();
            
            if (data.success) {
                // Show secret
                tokenSecretText.textContent = data.ticket;
                newTokenDisplay.style.display = 'block';
                createForm.reset();
                // Reload list
                loadOats();
            } else {
                alert("Failed: " + data.message);
            }
        } catch (e) {
            alert("network error");
        }
    });

    // 5. Delete OAT
    async function deleteOat(id) {
        if (!confirm("Are you sure you want to delete this OAT? This action cannot be undone.")) return;
        
        try {
            const res = await fetch(`/api/oats?id=${id}`, { method: 'DELETE' });
            const data = await res.json();
            if (data.success) {
                loadOats();
            } else {
                alert("Delete failed: " + data.message);
            }
        } catch (e) {
            alert("network error");
        }
    }

    function escapeHtml(text) {
        if (!text) return text;
        return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }

})();