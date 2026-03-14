document.addEventListener('DOMContentLoaded', () => {
    loadSessions();
    loadUserInfo();

    const revokeAllBtn = document.getElementById('revoke-all-btn');
    if (revokeAllBtn) {
        revokeAllBtn.addEventListener('click', revokeAllOthers);
    }
});

async function revokeAllOthers() {
    if (!confirm('Are you sure you want to revoke all other sessions and delete all Opaque Auth Tickets (OATs)? This will log out all other devices.')) return;

    try {
        const response = await fetch('/api/sessions/others', {
            method: 'DELETE'
        });
        const data = await response.json();
        if (data.success) {
            loadSessions();
            alert('All other sessions and OATs have been revoked.');
        } else {
            alert('failed to revoke: ' + (data.message || 'Unknown error'));
        }
    } catch (err) {
        alert('network error');
    }
}

async function loadUserInfo() {
    try {
        const response = await fetch('/api/user');
        if (response.ok) {
            const user = await response.json();
            document.getElementById('user-display').innerHTML = `Hi, ${user.username} (<a href="/api/logout">logout</a>) `;
        } else {
             window.location.href = '/auth/login';
        }
    } catch (e) {
        console.error(e);
    }
}

async function loadSessions() {
    const list = document.getElementById('sessions-list');
    list.innerHTML = '<div class="loading">loading sessions...</div>';

    try {
        const response = await fetch('/api/sessions');
        if (response.status === 401) {
            window.location.href = '/auth/login';
            return;
        }
        
        const data = await response.json();
        if (data.success) {
            renderSessions(data.sessions);
        } else {
            list.innerHTML = '<div class="error">failed to load sessions</div>';
        }
    } catch (err) {
        console.error(err);
        list.innerHTML = '<div class="error">network error</div>';
    }
}

function renderSessions(sessions) {
    const list = document.getElementById('sessions-list');
    list.innerHTML = '';

    if (sessions.length === 0) {
        list.innerHTML = '<div class="no-sessions">No active sessions found.</div>';
        return;
    }

    sessions.forEach(session => {
        const item = document.createElement('div');
        item.className = `session-item ${session.is_current ? 'current' : ''}`;
        
        const date = new Date(session.created_at).toLocaleString();
        const expireDate = new Date(session.expires_at).toLocaleString();
        
        // Truncate UA if too long
        let ua = session.user_agent || 'unknown device';
        
        const ip = session.ip || 'unknown IP';
        
        let html = `
            <div class="session-info">
                <div class="session-meta">
                    <span class="session-ip">${ip}</span>
                    ${session.is_current ? '<span class="current-badge">THIS DEVICE</span>' : ''}
                </div>
                <div class="session-details">
                    <div title="${session.user_agent}">${ua}</div>
                    <div>Created: ${date}, Expires: ${expireDate}</div>
                </div>
            </div>
        `;
        
        if (!session.is_current) {
            html += `<button class="btn-revoke" onclick="revokeSession('${session.id}')">revoke</button>`;
        } else {
             html += `<div style="width: 60px;"></div>`; 
        }

        item.innerHTML = html;
        list.appendChild(item);
    });
}

window.revokeSession = async function(id) {
    if (!confirm('Are you sure you want to revoke this session?')) return;

    try {
        const response = await fetch(`/api/sessions?id=${id}`, {
            method: 'DELETE'
        });
        const data = await response.json();
        if (data.success) {
            loadSessions();
        } else {
            alert('failed to revoke session: ' + (data.message || 'Unknown error'));
        }
    } catch (err) {
        alert('network error');
    }
};
