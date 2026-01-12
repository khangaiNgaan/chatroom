document.addEventListener('DOMContentLoaded', () => {
    loadSessions();
    loadUserInfo();
});

async function loadUserInfo() {
    try {
        const response = await fetch('/api/user');
        if (response.ok) {
            const user = await response.json();
            document.getElementById('user-display').innerHTML = `Hi, ${user.username} (<a href="/api/logout">logout</a>) `;
        } else {
             window.location.href = '/auth/login.html';
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
            window.location.href = '/auth/login.html';
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
        list.innerHTML = '<div class="error">Network error</div>';
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
        
        // Truncate UA if too long
        let ua = session.user_agent || 'unknown device';
        if (ua.length > 80) ua = ua.substring(0, 80) + '...';
        
        const ip = session.ip || 'unknown IP';
        
        let html = `
            <div class="session-info">
                <div class="session-meta">
                    <span class="session-ip">${ip}</span>
                    ${session.is_current ? '<span class="current-badge">THIS DEVICE</span>' : ''}
                </div>
                <div class="session-details">
                    <div title="${session.user_agent}">${ua}</div>
                    <div>Created: ${date}</div>
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
            alert('Failed to revoke session: ' + (data.message || 'Unknown error'));
        }
    } catch (err) {
        alert('Network error');
    }
};
