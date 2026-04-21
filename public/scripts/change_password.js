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

const form = document.getElementById('change-password-form');

// override native validation tooltips
if (window.setupFormValidation) window.setupFormValidation(form);

form.addEventListener('submit', async function(e) {
    e.preventDefault();
    const msgBox = document.getElementById('auth-message');
    msgBox.style.display = 'none';
    msgBox.className = 'auth-message';

    const oldPassword = document.getElementById('old-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmNewPassword = document.getElementById('confirm-new-password').value;

    if (newPassword !== confirmNewPassword) {
        msgBox.innerText = "new passwords do not match";
        msgBox.style.display = 'block';
        msgBox.classList.add('error');
        return;
    }

    try {
        const formData = new FormData();
        formData.append('old-password', oldPassword);
        formData.append('new-password', newPassword);

        const res = await fetch('/api/user/change-password', {
            method: 'POST',
            body: formData
        });

        const data = await res.json();

        if (data.success) {
            msgBox.innerText = data.message;
            msgBox.style.display = 'block';
            msgBox.classList.add('success');
            setTimeout(() => {
                window.location.href = '/user/settings';
            }, 5000);
        } else {
            msgBox.innerText = data.message;
            msgBox.style.display = 'block';
            msgBox.classList.add('error');
        }
    } catch (err) {
        msgBox.innerText = "network error";
        msgBox.style.display = 'block';
        msgBox.classList.add('error');
    }
});

loadUserInfo();