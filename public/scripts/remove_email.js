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

const form = document.getElementById('remove-email-form');
const msgBox = document.getElementById('auth-message');

// 接管浏览器原生验证提示
form.querySelectorAll('input').forEach(input => {
    input.addEventListener('invalid', function(e) {
        e.preventDefault();
        const oldTip = this.parentNode.querySelector('.error-tip');
        if (oldTip) oldTip.remove();

        const tip = document.createElement('div');
        tip.className = 'error-tip';
        tip.innerText = this.validationMessage;
        this.parentNode.appendChild(tip);
        setTimeout(() => { tip.remove(); }, 2000);
    });
});

form.addEventListener('submit', async function(e) {
    e.preventDefault();
    msgBox.style.display = 'none';
    msgBox.className = 'auth-message';

    const password = document.getElementById('password').value;

    try {
        const formData = new FormData();
        formData.append('password', password);

        const res = await fetch('/api/user/unbind-email', {
            method: 'POST',
            body: formData
        });

        const data = await res.json();

        if (data.success) {
            msgBox.innerText = data.message;
            msgBox.style.display = 'block';
            msgBox.classList.add('success');
            setTimeout(() => {
                window.location.href = '/user/settings.html';
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