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

const form = document.getElementById('bind-email-form');
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

    const email = document.getElementById('email').value;

    try {
        const formData = new FormData();
        formData.append('email', email);

        const res = await fetch('/api/user/bind-email', {
            method: 'POST',
            body: formData
        });

        const data = await res.json();

        if (data.success) {
            msgBox.innerText = data.message;
            msgBox.style.display = 'block';
            msgBox.classList.add('success');
            // 成功后禁用按钮防止重复发送
            form.querySelector('button').disabled = true;
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