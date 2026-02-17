document.addEventListener('DOMContentLoaded', () => {
    // 1. 检查 SessionStorage
    const username = sessionStorage.getItem('signup_username');
    const password = sessionStorage.getItem('signup_password');

    if (!username || !password) {
        window.location.href = '/auth/signup.html';
        return;
    }

    const form = document.getElementById('signup-method-form');
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

    // 表单提交
    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        msgBox.style.display = 'none';
        msgBox.className = 'auth-message';

        const formData = new FormData(form);
        formData.append('username', username);
        formData.append('password', password);
        // 不再需要 'method' 字段，由后端判断内容

        if (window.turnstile) {
            const token = window.turnstile.getResponse();
            if (token) formData.append('cf-turnstile-response', token);
        }

        const email = formData.get('email');
        const inviteCode = formData.get('invite-code');

        if (!email && !inviteCode) {
            msgBox.innerText = "please provide at least one verification method";
            msgBox.style.display = 'block';
            msgBox.classList.add('error');
            return;
        }

        try {
            const res = await fetch('/api/signup', {
                method: 'POST',
                body: formData
            });
            
            const data = await res.json();

            if (data.success) {
                msgBox.innerText = data.message;
                msgBox.style.display = 'block';
                msgBox.classList.add('success');
                
                sessionStorage.removeItem('signup_username');
                sessionStorage.removeItem('signup_password');

                if (data.redirect) {
                    setTimeout(() => {
                        window.location.href = data.redirect;
                    }, 2000);
                } else {
                    // 邮箱流程，隐藏表单
                    form.style.display = 'none'; 
                }
            } else {
                msgBox.innerText = data.message;
                msgBox.style.display = 'block';
                msgBox.classList.add('error');
                if (window.turnstile) window.turnstile.reset();
            }
        } catch (err) {
            msgBox.innerText = "network error";
            msgBox.style.display = 'block';
            msgBox.classList.add('error');
        }
    });
});