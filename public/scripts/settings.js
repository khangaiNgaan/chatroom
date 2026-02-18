async function loadUserInfo() {
    try {
        const response = await fetch('/api/user');
        if (response.ok) {
            const user = await response.json();
            document.getElementById('user-display').innerHTML = `Hi, ${user.username} (<a href="/api/logout">logout</a>) `;
            
            // 显示邮箱状态
            const boundSection = document.getElementById('email-bound-section');
            const unboundSection = document.getElementById('email-unbound-section');
            const emailSpan = document.getElementById('current-email');

            if (user.email && user.email_verified) {
                if (boundSection && emailSpan) {
                    emailSpan.textContent = user.email;
                    boundSection.style.display = 'block';
                    if (unboundSection) unboundSection.style.display = 'none';
                }
            } else {
                if (unboundSection) {
                    unboundSection.style.display = 'block';
                    if (boundSection) boundSection.style.display = 'none';
                }
            }

            // 2FA 状态
            const twoFaMsg = document.getElementById('2fa-enabled-msg');
            if (user.two_factor_enabled && twoFaMsg) {
                twoFaMsg.style.display = 'block';
            }
        } else {
             window.location.href = '/auth/login.html';
        }
    } catch (e) {
        console.error(e);
    }
}
loadUserInfo();