document.addEventListener('DOMContentLoaded', () => {
    // check session storage
    const username = sessionStorage.getItem('signup_username');
    const password = sessionStorage.getItem('signup_password');

    if (!username || !password) {
        window.location.href = '/auth/signup';
        return;
    }

    const form = document.getElementById('signup-method-form');
    const msgBox = document.getElementById('auth-message');

    // override native validation tooltips
    if (window.setupFormValidation) {
        window.setupFormValidation(form);
    }

    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        msgBox.style.display = 'none';
        msgBox.className = 'auth-message';

        const formData = new FormData(form);
        formData.append('username', username);
        formData.append('password', password);

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
                    // hide form for email flow
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