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

const form = document.getElementById('bind-email-form');
const msgBox = document.getElementById('auth-message');

if (window.setupFormValidation) {
    window.setupFormValidation(form);
}

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
            // disable button after success
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