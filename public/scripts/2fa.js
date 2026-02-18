async function init2FA() {
    const loadingState = document.getElementById('loading-state');
    const enabledUI = document.getElementById('2fa-enabled-ui');
    const disabledUI = document.getElementById('2fa-disabled-ui');
    const userDisplay = document.getElementById('user-display');
    const authMessage = document.getElementById('auth-message');

    function showMessage(msg, type = 'error') {
        authMessage.textContent = msg;
        authMessage.className = `auth-message ${type}`;
        authMessage.style.display = 'block';
    }

    function clearMessage() {
        authMessage.style.display = 'none';
        authMessage.textContent = '';
        authMessage.className = 'auth-message';
    }

    function setupFormValidation(form) {
        if (!form) return;
        form.querySelectorAll('input').forEach(input => {
            input.addEventListener('invalid', function(e) {
                e.preventDefault();
                const oldTip = this.parentNode.querySelector('.error-tip');
                if (oldTip) oldTip.remove();

                const tip = document.createElement('div');
                tip.className = 'error-tip';
                tip.innerText = this.validationMessage;
                this.parentNode.appendChild(tip);
                setTimeout(() => { tip.remove(); }, 3000);
            });
        });
    }

    setupFormValidation(document.getElementById('verify-2fa-form'));
    setupFormValidation(document.getElementById('disable-2fa-form'));

    async function fetchApi(url, options = {}) {
        try {
            const res = await fetch(url, options);
            const text = await res.text();
            let json;
            try {
                json = JSON.parse(text);
            } catch (e) {
                console.error("Non-JSON response:", text.substring(0, 500));
                throw new Error(`server error (${res.status}): response is not json.`);
            }

            if (!res.ok) {
                throw new Error(json.message || `Server Error (${res.status})`);
            }
            return json;
        } catch (e) {
            console.error("Fetch API Error:", e);
            throw e;
        }
    }

    try {
        const res = await fetch('/api/user');
        if (!res.ok) {
            window.location.href = '/auth/login.html';
            return;
        }
        const user = await res.json();
        userDisplay.innerHTML = `Hi, ${user.username} (<a href="/api/logout">logout</a>) `;

        loadingState.style.display = 'none';
        if (user.two_factor_enabled) {
            enabledUI.classList.add('active'); // use active class for display block
        } else {
            disabledUI.classList.add('active'); // use active class for display block
        }
    } catch (e) {
        console.error(e);
        loadingState.textContent = "Error loading 2FA status: " + e.message;
    }

    const stepStart = document.getElementById('step-start');
    const step1 = document.getElementById('step-1');
    const step2 = document.getElementById('step-2');
    const step3 = document.getElementById('step-3');

    function goToStep(stepElement) {
        clearMessage();
        [stepStart, step1, step2, step3].forEach(s => s.classList.remove('active'));
        stepElement.classList.add('active');
    }

    document.getElementById('btn-start-setup').onclick = async () => {
        clearMessage();
        try {
            const data = await fetchApi('/api/user/2fa/setup', { method: 'POST' });
            if (data.success) {
                goToStep(step1);
                document.getElementById('qrcode').innerHTML = `<img src="${data.qrCode}" alt="QR Code">`;
                document.getElementById('secret-text').textContent = data.secret;
            } else {
                showMessage(data.message || "Failed to start setup.");
            }
        } catch (e) {
            showMessage(e.message);
        }
    };

    document.getElementById('btn-next-to-verify').onclick = () => {
        goToStep(step2);
    };

    document.getElementById('verify-2fa-form').onsubmit = async (e) => {
        e.preventDefault();
        clearMessage();
        const code = document.getElementById('verify-code').value;
        const formData = new FormData();
        formData.append('code', code);

        try {
            const data = await fetchApi('/api/user/2fa/enable', {
                method: 'POST',
                body: formData
            });

            if (data.success) {
                showRecoveryCodes(data);
            } else {
                showMessage(data.message || "Verification failed");
            }
        } catch (e) {
            showMessage(e.message);
        }
    };

    function showRecoveryCodes(data) {
        goToStep(step3);
        const list = document.getElementById('recovery-codes-list');
        list.innerHTML = '';
        data.recoveryCodes.forEach(code => {
            const div = document.createElement('div');
            div.className = 'recovery-code-item';
            div.textContent = code;
            list.appendChild(div);
        });

        window.recoveryData = data;
    }

    document.getElementById('btn-download-recovery').onclick = () => {
        const data = window.recoveryData;
        if (!data) return;

        const content = `Keep this file in a secure place.
Each of these codes can be used once to log in if you lose your 2FA device.

${data.recoveryCodes.map(c => `${c}`).join('\n')}

username: ${data.username}
email: ${data.email || 'N/A'}
generated: ${data.date}

`;
        const blob = new Blob([content], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'caffeineid_recovery_codes.txt';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    document.getElementById('btn-finish-setup').onclick = () => {
        window.location.reload();
    };

    const cancelHandler = () => {
        clearMessage();
        goToStep(stepStart);
    };
    document.getElementById('btn-cancel-setup-1').onclick = cancelHandler;
    document.getElementById('btn-cancel-setup-2').onclick = cancelHandler;

    document.getElementById('disable-2fa-form').onsubmit = async (e) => {
        e.preventDefault();
        clearMessage();
        const password = document.getElementById('disable-password').value;
        const formData = new FormData();
        formData.append('password', password);

        try {
            const data = await fetchApi('/api/user/2fa/disable', {
                method: 'POST',
                body: formData
            });

            if (data.success) {
                showMessage("2FA has been disabled.", "success");
                setTimeout(() => window.location.reload(), 1500);
            } else {
                showMessage(data.message || "failed to disable 2FA");
            }
        } catch (e) {
            showMessage(e.message);
        }
    };
}

init2FA();
