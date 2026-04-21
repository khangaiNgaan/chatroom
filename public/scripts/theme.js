(function() {
    // initialize state and variables
    const button = document.getElementById('darkModeButton');
    const html = document.documentElement;
    const darkModeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const turnstile = document.querySelector('.cf-turnstile');
    
    const modes = ['light', 'dark', 'mono', 'auto'];
    
    // load saved theme mode
    const savedMode = localStorage.getItem('theme-mode') || 'auto';
    
    // 0: light, 1: dark, 2: mono, 3: auto
    let currentModeIndex = modes.indexOf(savedMode);
    if (currentModeIndex === -1) currentModeIndex = 3;

    // define theme application logic
    const applyTheme = (modeName) => {
        let shouldBeDark = false;
        let isMono = false;

        if (modeName === 'auto') {
            shouldBeDark = darkModeMediaQuery.matches;
        } else if (modeName === 'mono') {
            isMono = true;
        } else {
            shouldBeDark = (modeName === 'dark');
        }

        // update html data-theme attribute
        if (shouldBeDark) {
            html.setAttribute('data-theme', 'dark');
            updateTurnstileTheme('dark');
        } else if (isMono) {
            html.setAttribute('data-theme', 'mono');
            updateTurnstileTheme('light');
        } else {
            html.removeAttribute('data-theme');
            updateTurnstileTheme('light');
        }
    };

    // update theme button text
    const updateButtonText = () => {
        if (button) {
            button.innerText = modes[currentModeIndex];
        }
    };

    // initial execution
    updateButtonText();
    applyTheme(modes[currentModeIndex]);

    // handle theme button click
    if (button) {
        button.addEventListener('click', (e) => {
            e.preventDefault();

            // cycle through available modes
            currentModeIndex = (currentModeIndex + 1) % 4;
            const newMode = modes[currentModeIndex];

            localStorage.setItem('theme-mode', newMode);
            
            updateButtonText();
            applyTheme(newMode);
        });
    }

    // listen for system theme changes
    darkModeMediaQuery.addEventListener('change', (e) => {
        const currentSaved = localStorage.getItem('theme-mode') || 'auto';
        if (currentSaved === 'auto') {
            applyTheme('auto');
        }
    });

    // handle turnstile widget theme
    let widgetId = null;
    function updateTurnstileTheme(theme) {
        if (turnstile) {
            turnstile.setAttribute('data-theme', theme);
            if (window.turnstile) {
                if (widgetId) {
                    window.turnstile.remove(widgetId);
                    widgetId = null;
                } else {
                    turnstile.innerHTML = '';
                }
                
                const sitekey = turnstile.getAttribute('data-sitekey');
                if (sitekey) {
                    widgetId = window.turnstile.render(turnstile, {
                        sitekey: sitekey,
                        theme: theme
                    });
                }
            }
        }
    }

    // global utility functions
    window.showErrorTip = function(element, message, duration = 2000) {
        const oldTip = element.parentNode.querySelector('.error-tip');
        if (oldTip) oldTip.remove();

        const tip = document.createElement('div');
        tip.className = 'error-tip';
        tip.innerText = message;
        element.parentNode.appendChild(tip);
        setTimeout(() => { tip.remove(); }, duration);
    };

    window.setupFormValidation = function(form) {
        if (!form) return;
        form.querySelectorAll('input').forEach(input => {
            input.addEventListener('invalid', function(e) {
                e.preventDefault();
                window.showErrorTip(this, this.validationMessage);
            });
        });
    };

})();