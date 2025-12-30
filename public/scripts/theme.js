(function() {
    // 1. 变量与状态初始化
    const button = document.getElementById('darkModeButton');
    const html = document.documentElement; // 获取 <html> 根标签
    const darkModeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const turnstile = document.querySelector('.cf-turnstile');
    
    const modes = ['light', 'dark', 'mono', 'auto'];
    
    // 是否保存过用户选择的模式
    const savedMode = localStorage.getItem('theme-mode') || 'auto';
    
    // 0: light, 1: dark, 2: mono, 3: auto
    let currentModeIndex = modes.indexOf(savedMode);
    // auto 兜底
    if (currentModeIndex === -1) currentModeIndex = 3;

    // 2. 功能函数定义

    const applyTheme = (modeName) => {
        let shouldBeDark = false;
        let isMono = false;

        // 判断逻辑
        if (modeName === 'auto') {
            shouldBeDark = darkModeMediaQuery.matches;
        } else if (modeName === 'mono') {
            isMono = true;
        } else {
            shouldBeDark = (modeName === 'dark');
        }

        // 核心动作：切换 HTML 属性
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

    // 更新按钮显示的文字
    const updateButtonText = () => {
        if (button) {
            button.innerText = modes[currentModeIndex];
        }
    };

    // 3. 事件监听与执行

    // 初始化运行：设置按钮文字
    updateButtonText();
    applyTheme(modes[currentModeIndex]);

    // 按钮点击事件
    if (button) {
        button.addEventListener('click', (e) => {
            e.preventDefault();

            // 循环切换索引: 0 -> 1 -> 2 -> 3 -> 0
            currentModeIndex = (currentModeIndex + 1) % 4;
            const newMode = modes[currentModeIndex];

            // 存入本地存储
            localStorage.setItem('theme-mode', newMode);
            
            // 更新界面
            updateButtonText();
            applyTheme(newMode);
        });
    }

    // 系统深色模式变化监听
    // 系统设置改变时，如果处于 auto 模式，则更新主题
    darkModeMediaQuery.addEventListener('change', (e) => {
        const currentSaved = localStorage.getItem('theme-mode') || 'auto';
        if (currentSaved === 'auto') {
            applyTheme('auto');
        }
    });

    // 辅助函数：Turnstile 主题切换
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

})();