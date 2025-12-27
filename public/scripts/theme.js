(function() {
    // 1. 变量与状态初始化
    const button = document.getElementById('darkModeButton');
    const html = document.documentElement; // 获取 <html> 根标签
    const darkModeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    
    // 定义三种模式
    const modes = ['light', 'dark', 'mono', 'auto'];
    
    // 获取当前存储的模式，如果没有则默认为 auto
    const savedMode = localStorage.getItem('theme-mode') || 'auto';

    // 计算当前的索引 (0: light, 1: dark, 2: mono, 3: auto)
    let currentModeIndex = modes.indexOf(savedMode);
    // 防止存储被篡改导致找不到索引，兜底为 auto
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
        } else if (isMono) {
            html.setAttribute('data-theme', 'mono');
        } else {
            html.removeAttribute('data-theme');
        }
    };

    /* 更新按钮显示的文字 */
    const updateButtonText = () => {
        if (button) {
            button.innerText = modes[currentModeIndex];
        }
    };

    // 3. 事件监听与执行

    // 初始化运行：设置按钮文字
    updateButtonText();

    // 按钮点击事件
    if (button) {
        button.addEventListener('click', (e) => {
            e.preventDefault();

            // 循环切换索引: 0 -> 1 -> 2 -> 3 -> 0
            currentModeIndex = (currentModeIndex + 1) % 4;
            const newMode = modes[currentModeIndex];

            // 1. 存入本地存储
            localStorage.setItem('theme-mode', newMode);
            
            // 2. 更新界面
            updateButtonText();
            applyTheme(newMode);
        });
    }

    // 系统深色模式变化监听
    // 当系统设置改变时，如果当前处于 auto 模式，页面要跟着变
    darkModeMediaQuery.addEventListener('change', (e) => {
        const currentSaved = localStorage.getItem('theme-mode') || 'auto';
        if (currentSaved === 'auto') {
            applyTheme('auto');
        }
    });
})();