// 404 Page Template
export const get404Html = () => `
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - caffeine-Ink</title>
    <meta name="theme-color" content="#d8e3ed" media="(prefers-color-scheme: light)">
    <meta name="theme-color" content="#242931" media="(prefers-color-scheme: dark)">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <link rel="manifest" href="/site.webmanifest">
    <script defer src="/scripts/favicon.js"></script>
    <link rel="stylesheet" href="/css/style.css">
    <link rel="stylesheet" href="/css/main.css">
    <script>
      (function() {
          const savedMode = localStorage.getItem('theme-mode') || 'auto';
          let isDark = false;
          let isMono = false;
          if (savedMode === 'auto') {
              isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
          } else if (savedMode === 'mono') {
              isMono = true;
          } else {
              isDark = (savedMode === 'dark');
          }
          if (isDark) {
              document.documentElement.setAttribute('data-theme', 'dark');
          } else if (isMono) {
              document.documentElement.setAttribute('data-theme', 'mono');
          }
      })();
    </script>
	<script defer src="https://cloud.umami.is/script.js" data-website-id="cf3f6b51-a212-4d89-bad2-8d83e259075d"></script>
  </head>
  <body>
    <div class="box">
        <div class="content">
          <div class="header">  
          <span class="title">caffeine-Ink</span>
          <span class="date"></span>
          </div>
          <br>
          <p>Error 404: Not Found</p>
          <br>
        </div>
        <div class="back"><a href="/">&lt; back to home</a></div>
        <footer>
          <br>
          <div class="copyright"></div>
        </footer>
    </div>
    <script src="/scripts/theme.js"></script>
  </body>
</html>`

// Email Verified Success Page
export const getEmailVerifiedHtml = (email: string) => `
<!DOCTYPE html>
<html>
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="5;url=/user/settings.html" />
    <title>email verified - coffeeroom</title>
    <meta name="theme-color" content="#d8e3ed" media="(prefers-color-scheme: light)">
    <meta name="theme-color" content="#242931" media="(prefers-color-scheme: dark)">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <link rel="manifest" href="/site.webmanifest">
    <style>
        @font-face {
            font-family: unifont;
            src: url(../fonts/unifont.otf);
        }
        @font-face {
            font-family: sentient;
            font-weight: bold;
            src: url(../fonts/Sentient-Bold.otf);
        }

        :root {
            --bg-color: #d8e3ed;
            --chat-bg-color: #eff3f7;
            --popup-bg-color: rgba(255, 255, 255, 0.5);
            --border-color: #808ea1;
            --note-color: #69727d;
            --text-color: #444f5d;
            --highlight-color: #b7c2d0;
            --pre-code-color: #ced9e3;
            --button-color: #f4f7f9;
            --button-hover-color: #ecf1f4;
            --button-active-color: #dee4e8;
            --msg-bg-color: #e1eaf1;
            --connection-green: #347b68;
            --connection-red: #c05858;
            --success-color: #347b68;
            --error-color: #c05858;
            --my-nom-color: #5d8dc7;
            --admin-nom-color: #d79a40;
            --nom-color: #d868a3;
        }
        [data-theme="dark"] {
            --bg-color: #242931;
            --chat-bg-color: #2e3640;
            --popup-bg-color: rgba(46, 54, 64, 0.5);
            --border-color: #555c68;
            --note-color: #888e9d;
            --text-color: #e9f0f5;
            --highlight-color: #444f5d;
            --pre-code-color: #2e3640;
            --button-color: #2e3640;
            --button-hover-color: #444f5d;
            --button-active-color: #39424e;
            --msg-bg-color: #444f5d;
            --connection-green: #A7D3A6;
            --connection-red: #D67A85;
            --success-color: #A7D3A6;
            --error-color: #D67A85;
            --my-nom-color: #A7C6EC;
            --admin-nom-color: #F9E1BD; /* #C5E4C0 */
            --nom-color: #E8A5C8;
        }
        [data-theme="mono"] {
            --bg-color: #ffffff;
            --chat-bg-color: #ffffff;
            --popup-bg-color: #ffffff;
            --border-color: #777777;
            --note-color: #777777;
            --text-color: #000000;
            --highlight-color: #cccccc;
            --pre-code-color: #dddddd;
            --button-color: #ffffff;
            --button-hover-color: #ffffff;
            --button-active-color: #eeeeee;
            --msg-bg-color: #ffffff;
            --connection-green: #000000;
            --connection-red: #000000;
            --success-color: #000000;
            --error-color: #000000;
            --my-nom-color: #000000;
            --admin-nom-color: #000000;
            --nom-color: #000000;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-color);
            max-width: 800px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
            box-sizing: border-box;
        }

        html {
            background-color: var(--bg-color);
        }

        @media (max-width: 800px) {
            body {
                padding: 30px 15px 60px 15px;
                margin: 0;
            }
        }

        a {
            color: var(--text-color);
            cursor: pointer;
            font-family: 'unifont', sans-serif;
        }

        a:hover {
            background-color: var(--text-color);
            color: var(--bg-color);
        }

        ::selection {
            background-color: var(--text-color);
            color: var(--bg-color);
        }
    </style>
    <script>
        (function() {
            const savedMode = localStorage.getItem('theme-mode') || 'auto';
            let isDark = false;
            let isMono = false;
            if (savedMode === 'auto') {
                isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            } else if (savedMode === 'mono') {
                isMono = true;
            } else {
                isDark = (savedMode === 'dark');
            }
            if (isDark) {
                document.documentElement.setAttribute('data-theme', 'dark');
            } else if (isMono) {
                document.documentElement.setAttribute('data-theme', 'mono');
            }
        })();
    </script>
    </head>
    <body>
        <div style="height: 100vh; width: 100%; max-width: 500px; margin: 0 auto; display: flex; align-items: center; justify-content: center; box-sizing: border-box;">
            <div style="border: 1px solid var(--border-color); background-color: var(--chat-bg-color); border-radius: 5px; padding: 20px; width: 100%; box-sizing: border-box; text-align: center;">
                <div style="color: var(--success-color); font-size: 16px; margin-bottom: 10px; font-family: 'unifont', sans-serif;">Email Verified</div>
                <div style="font-size: 14px; margin-bottom: 20px; font-family: 'unifont', sans-serif;">Your email <strong>${email}</strong> has been bound to your account.</div>
                <div style="font-size: 12px; color: var(--note-color); font-family: 'unifont', sans-serif;">Redirecting to settings in 5 seconds...</div>
                <br>
                <div style="font-size: 14px;"><a href="/user/settings.html">Click here if not redirected</a></div>
            </div>
        </div>
    <script src="/scripts/theme.js"></script>
    </body>
</html>`

// Registration Success Page
export const getRegistrationSuccessHtml = (username: string) => `
<!DOCTYPE html>
<html>
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="5;url=/auth/login.html" />
    <title>email verified - coffeeroom</title>
    <meta name="theme-color" content="#d8e3ed" media="(prefers-color-scheme: light)">
    <meta name="theme-color" content="#242931" media="(prefers-color-scheme: dark)">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <link rel="manifest" href="/site.webmanifest">
    <style>
        @font-face {
            font-family: unifont;
            src: url(../fonts/unifont.otf);
        }
        @font-face {
            font-family: sentient;
            font-weight: bold;
            src: url(../fonts/Sentient-Bold.otf);
        }

        :root {
            --bg-color: #d8e3ed;
            --chat-bg-color: #eff3f7;
            --popup-bg-color: rgba(255, 255, 255, 0.5);
            --border-color: #808ea1;
            --note-color: #69727d;
            --text-color: #444f5d;
            --highlight-color: #b7c2d0;
            --pre-code-color: #ced9e3;
            --button-color: #f4f7f9;
            --button-hover-color: #ecf1f4;
            --button-active-color: #dee4e8;
            --msg-bg-color: #e1eaf1;
            --connection-green: #347b68;
            --connection-red: #c05858;
            --success-color: #347b68;
            --error-color: #c05858;
            --my-nom-color: #5d8dc7;
            --admin-nom-color: #d79a40;
            --nom-color: #d868a3;
        }
        [data-theme="dark"] {
            --bg-color: #242931;
            --chat-bg-color: #2e3640;
            --popup-bg-color: rgba(46, 54, 64, 0.5);
            --border-color: #555c68;
            --note-color: #888e9d;
            --text-color: #e9f0f5;
            --highlight-color: #444f5d;
            --pre-code-color: #2e3640;
            --button-color: #2e3640;
            --button-hover-color: #444f5d;
            --button-active-color: #39424e;
            --msg-bg-color: #444f5d;
            --connection-green: #A7D3A6;
            --connection-red: #D67A85;
            --success-color: #A7D3A6;
            --error-color: #D67A85;
            --my-nom-color: #A7C6EC;
            --admin-nom-color: #F9E1BD; /* #C5E4C0 */
            --nom-color: #E8A5C8;
        }
        [data-theme="mono"] {
            --bg-color: #ffffff;
            --chat-bg-color: #ffffff;
            --popup-bg-color: #ffffff;
            --border-color: #777777;
            --note-color: #777777;
            --text-color: #000000;
            --highlight-color: #cccccc;
            --pre-code-color: #dddddd;
            --button-color: #ffffff;
            --button-hover-color: #ffffff;
            --button-active-color: #eeeeee;
            --msg-bg-color: #ffffff;
            --connection-green: #000000;
            --connection-red: #000000;
            --success-color: #000000;
            --error-color: #000000;
            --my-nom-color: #000000;
            --admin-nom-color: #000000;
            --nom-color: #000000;
        }

        body {
            background-color: var(--bg-color);
            color: var(--text-color);
            max-width: 800px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
            box-sizing: border-box;
        }

        html {
            background-color: var(--bg-color);
        }

        @media (max-width: 800px) {
            body {
                padding: 30px 15px 60px 15px;
                margin: 0;
            }
        }

        a {
            color: var(--text-color);
            cursor: pointer;
            font-family: 'unifont', sans-serif;
        }

        a:hover {
            background-color: var(--text-color);
            color: var(--bg-color);
        }

        ::selection {
            background-color: var(--text-color);
            color: var(--bg-color);
        }
    </style>
    <script>
        (function() {
            const savedMode = localStorage.getItem('theme-mode') || 'auto';
            let isDark = false;
            let isMono = false;
            if (savedMode === 'auto') {
                isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            } else if (savedMode === 'mono') {
                isMono = true;
            } else {
                isDark = (savedMode === 'dark');
            }
            if (isDark) {
                document.documentElement.setAttribute('data-theme', 'dark');
            } else if (isMono) {
                document.documentElement.setAttribute('data-theme', 'mono');
            }
        })();
    </script>
    </head>
    <body>
        <div style="height: 100vh; width: 100%; max-width: 500px; margin: 0 auto; display: flex; align-items: center; justify-content: center; box-sizing: border-box;">
            <div style="border: 1px solid var(--border-color); background-color: var(--chat-bg-color); border-radius: 5px; padding: 20px; width: 100%; box-sizing: border-box; text-align: center;">
                <div style="color: var(--success-color); font-size: 16px; margin-bottom: 10px; font-family: 'unifont', sans-serif;">Registration Successful</div>
                <div style="font-size: 14px; margin-bottom: 20px; font-family: 'unifont', sans-serif;">Your account <strong>${username}</strong> has been created.</div>
                <div style="font-size: 12px; color: var(--note-color); font-family: 'unifont', sans-serif;">Redirecting to login in 5 seconds...</div>
                <br>
                <div style="font-size: 14px;"><a href="/auth/login.html">Click here if not redirected</a></div>
            </div>
        </div>
    <script src="/scripts/theme.js"></script>
    </body>
</html>`

// Reset Password Expired Page
export const getResetExpiredHtml = () => `
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>error - coffeeroom</title>
        <link rel="stylesheet" href="/css/auth.css">
        <script>
            (function() {
                const savedMode = localStorage.getItem('theme-mode') || 'auto';
                let isDark = false;
                let isMono = false;
                if (savedMode === 'auto') {
                    isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                } else if (savedMode === 'mono') {
                    isMono = true;
                } else {
                    isDark = (savedMode === 'dark');
                }
                if (isDark) {
                    document.documentElement.setAttribute('data-theme', 'dark');
                } else if (isMono) {
                    document.documentElement.setAttribute('data-theme', 'mono');
                }
            })();
        </script>
    </head>
    <body>
        <div class="box">
            <div class="content">
                <div class="title-auth">Link Expired</div>
                <div class="container">
                    <div class="authbox">
                        <span class="text">This reset link is invalid or has expired.</span><br>
                        <span class="text"><a href="/auth/forgot.html">Request a new one</a>.</span>
                    </div>
                </div>
            </div>
        </div>
    </body>
</html>`

// Reset Password Form Page
export const getResetPasswordFormHtml = (token: string, is2FAEnabled: boolean) => `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>reset password - coffeeroom</title>
    <link rel="stylesheet" href="/css/auth.css">
    <script src="/scripts/theme.js"></script>
    <script>const is2FAEnabled = ${is2FAEnabled};</script>
</head>
<body>
    <div class="box">
        <div class="content">
        <div class="header"><span class="title">caffeineId</span></div>
        <br>
        <div class="title-auth">Reset Password</div>
        <div class="container">
            <div class="authbox">
                <span class="text">Enter your new password below.</span>
            </div>
            <div class="authbox">
                <div id="auth-message" class="auth-message"></div>
                <br>
                <form id="reset-password-form">
                    <input type="hidden" name="token" value="${token}">
                    <div class="input-group"><input type="password" name="password" placeholder="new password" required /></div>
                    <div class="input-group"><input type="password" name="confirm-password" placeholder="confirm new password" required /></div>
                    
                    <div class="input-group" id="2fa-group" style="display: none;">
                        <input type="text" name="code" placeholder="2FA / recovery code" autocomplete="off" />
                    </div>

                    <button type="submit">reset password</button>
                </form>
                <br>
            </div>
        </div>
        </div>
    </div>
    <script>
        if (is2FAEnabled) {
            const group = document.getElementById('2fa-group');
            group.style.display = 'block';
            group.querySelector('input').required = true;
        }

        const form = document.getElementById('reset-password-form');
        const msgBox = document.getElementById('auth-message');

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

            const formData = new FormData(form);
            try {
                const res = await fetch('/api/auth/reset-password', {
                    method: 'POST',
                    body: formData
                });
                
                const text = await res.text();
                
                if (res.ok) {
                    // If success, backend returns a success HTML page
                    document.open();
                    document.write(text);
                    document.close();
                } else {
                    msgBox.innerText = text || "Error resetting password";
                    msgBox.className = "auth-message error";
                    msgBox.style.display = 'block';
                }
            } catch (err) {
                msgBox.innerText = "Network error";
                msgBox.className = "auth-message error";
                msgBox.style.display = 'block';
            }
        });
    </script>
</body>
</html>`

// Reset Password Success Page
export const getResetSuccessHtml = () => `
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8">
        <meta http-equiv="refresh" content="5;url=/auth/login.html" />
        <title>success</title>
        <link rel="stylesheet" href="/css/auth.css">
        <script>
            (function() {
                const savedMode = localStorage.getItem('theme-mode') || 'auto';
                let isDark = false;
                let isMono = false;
                if (savedMode === 'auto') {
                    isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
                } else if (savedMode === 'mono') {
                    isMono = true;
                } else {
                    isDark = (savedMode === 'dark');
                }
                if (isDark) {
                    document.documentElement.setAttribute('data-theme', 'dark');
                } else if (isMono) {
                    document.documentElement.setAttribute('data-theme', 'mono');
                }
            })();
        </script>
        <script src="/scripts/theme.js"></script>
    </head>
    <body>
        <div class="box">
            <div class="content">
                <div class="title-auth">Success</div>
                <div class="container">
                    <div class="authbox">
                        <span class="text">Password reset successfully! Redirecting to login...</span><br>
                        <span class="text">If you are not redirected, please click <a href="/auth/login.html">here</a>.</span>
                    </div>
                </div>
            </div>
        </div>
    </body>
</html>`
