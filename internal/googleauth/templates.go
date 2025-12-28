package googleauth

// successTemplate renders after successful OAuth authorization
const successTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connected - gog</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=DM+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-deep: #0a0a0f;
            --bg-card: #111118;
            --bg-input: #18181f;
            --border: #1f1f2e;
            --text: #e8e8ed;
            --text-muted: #8888a0;
            --text-dim: #4a4a5a;
            --google-blue: #4285F4;
            --google-red: #EA4335;
            --google-yellow: #FBBC05;
            --google-green: #34A853;
            --success: #34A853;
            --success-glow: rgba(52, 168, 83, 0.15);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'DM Sans', -apple-system, sans-serif;
            background: var(--bg-deep);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
            position: relative;
            overflow: hidden;
        }

        /* Subtle grid pattern */
        body::before {
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background-image:
                linear-gradient(rgba(66, 133, 244, 0.015) 1px, transparent 1px),
                linear-gradient(90deg, rgba(66, 133, 244, 0.015) 1px, transparent 1px);
            background-size: 80px 80px;
            pointer-events: none;
        }

        /* Animated Google-colored gradient orbs */
        .orb {
            position: fixed;
            border-radius: 50%;
            filter: blur(120px);
            opacity: 0.4;
            pointer-events: none;
            animation: orbDrift 25s ease-in-out infinite;
        }

        .orb-blue {
            width: 600px;
            height: 600px;
            background: var(--google-blue);
            top: -20%;
            left: -10%;
            animation-delay: 0s;
        }

        .orb-red {
            width: 500px;
            height: 500px;
            background: var(--google-red);
            top: 60%;
            right: -15%;
            animation-delay: -6s;
        }

        .orb-yellow {
            width: 400px;
            height: 400px;
            background: var(--google-yellow);
            bottom: -10%;
            left: 30%;
            animation-delay: -12s;
        }

        .orb-green {
            width: 450px;
            height: 450px;
            background: var(--google-green);
            top: 20%;
            right: 20%;
            animation-delay: -18s;
        }

        @keyframes orbDrift {
            0%, 100% { transform: translate(0, 0) scale(1); }
            25% { transform: translate(30px, -20px) scale(1.05); }
            50% { transform: translate(-20px, 30px) scale(0.95); }
            75% { transform: translate(-30px, -10px) scale(1.02); }
        }

        .container {
            width: 100%;
            max-width: 540px;
            position: relative;
            z-index: 1;
            text-align: center;
        }

        /* Google "G" logo with colors */
        .google-logo {
            width: 72px;
            height: 72px;
            margin: 0 auto 2rem;
            animation: logoReveal 0.6s cubic-bezier(0.34, 1.56, 0.64, 1) forwards;
            filter: drop-shadow(0 8px 32px rgba(66, 133, 244, 0.25));
        }

        @keyframes logoReveal {
            from { transform: scale(0) rotate(-180deg); opacity: 0; }
            to { transform: scale(1) rotate(0deg); opacity: 1; }
        }

        /* Success checkmark ring */
        .success-ring {
            position: absolute;
            top: -12px;
            right: -12px;
            width: 32px;
            height: 32px;
            background: var(--success);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            animation: ringPop 0.4s cubic-bezier(0.34, 1.56, 0.64, 1) 0.5s both;
            box-shadow: 0 4px 16px rgba(52, 168, 83, 0.4);
        }

        .success-ring svg {
            width: 18px;
            height: 18px;
            stroke: white;
            stroke-width: 3;
            fill: none;
        }

        @keyframes ringPop {
            from { transform: scale(0); }
            to { transform: scale(1); }
        }

        .logo-container {
            position: relative;
            display: inline-block;
        }

        h1 {
            font-size: 2.25rem;
            font-weight: 700;
            letter-spacing: -0.03em;
            margin-bottom: 0.625rem;
            animation: fadeSlideUp 0.5s ease 0.2s both;
            background: linear-gradient(135deg, var(--text) 0%, var(--text-muted) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .subtitle {
            color: var(--text-muted);
            font-size: 1.0625rem;
            margin-bottom: 2.5rem;
            animation: fadeSlideUp 0.5s ease 0.3s both;
        }

        .subtitle strong {
            color: var(--google-blue);
            font-weight: 600;
        }

        @keyframes fadeSlideUp {
            from { opacity: 0; transform: translateY(16px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Terminal window */
        .terminal {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            overflow: hidden;
            text-align: left;
            animation: fadeSlideUp 0.5s ease 0.4s both;
            box-shadow:
                0 4px 24px rgba(0, 0, 0, 0.3),
                0 0 0 1px rgba(255, 255, 255, 0.02) inset;
        }

        .terminal-bar {
            background: var(--bg-input);
            padding: 0.875rem 1.125rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            border-bottom: 1px solid var(--border);
        }

        .terminal-dots {
            display: flex;
            gap: 6px;
        }

        .terminal-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }

        .terminal-dot.close { background: #ff5f57; }
        .terminal-dot.minimize { background: #febc2e; }
        .terminal-dot.maximize { background: #28c840; }

        .terminal-title {
            flex: 1;
            text-align: center;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.75rem;
            color: var(--text-dim);
            margin-right: 48px;
        }

        .terminal-body {
            padding: 1.5rem;
        }

        .terminal-line {
            display: flex;
            align-items: center;
            gap: 0.625rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.875rem;
            margin-bottom: 0.875rem;
            line-height: 1.5;
        }

        .terminal-line:last-child {
            margin-bottom: 0;
        }

        .terminal-prompt {
            color: var(--google-blue);
            user-select: none;
            font-weight: 500;
        }

        .terminal-cmd {
            color: var(--text);
        }

        .terminal-flag {
            color: var(--google-yellow);
        }

        .terminal-arg {
            color: var(--google-green);
        }

        .terminal-output {
            color: var(--text-dim);
            padding-left: 1.125rem;
            margin-top: -0.5rem;
            margin-bottom: 0.875rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8125rem;
        }

        .terminal-output.success {
            color: var(--success);
        }

        /* Blinking cursor - 1.2s interval as requested */
        .terminal-cursor {
            display: inline-block;
            width: 10px;
            height: 20px;
            background: var(--google-blue);
            animation: cursorBlink 1.2s step-end infinite;
            margin-left: 2px;
            vertical-align: middle;
            border-radius: 1px;
        }

        @keyframes cursorBlink {
            0%, 50% { opacity: 1; }
            50.01%, 100% { opacity: 0; }
        }

        /* Info card */
        .info-card {
            margin-top: 2rem;
            padding: 1.25rem 1.5rem;
            background: rgba(66, 133, 244, 0.06);
            border: 1px solid rgba(66, 133, 244, 0.12);
            border-radius: 12px;
            animation: fadeSlideUp 0.5s ease 0.5s both;
            text-align: left;
            display: flex;
            gap: 1rem;
            align-items: flex-start;
        }

        .info-icon {
            flex-shrink: 0;
            width: 40px;
            height: 40px;
            background: rgba(66, 133, 244, 0.1);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .info-icon svg {
            width: 20px;
            height: 20px;
            stroke: var(--google-blue);
        }

        .info-content h3 {
            font-size: 0.9375rem;
            font-weight: 600;
            color: var(--text);
            margin-bottom: 0.25rem;
        }

        .info-content p {
            font-size: 0.875rem;
            color: var(--text-muted);
            line-height: 1.5;
        }

        .info-content code {
            font-family: 'JetBrains Mono', monospace;
            background: rgba(66, 133, 244, 0.1);
            padding: 0.125rem 0.375rem;
            border-radius: 4px;
            font-size: 0.8125rem;
            color: var(--google-blue);
        }

        .footer {
            text-align: center;
            margin-top: 2rem;
            font-size: 0.8125rem;
            color: var(--text-dim);
            animation: fadeSlideUp 0.5s ease 0.6s both;
        }

        .footer a {
            color: var(--text-muted);
            text-decoration: none;
            transition: color 0.2s;
        }

        .footer a:hover {
            color: #2D52F6;
        }

        .github-link {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }

        .github-link svg {
            opacity: 0.7;
            transition: opacity 0.2s;
        }

        .github-link:hover svg {
            opacity: 1;
        }
    </style>
</head>
<body>
    <div class="orb orb-blue"></div>
    <div class="orb orb-red"></div>
    <div class="orb orb-yellow"></div>
    <div class="orb orb-green"></div>

    <div class="container">
        <div class="logo-container">
            <svg class="google-logo" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
            </svg>
            <div class="success-ring">
                <svg viewBox="0 0 24 24">
                    <polyline points="20 6 9 17 4 12"></polyline>
                </svg>
            </div>
        </div>

        <h1>You're connected</h1>
        <p class="subtitle">gog is now authorized to access <strong>Google Workspace</strong></p>

        <div class="terminal">
            <div class="terminal-bar">
                <div class="terminal-dots">
                    <span class="terminal-dot close"></span>
                    <span class="terminal-dot minimize"></span>
                    <span class="terminal-dot maximize"></span>
                </div>
                <span class="terminal-title">Terminal</span>
            </div>
            <div class="terminal-body">
                <div class="terminal-line">
                    <span class="terminal-prompt">$</span>
                    <span class="terminal-cmd">gog</span>
                    <span class="terminal-arg">calendar</span>
                    <span class="terminal-arg">list</span>
                </div>
                <div class="terminal-output success">Fetching calendars...</div>
                <div class="terminal-line">
                    <span class="terminal-prompt">$</span>
                    <span class="terminal-cmd">gog</span>
                    <span class="terminal-arg">gmail</span>
                    <span class="terminal-arg">search</span>
                    <span class="terminal-flag">--query</span>
                    <span class="terminal-cmd">"is:unread"</span>
                </div>
                <div class="terminal-output success">Found 12 messages</div>
                <div class="terminal-line">
                    <span class="terminal-prompt">$</span>
                    <span class="terminal-cursor"></span>
                </div>
            </div>
        </div>

        <div class="info-card">
            <div class="info-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="4 17 10 11 4 5"></polyline>
                    <line x1="12" y1="19" x2="20" y2="19"></line>
                </svg>
            </div>
            <div class="info-content">
                <h3>Return to your terminal</h3>
                <p>You can close this window. Run <code>gog --help</code> to see available commands.</p>
            </div>
        </div>

        <div class="footer">
            <a href="https://github.com/salmonumbrella/gog-cli" target="_blank" class="github-link">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                </svg>
                View on GitHub
            </a>
        </div>
    </div>
</body>
</html>`

// errorTemplate renders when OAuth authorization fails
const errorTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authorization Failed - gog</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=DM+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-deep: #0a0a0f;
            --bg-card: #111118;
            --bg-input: #18181f;
            --border: #1f1f2e;
            --text: #e8e8ed;
            --text-muted: #8888a0;
            --text-dim: #4a4a5a;
            --google-blue: #4285F4;
            --google-red: #EA4335;
            --error: #EA4335;
            --error-glow: rgba(234, 67, 53, 0.15);
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'DM Sans', -apple-system, sans-serif;
            background: var(--bg-deep);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
            position: relative;
            overflow: hidden;
        }

        body::before {
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background-image:
                linear-gradient(rgba(234, 67, 53, 0.02) 1px, transparent 1px),
                linear-gradient(90deg, rgba(234, 67, 53, 0.02) 1px, transparent 1px);
            background-size: 80px 80px;
            pointer-events: none;
        }

        .orb {
            position: fixed;
            border-radius: 50%;
            filter: blur(120px);
            opacity: 0.35;
            pointer-events: none;
        }

        .orb-red {
            width: 600px;
            height: 600px;
            background: var(--google-red);
            top: -20%;
            right: -10%;
            animation: orbPulse 4s ease-in-out infinite;
        }

        @keyframes orbPulse {
            0%, 100% { opacity: 0.35; transform: scale(1); }
            50% { opacity: 0.5; transform: scale(1.1); }
        }

        .container {
            width: 100%;
            max-width: 480px;
            position: relative;
            z-index: 1;
            text-align: center;
        }

        .error-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 2rem;
            background: var(--error-glow);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            animation: iconShake 0.5s ease 0.2s both;
            box-shadow: 0 8px 32px rgba(234, 67, 53, 0.2);
        }

        .error-icon svg {
            width: 40px;
            height: 40px;
            stroke: var(--error);
            stroke-width: 2;
        }

        @keyframes iconShake {
            0%, 100% { transform: translateX(0); }
            20% { transform: translateX(-8px); }
            40% { transform: translateX(8px); }
            60% { transform: translateX(-4px); }
            80% { transform: translateX(4px); }
        }

        h1 {
            font-size: 2rem;
            font-weight: 700;
            letter-spacing: -0.03em;
            margin-bottom: 0.625rem;
            color: var(--text);
            animation: fadeIn 0.5s ease 0.3s both;
        }

        .subtitle {
            color: var(--text-muted);
            font-size: 1rem;
            margin-bottom: 2rem;
            animation: fadeIn 0.5s ease 0.4s both;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .error-card {
            background: var(--bg-card);
            border: 1px solid rgba(234, 67, 53, 0.2);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: left;
            animation: fadeIn 0.5s ease 0.5s both;
        }

        .error-label {
            font-size: 0.6875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--error);
            margin-bottom: 0.5rem;
        }

        .error-message {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.875rem;
            color: var(--text);
            word-break: break-word;
            line-height: 1.6;
        }

        .help-section {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
            text-align: left;
            animation: fadeIn 0.5s ease 0.6s both;
        }

        .help-title {
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text-dim);
            margin-bottom: 1rem;
        }

        .help-item {
            display: flex;
            align-items: flex-start;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
            font-size: 0.875rem;
            color: var(--text-muted);
        }

        .help-item:last-child {
            margin-bottom: 0;
        }

        .help-num {
            flex-shrink: 0;
            width: 20px;
            height: 20px;
            background: var(--bg-input);
            border-radius: 5px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.6875rem;
            color: var(--text-dim);
        }

        .help-item code {
            font-family: 'JetBrains Mono', monospace;
            background: var(--bg-input);
            padding: 0.125rem 0.375rem;
            border-radius: 4px;
            font-size: 0.8125rem;
            color: var(--google-blue);
        }

        .footer {
            margin-top: 2rem;
            font-size: 0.8125rem;
            color: var(--text-dim);
            animation: fadeIn 0.5s ease 0.7s both;
        }
    </style>
</head>
<body>
    <div class="orb orb-red"></div>

    <div class="container">
        <div class="error-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="15" y1="9" x2="9" y2="15"></line>
                <line x1="9" y1="9" x2="15" y2="15"></line>
            </svg>
        </div>

        <h1>Authorization failed</h1>
        <p class="subtitle">Unable to connect to your Google account</p>

        <div class="error-card">
            <div class="error-label">Error</div>
            <div class="error-message">{{.Error}}</div>
        </div>

        <div class="help-section">
            <div class="help-title">Try again</div>
            <div class="help-item">
                <span class="help-num">1</span>
                <span>Close this window and return to your terminal</span>
            </div>
            <div class="help-item">
                <span class="help-num">2</span>
                <span>Run <code>gog auth add you@gmail.com</code> to restart</span>
            </div>
            <div class="help-item">
                <span class="help-num">3</span>
                <span>If the issue persists, try <code>gog auth add --force-consent</code></span>
            </div>
        </div>

        <p class="footer">You can close this window.</p>
    </div>
</body>
</html>`

// cancelledTemplate renders when user cancels the OAuth flow
const cancelledTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cancelled - gog</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-deep: #0a0a0f;
            --bg-card: #111118;
            --bg-input: #18181f;
            --border: #1f1f2e;
            --text: #e8e8ed;
            --text-muted: #8888a0;
            --text-dim: #4a4a5a;
            --google-blue: #4285F4;
            --google-yellow: #FBBC05;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'DM Sans', -apple-system, sans-serif;
            background: var(--bg-deep);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
            position: relative;
        }

        body::before {
            content: '';
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background-image:
                linear-gradient(rgba(251, 188, 5, 0.015) 1px, transparent 1px),
                linear-gradient(90deg, rgba(251, 188, 5, 0.015) 1px, transparent 1px);
            background-size: 80px 80px;
            pointer-events: none;
        }

        .orb {
            position: fixed;
            width: 500px;
            height: 500px;
            background: var(--google-yellow);
            border-radius: 50%;
            filter: blur(120px);
            opacity: 0.25;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            pointer-events: none;
        }

        .container {
            width: 100%;
            max-width: 420px;
            position: relative;
            z-index: 1;
            text-align: center;
        }

        .icon {
            width: 72px;
            height: 72px;
            margin: 0 auto 2rem;
            background: rgba(251, 188, 5, 0.1);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            animation: fadeIn 0.5s ease both;
        }

        .icon svg {
            width: 32px;
            height: 32px;
            stroke: var(--google-yellow);
            stroke-width: 2;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: scale(0.9); }
            to { opacity: 1; transform: scale(1); }
        }

        h1 {
            font-size: 1.75rem;
            font-weight: 600;
            letter-spacing: -0.02em;
            margin-bottom: 0.5rem;
            animation: fadeSlide 0.5s ease 0.1s both;
        }

        .subtitle {
            color: var(--text-muted);
            font-size: 1rem;
            margin-bottom: 2rem;
            animation: fadeSlide 0.5s ease 0.2s both;
        }

        @keyframes fadeSlide {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .action-hint {
            font-size: 0.875rem;
            color: var(--text-dim);
            animation: fadeSlide 0.5s ease 0.3s both;
        }

        .action-hint code {
            font-family: 'JetBrains Mono', monospace;
            background: var(--bg-input);
            padding: 0.125rem 0.375rem;
            border-radius: 4px;
            font-size: 0.8125rem;
            color: var(--google-blue);
        }
    </style>
</head>
<body>
    <div class="orb"></div>

    <div class="container">
        <div class="icon">
            <svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="8" y1="12" x2="16" y2="12"></line>
            </svg>
        </div>

        <h1>Authorization cancelled</h1>
        <p class="subtitle">No changes were made to your account</p>

        <p class="action-hint">Run <code>gog auth add you@gmail.com</code> when you're ready to try again.</p>
    </div>
</body>
</html>`
