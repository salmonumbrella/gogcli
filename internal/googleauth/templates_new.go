package googleauth

// accountsTemplate renders the accounts management page
const accountsTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Accounts - gog</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-void: #050508;
            --bg-base: #0a0a0f;
            --bg-surface: #111116;
            --bg-elevated: #18181d;
            --bg-hover: #1f1f26;
            --border: rgba(255, 255, 255, 0.06);
            --border-subtle: rgba(255, 255, 255, 0.04);
            --border-active: rgba(255, 255, 255, 0.12);
            --text: #f4f4f5;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --text-dim: #52525b;

            /* Google colors - refined */
            --g-blue: #4285F4;
            --g-blue-dim: rgba(66, 133, 244, 0.12);
            --g-red: #EA4335;
            --g-red-dim: rgba(234, 67, 53, 0.12);
            --g-yellow: #FBBC05;
            --g-yellow-dim: rgba(251, 188, 5, 0.12);
            --g-green: #34A853;
            --g-green-dim: rgba(52, 168, 83, 0.12);

            --radius-sm: 8px;
            --radius: 12px;
            --radius-lg: 16px;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        .hidden { display: none !important; }

        body {
            font-family: 'Sora', -apple-system, sans-serif;
            background: var(--bg-void);
            color: var(--text);
            min-height: 100vh;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
            opacity: 0;
            animation: pageReveal 0.5s ease-out forwards;
        }

        @keyframes pageReveal {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        /* Ambient background */
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background:
                radial-gradient(ellipse 100% 80% at 50% -30%, var(--g-blue-dim), transparent 70%),
                radial-gradient(ellipse 60% 50% at 80% 20%, var(--g-red-dim), transparent 60%),
                radial-gradient(ellipse 50% 40% at 20% 60%, var(--g-green-dim), transparent 50%);
            pointer-events: none;
            z-index: 0;
        }

        /* Subtle grid */
        body::after {
            content: '';
            position: fixed;
            inset: 0;
            background-image:
                linear-gradient(rgba(255, 255, 255, 0.015) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.015) 1px, transparent 1px);
            background-size: 64px 64px;
            pointer-events: none;
            z-index: 0;
        }

        .container {
            max-width: 560px;
            margin: 0 auto;
            padding: 48px 24px;
            position: relative;
            z-index: 1;
        }

        /* Header */
        header {
            text-align: center;
            margin-bottom: 40px;
        }

        .logo-mark {
            display: flex;
            justify-content: center;
            margin-bottom: 20px;
        }

        .logo-svg {
            width: 48px;
            height: 48px;
            filter: drop-shadow(0 4px 24px rgba(66, 133, 244, 0.3));
        }

        .brand {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            margin-bottom: 6px;
        }

        .brand-name {
            font-size: 13px;
            font-weight: 600;
            letter-spacing: 0.15em;
            text-transform: uppercase;
            color: var(--text-muted);
        }

        .brand-version {
            font-size: 10px;
            font-weight: 500;
            color: var(--text-dim);
            background: var(--bg-elevated);
            padding: 2px 8px;
            border-radius: 99px;
            border: 1px solid var(--border);
        }

        h1 {
            font-size: 26px;
            font-weight: 700;
            letter-spacing: -0.03em;
            margin-bottom: 4px;
        }

        .subtitle {
            color: var(--text-muted);
            font-size: 14px;
        }

        /* Accounts Section */
        .accounts-section {
            margin-bottom: 24px;
        }

        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
            padding: 0 4px;
        }

        .section-label {
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            color: var(--text-dim);
        }

        .account-badge {
            font-size: 11px;
            font-weight: 500;
            color: var(--text-dim);
            background: var(--bg-surface);
            padding: 4px 10px;
            border-radius: 99px;
            border: 1px solid var(--border);
        }

        /* Account Cards */
        .accounts-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }

        .account-card {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 16px;
            display: flex;
            align-items: center;
            gap: 14px;
            transition: all 0.2s ease;
            position: relative;
        }

        .account-card:hover {
            background: var(--bg-elevated);
            border-color: var(--border-active);
        }

        .account-card.default {
            border-color: rgba(66, 133, 244, 0.3);
            background: linear-gradient(135deg, var(--bg-surface), rgba(66, 133, 244, 0.04));
        }

        .account-avatar {
            width: 44px;
            height: 44px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 16px;
            color: white;
            flex-shrink: 0;
            text-shadow: 0 1px 2px rgba(0,0,0,0.2);
        }

        .account-details {
            flex: 1;
            min-width: 0;
        }

        .account-email {
            font-size: 14px;
            font-weight: 600;
            color: var(--text);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            margin-bottom: 6px;
        }

        .account-services {
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
        }

        .service-tag {
            font-size: 10px;
            font-weight: 500;
            letter-spacing: 0.02em;
            padding: 3px 8px 3px 22px;
            border-radius: 99px;
            border: 1px solid;
            background-repeat: no-repeat;
            background-position: 5px center;
            background-size: 12px 12px;
        }

        .service-tag.calendar {
            color: var(--g-blue);
            background-color: var(--g-blue-dim);
            border-color: rgba(66, 133, 244, 0.2);
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 24 24' fill='%234285F4' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M18.316 5.684H24v12.632h-5.684V5.684zM5.684 24h12.632v-5.684H5.684V24zM18.316 5.684V0H1.895A1.894 1.894 0 0 0 0 1.895v16.421h5.684V5.684h12.632zM22.105 0h-3.289v5.184H24V1.895A1.894 1.894 0 0 0 22.105 0zM0 22.105C0 23.152.848 24 1.895 24h3.289v-5.184H0v3.289z'/%3E%3C/svg%3E");
        }

        .service-tag.gmail {
            color: var(--g-red);
            background-color: var(--g-red-dim);
            border-color: rgba(234, 67, 53, 0.2);
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 24 24' fill='%23EA4335' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M24 5.457v13.909c0 .904-.732 1.636-1.636 1.636h-3.819V11.73L12 16.64l-6.545-4.91v9.273H1.636A1.636 1.636 0 0 1 0 19.366V5.457c0-2.023 2.309-3.178 3.927-1.964L5.455 4.64 12 9.548l6.545-4.91 1.528-1.145C21.69 2.28 24 3.434 24 5.457z'/%3E%3C/svg%3E");
        }

        .service-tag.drive {
            color: var(--g-yellow);
            background-color: var(--g-yellow-dim);
            border-color: rgba(251, 188, 5, 0.2);
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 24 24' fill='%23FBBC05' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M12.01 1.485c-2.082 0-3.754.02-3.743.047.01.02 1.708 3.001 3.774 6.62l3.76 6.574h3.76c2.081 0 3.753-.02 3.742-.047-.005-.02-1.708-3.001-3.775-6.62l-3.76-6.574zm-4.76 1.73a789.828 789.861 0 0 0-3.63 6.319L0 15.868l1.89 3.298 1.885 3.297 3.62-6.335 3.618-6.33-1.88-3.287C8.1 4.704 7.255 3.22 7.25 3.214zm2.259 12.653-.203.348c-.114.198-.96 1.672-1.88 3.287a423.93 423.948 0 0 1-1.698 2.97c-.01.026 3.24.042 7.222.042h7.244l1.796-3.157c.992-1.734 1.85-3.23 1.906-3.323l.104-.167h-7.249z'/%3E%3C/svg%3E");
        }

        .service-tag.contacts {
            color: var(--g-blue);
            background-color: var(--g-blue-dim);
            border-color: rgba(66, 133, 244, 0.2);
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 24 24' fill='%234285F4' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M20 0H4v2h16V0zM4 24h16v-2H4v2zM20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm-8 2.75c1.24 0 2.25 1.01 2.25 2.25s-1.01 2.25-2.25 2.25S9.75 10.24 9.75 9 10.76 6.75 12 6.75zM17 17H7v-1.5c0-1.67 3.33-2.5 5-2.5s5 .83 5 2.5V17z'/%3E%3C/svg%3E");
        }

        .service-tag.sheets {
            color: var(--g-green);
            background-color: var(--g-green-dim);
            border-color: rgba(52, 168, 83, 0.2);
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 24 24' fill='%2334A853' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M11.318 12.545H7.91v-1.909h3.41v1.91zM14.728 0v6h6l-6-6zm1.363 10.636h-3.41v1.91h3.41v-1.91zm0 3.273h-3.41v1.91h3.41v-1.91zM20.727 6.5v15.864c0 .904-.732 1.636-1.636 1.636H4.909a1.636 1.636 0 0 1-1.636-1.636V1.636C3.273.732 4.005 0 4.909 0h9.318v6.5h6.5zm-3.273 2.773H6.545v7.909h10.91v-7.91zm-6.136 4.636H7.91v1.91h3.41v-1.91z'/%3E%3C/svg%3E");
        }

        .account-actions {
            display: flex;
            align-items: center;
            gap: 8px;
            flex-shrink: 0;
        }

        .default-badge {
            display: inline-flex;
            align-items: center;
            gap: 4px;
            font-size: 10px;
            font-weight: 600;
            color: var(--g-blue);
            background: var(--g-blue-dim);
            padding: 5px 10px;
            border-radius: 99px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .default-badge svg {
            width: 10px;
            height: 10px;
        }

        .set-default-btn {
            font-size: 11px;
            font-weight: 500;
            color: var(--text-dim);
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            padding: 5px 10px;
            border-radius: 99px;
            cursor: pointer;
            transition: all 0.2s ease;
            opacity: 0;
            font-family: inherit;
        }

        .account-card:hover .set-default-btn {
            opacity: 1;
        }

        .set-default-btn:hover {
            background: var(--bg-hover);
            color: var(--text-secondary);
            border-color: var(--border-active);
        }

        .remove-btn {
            width: 28px;
            height: 28px;
            background: transparent;
            border: none;
            border-radius: var(--radius-sm);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            color: var(--text-dim);
            transition: all 0.2s ease;
            opacity: 0;
        }

        .account-card:hover .remove-btn {
            opacity: 1;
        }

        .remove-btn:hover {
            background: var(--g-red-dim);
            color: var(--g-red);
        }

        .remove-btn svg {
            width: 16px;
            height: 16px;
        }

        /* Add Account Button */
        .add-account-btn {
            width: 100%;
            margin-top: 12px;
            background: transparent;
            border: 1px solid var(--border-active);
            border-radius: var(--radius);
            padding: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            color: var(--text-muted);
            font-size: 14px;
            font-weight: 500;
            font-family: inherit;
            cursor: pointer;
            transition: all 0.2s ease;
        }

        .add-account-btn:hover {
            border-color: var(--g-blue);
            color: var(--g-blue);
            background: var(--g-blue-dim);
        }

        .add-account-btn svg {
            width: 18px;
            height: 18px;
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 48px 24px;
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
        }

        .empty-icon {
            width: 64px;
            height: 64px;
            margin: 0 auto 20px;
            background: var(--g-blue-dim);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .empty-icon svg {
            width: 32px;
            height: 32px;
            color: var(--g-blue);
        }

        .empty-state h3 {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 6px;
        }

        .empty-state p {
            font-size: 14px;
            color: var(--text-secondary);
            margin-bottom: 24px;
        }

        .connect-btn {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 14px 28px;
            background: var(--g-blue);
            color: white;
            border: none;
            border-radius: var(--radius);
            font-family: inherit;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 4px 16px rgba(66, 133, 244, 0.3);
        }

        .connect-btn:hover {
            background: #5a9cff;
            transform: translateY(-1px);
            box-shadow: 0 6px 24px rgba(66, 133, 244, 0.4);
        }

        .connect-btn svg {
            width: 20px;
            height: 20px;
        }

        /* Info Card */
        .info-card {
            margin-top: 32px;
            padding: 16px 20px;
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            display: flex;
            gap: 14px;
            align-items: flex-start;
        }

        .info-icon {
            flex-shrink: 0;
            width: 36px;
            height: 36px;
            background: var(--bg-elevated);
            border-radius: var(--radius-sm);
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .info-icon svg {
            width: 18px;
            height: 18px;
            color: var(--text-muted);
        }

        .info-content h4 {
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 2px;
        }

        .info-content p {
            font-size: 13px;
            color: var(--text-muted);
            line-height: 1.5;
        }

        .info-content code {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            background: var(--bg-elevated);
            padding: 2px 6px;
            border-radius: 4px;
            color: var(--g-blue);
        }

        /* Footer */
        .footer {
            text-align: center;
            margin-top: 2rem;
            font-size: 0.8125rem;
            color: var(--text-dim);
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

        .setup-link {
            margin-top: 12px;
            font-size: 12px;
        }

        .setup-link a {
            color: var(--g-blue);
            text-decoration: none;
        }

        .setup-link a:hover {
            opacity: 0.8;
        }

        /* Loading state */
        .spinner {
            width: 16px;
            height: 16px;
            border: 2px solid transparent;
            border-top-color: currentColor;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        @media (max-width: 480px) {
            .container {
                padding: 32px 16px;
            }

            .account-card {
                padding: 14px;
            }

            .account-actions {
                flex-direction: column;
                gap: 6px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="logo-mark">
                <svg class="logo-svg" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                </svg>
            </div>
            <h1>Google Accounts</h1>
            <p class="subtitle">Manage your connected accounts</p>
            <p class="setup-link">
                <a href="https://github.com/salmonumbrella/gog-cli?tab=readme-ov-file#setup-oauth" target="_blank">
                    First time? Set up Google Cloud credentials →
                </a>
            </p>
        </header>

        <!-- Accounts Section -->
        <div id="accountsSection" class="accounts-section hidden">
            <div class="section-header">
                <span class="section-label">Connected</span>
                <span id="accountBadge" class="account-badge">0 accounts</span>
            </div>
            <div id="accountsList" class="accounts-list"></div>
            <button id="addAccountBtn" class="add-account-btn" onclick="addAccount()">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round">
                    <line x1="12" y1="5" x2="12" y2="19"/>
                    <line x1="5" y1="12" x2="19" y2="12"/>
                </svg>
                Add Another Account
            </button>
        </div>

        <!-- Empty State -->
        <div id="emptyState" class="empty-state">
            <div class="empty-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/>
                    <circle cx="12" cy="7" r="4"/>
                </svg>
            </div>
            <h3>No accounts connected</h3>
            <p>Connect your Google account to get started with gog</p>
            <button class="connect-btn" onclick="addAccount()">
                <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="white"/>
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="white" fill-opacity="0.9"/>
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="white" fill-opacity="0.8"/>
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="white" fill-opacity="0.9"/>
                </svg>
                Connect with Google
            </button>
        </div>

        <!-- Info Card -->
        <div class="info-card">
            <div class="info-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="4 17 10 11 4 5"></polyline>
                    <line x1="12" y1="19" x2="20" y2="19"></line>
                </svg>
            </div>
            <div class="info-content">
                <h4>Use from terminal</h4>
                <p>Run <code>gog calendar list</code> or <code>gog gmail search</code> to interact with your Google services.</p>
            </div>
        </div>

        <footer class="footer">
            <a href="https://github.com/salmonumbrella/gog-cli" target="_blank" class="github-link">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                </svg>
                View on GitHub
            </a>
        </footer>
    </div>

    <script>
        const csrfToken = '{{.CSRFToken}}';
        let accounts = [];

        // Generate a gradient based on email first letter
        function getAvatarGradient(email) {
            const char = email.charAt(0).toLowerCase();
            const code = char.charCodeAt(0) - 97; // a=0, z=25
            const hue1 = (code * 14) % 360; // Spread across hue wheel
            const hue2 = (hue1 + 40) % 360;
            return ` + "`" + `linear-gradient(135deg, hsl(${hue1}, 70%, 55%), hsl(${hue2}, 80%, 45%))` + "`" + `;
        }

        // Load accounts on page load
        async function loadAccounts() {
            try {
                const response = await fetch('/accounts');
                const data = await response.json();
                accounts = data.accounts || [];
                renderAccounts();
            } catch (err) {
                console.error('Failed to load accounts:', err);
                accounts = [];
                renderAccounts();
            }
        }

        function renderAccounts() {
            const accountsSection = document.getElementById('accountsSection');
            const emptyState = document.getElementById('emptyState');
            const accountsList = document.getElementById('accountsList');
            const accountBadge = document.getElementById('accountBadge');

            if (accounts.length === 0) {
                accountsSection.classList.add('hidden');
                emptyState.classList.remove('hidden');
            } else {
                accountsSection.classList.remove('hidden');
                emptyState.classList.add('hidden');
                accountBadge.textContent = accounts.length + ' account' + (accounts.length !== 1 ? 's' : '');

                accountsList.innerHTML = accounts.map((acc, index) => {
                    const initial = acc.email.charAt(0).toUpperCase();
                    const isDefault = acc.isDefault;
                    const services = acc.services || ['calendar', 'gmail', 'drive'];

                    return ` + "`" + `
                        <div class="account-card ${isDefault ? 'default' : ''}" data-email="${acc.email}">
                            <div class="account-avatar" style="background: ${getAvatarGradient(acc.email)}">
                                ${initial}
                            </div>
                            <div class="account-details">
                                <div class="account-email">${acc.email}</div>
                                <div class="account-services">
                                    ${services.map(s => ` + "`" + `<span class="service-tag ${s.toLowerCase()}">${s}</span>` + "`" + `).join('')}
                                </div>
                            </div>
                            <div class="account-actions">
                                ${isDefault ? ` + "`" + `
                                    <span class="default-badge">
                                        <svg viewBox="0 0 24 24" fill="currentColor">
                                            <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
                                        </svg>
                                        Default
                                    </span>
                                ` + "`" + ` : ` + "`" + `
                                    <button class="set-default-btn" onclick="setDefault('${acc.email}')">Set default</button>
                                ` + "`" + `}
                                <button class="remove-btn" onclick="removeAccount('${acc.email}')" title="Remove account">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
                                        <line x1="18" y1="6" x2="6" y2="18"/>
                                        <line x1="6" y1="6" x2="18" y2="18"/>
                                    </svg>
                                </button>
                            </div>
                        </div>
                    ` + "`" + `;
                }).join('');
            }
        }

        function addAccount() {
            // Redirect to OAuth flow
            window.location.href = '/auth/start';
        }

        async function setDefault(email) {
            try {
                const response = await fetch('/set-default', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ email })
                });
                const data = await response.json();
                if (data.success) {
                    await loadAccounts();
                }
            } catch (err) {
                console.error('Failed to set default:', err);
            }
        }

        async function removeAccount(email) {
            if (!confirm('Remove ' + email + ' from gog?')) {
                return;
            }
            try {
                const response = await fetch('/remove-account', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Token': csrfToken
                    },
                    body: JSON.stringify({ email })
                });
                const data = await response.json();
                if (data.success) {
                    await loadAccounts();
                }
            } catch (err) {
                console.error('Failed to remove account:', err);
            }
        }

        // Initialize
        loadAccounts();
    </script>
</body>
</html>` + "`"

// successTemplateNew renders after successful OAuth authorization with add another option
const successTemplateNew = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connected - gog</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-void: #050508;
            --bg-base: #0a0a0f;
            --bg-surface: #111116;
            --bg-elevated: #18181d;
            --bg-hover: #1f1f26;
            --border: rgba(255, 255, 255, 0.06);
            --border-subtle: rgba(255, 255, 255, 0.04);
            --border-active: rgba(255, 255, 255, 0.12);
            --text: #f4f4f5;
            --text-secondary: #a1a1aa;
            --text-muted: #71717a;
            --text-dim: #52525b;

            --g-blue: #4285F4;
            --g-blue-dim: rgba(66, 133, 244, 0.12);
            --g-red: #EA4335;
            --g-red-dim: rgba(234, 67, 53, 0.12);
            --g-yellow: #FBBC05;
            --g-yellow-dim: rgba(251, 188, 5, 0.12);
            --g-green: #34A853;
            --g-green-dim: rgba(52, 168, 83, 0.12);

            --radius-sm: 8px;
            --radius: 12px;
            --radius-lg: 16px;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Sora', -apple-system, sans-serif;
            background: var(--bg-void);
            color: var(--text);
            min-height: 100vh;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
            opacity: 0;
            animation: pageReveal 0.5s ease-out forwards;
        }

        @keyframes pageReveal {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        /* Success ambient glow */
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background:
                radial-gradient(ellipse 80% 60% at 50% -20%, var(--g-green-dim), transparent 60%),
                radial-gradient(ellipse 60% 50% at 70% 30%, var(--g-blue-dim), transparent 50%);
            pointer-events: none;
            z-index: 0;
        }

        body::after {
            content: '';
            position: fixed;
            inset: 0;
            background-image:
                linear-gradient(rgba(255, 255, 255, 0.015) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.015) 1px, transparent 1px);
            background-size: 64px 64px;
            pointer-events: none;
            z-index: 0;
        }

        .container {
            max-width: 560px;
            margin: 0 auto;
            padding: 48px 24px;
            position: relative;
            z-index: 1;
        }

        /* Success Header */
        .success-header {
            text-align: center;
            margin-bottom: 40px;
        }

        .success-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 24px;
            position: relative;
            opacity: 0;
            animation: iconReveal 0.6s cubic-bezier(0.16, 1, 0.3, 1) 0.1s forwards;
        }

        @keyframes iconReveal {
            from {
                opacity: 0;
                transform: scale(0.8) translateY(10px);
            }
            to {
                opacity: 1;
                transform: scale(1) translateY(0);
            }
        }

        .success-icon svg {
            width: 100%;
            height: 100%;
            filter: drop-shadow(0 8px 32px rgba(66, 133, 244, 0.3));
        }

        .success-badge {
            position: absolute;
            bottom: -4px;
            right: -4px;
            width: 28px;
            height: 28px;
            background: var(--g-green);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 0 0 4px var(--bg-void), 0 4px 12px rgba(52, 168, 83, 0.4);
            opacity: 0;
            transform: scale(0);
            animation: badgePop 0.4s cubic-bezier(0.34, 1.56, 0.64, 1) 0.5s forwards;
        }

        @keyframes badgePop {
            to {
                opacity: 1;
                transform: scale(1);
            }
        }

        .success-badge svg {
            width: 16px;
            height: 16px;
            color: white;
        }

        h1 {
            font-size: 28px;
            font-weight: 700;
            letter-spacing: -0.03em;
            margin-bottom: 8px;
            opacity: 0;
            animation: contentReveal 0.5s ease-out 0.25s forwards;
        }

        @keyframes contentReveal {
            from {
                opacity: 0;
                transform: translateY(12px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .account-email {
            font-size: 15px;
            color: var(--text-secondary);
            margin-bottom: 16px;
            opacity: 0;
            animation: contentReveal 0.5s ease-out 0.35s forwards;
        }

        .account-email strong {
            color: var(--g-blue);
            font-weight: 600;
        }

        .services-row {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 6px;
            margin-bottom: 20px;
            opacity: 0;
            animation: contentReveal 0.5s ease-out 0.4s forwards;
        }

        .service-tag {
            font-size: 11px;
            font-weight: 500;
            letter-spacing: 0.02em;
            padding: 4px 10px 4px 24px;
            border-radius: 99px;
            border: 1px solid;
            background-repeat: no-repeat;
            background-position: 6px center;
            background-size: 14px 14px;
        }

        .service-tag.calendar {
            color: var(--g-blue);
            background-color: var(--g-blue-dim);
            border-color: rgba(66, 133, 244, 0.2);
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 24 24' fill='%234285F4' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M18.316 5.684H24v12.632h-5.684V5.684zM5.684 24h12.632v-5.684H5.684V24zM18.316 5.684V0H1.895A1.894 1.894 0 0 0 0 1.895v16.421h5.684V5.684h12.632zM22.105 0h-3.289v5.184H24V1.895A1.894 1.894 0 0 0 22.105 0zM0 22.105C0 23.152.848 24 1.895 24h3.289v-5.184H0v3.289z'/%3E%3C/svg%3E");
        }

        .service-tag.gmail {
            color: var(--g-red);
            background-color: var(--g-red-dim);
            border-color: rgba(234, 67, 53, 0.2);
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 24 24' fill='%23EA4335' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M24 5.457v13.909c0 .904-.732 1.636-1.636 1.636h-3.819V11.73L12 16.64l-6.545-4.91v9.273H1.636A1.636 1.636 0 0 1 0 19.366V5.457c0-2.023 2.309-3.178 3.927-1.964L5.455 4.64 12 9.548l6.545-4.91 1.528-1.145C21.69 2.28 24 3.434 24 5.457z'/%3E%3C/svg%3E");
        }

        .service-tag.drive {
            color: var(--g-yellow);
            background-color: var(--g-yellow-dim);
            border-color: rgba(251, 188, 5, 0.2);
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 24 24' fill='%23FBBC05' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M12.01 1.485c-2.082 0-3.754.02-3.743.047.01.02 1.708 3.001 3.774 6.62l3.76 6.574h3.76c2.081 0 3.753-.02 3.742-.047-.005-.02-1.708-3.001-3.775-6.62l-3.76-6.574zm-4.76 1.73a789.828 789.861 0 0 0-3.63 6.319L0 15.868l1.89 3.298 1.885 3.297 3.62-6.335 3.618-6.33-1.88-3.287C8.1 4.704 7.255 3.22 7.25 3.214zm2.259 12.653-.203.348c-.114.198-.96 1.672-1.88 3.287a423.93 423.948 0 0 1-1.698 2.97c-.01.026 3.24.042 7.222.042h7.244l1.796-3.157c.992-1.734 1.85-3.23 1.906-3.323l.104-.167h-7.249z'/%3E%3C/svg%3E");
        }

        .service-tag.contacts {
            color: var(--g-blue);
            background-color: var(--g-blue-dim);
            border-color: rgba(66, 133, 244, 0.2);
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 24 24' fill='%234285F4' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M20 0H4v2h16V0zM4 24h16v-2H4v2zM20 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V6c0-1.1-.9-2-2-2zm-8 2.75c1.24 0 2.25 1.01 2.25 2.25s-1.01 2.25-2.25 2.25S9.75 10.24 9.75 9 10.76 6.75 12 6.75zM17 17H7v-1.5c0-1.67 3.33-2.5 5-2.5s5 .83 5 2.5V17z'/%3E%3C/svg%3E");
        }

        .service-tag.sheets {
            color: var(--g-green);
            background-color: var(--g-green-dim);
            border-color: rgba(52, 168, 83, 0.2);
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 24 24' fill='%2334A853' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M11.318 12.545H7.91v-1.909h3.41v1.91zM14.728 0v6h6l-6-6zm1.363 10.636h-3.41v1.91h3.41v-1.91zm0 3.273h-3.41v1.91h3.41v-1.91zM20.727 6.5v15.864c0 .904-.732 1.636-1.636 1.636H4.909a1.636 1.636 0 0 1-1.636-1.636V1.636C3.273.732 4.005 0 4.909 0h9.318v6.5h6.5zm-3.273 2.773H6.545v7.909h10.91v-7.91zm-6.136 4.636H7.91v1.91h3.41v-1.91z'/%3E%3C/svg%3E");
        }

        /* Terminal Card */
        .terminal-card {
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius-lg);
            overflow: hidden;
            margin-bottom: 20px;
            opacity: 0;
            animation: contentReveal 0.5s ease-out 0.45s forwards;
            box-shadow: 0 4px 24px rgba(0, 0, 0, 0.2);
        }

        .terminal-bar {
            background: var(--bg-elevated);
            padding: 12px 16px;
            display: flex;
            align-items: center;
            gap: 8px;
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
            font-size: 11px;
            color: var(--text-dim);
            margin-right: 48px;
        }

        .terminal-body {
            padding: 20px;
        }

        .terminal-line {
            display: flex;
            align-items: center;
            gap: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            margin-bottom: 10px;
            line-height: 1.5;
        }

        .terminal-line:last-child {
            margin-bottom: 0;
        }

        .terminal-prompt {
            color: var(--g-blue);
            user-select: none;
            font-weight: 500;
        }

        .terminal-cmd {
            color: var(--text);
        }

        .terminal-flag {
            color: var(--g-yellow);
        }

        .terminal-arg {
            color: var(--g-green);
        }

        .terminal-output {
            color: var(--text-dim);
            padding-left: 18px;
            margin-top: -6px;
            margin-bottom: 10px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
        }

        .terminal-output.success {
            color: var(--g-green);
        }

        .terminal-cursor {
            display: inline-block;
            width: 8px;
            height: 18px;
            background: var(--g-blue);
            animation: cursorBlink 1.2s step-end infinite;
            border-radius: 1px;
        }

        @keyframes cursorBlink {
            0%, 50% { opacity: 1; }
            50.01%, 100% { opacity: 0; }
        }

        /* Action Buttons */
        .actions {
            display: flex;
            gap: 10px;
            margin-bottom: 24px;
            opacity: 0;
            animation: contentReveal 0.5s ease-out 0.5s forwards;
        }

        .btn {
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 14px 20px;
            border-radius: var(--radius);
            font-family: inherit;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            border: none;
        }

        .btn-primary {
            background: var(--bg-surface);
            color: var(--text);
            border: 1px solid var(--border);
        }

        .btn-primary:hover {
            background: var(--bg-elevated);
            border-color: var(--border-active);
        }

        .btn-secondary {
            background: var(--g-blue);
            color: white;
            box-shadow: 0 4px 16px rgba(66, 133, 244, 0.25);
        }

        .btn-secondary:hover {
            background: #5a9cff;
            transform: translateY(-1px);
            box-shadow: 0 6px 24px rgba(66, 133, 244, 0.35);
        }

        .btn svg {
            width: 18px;
            height: 18px;
        }

        /* Info Card */
        .info-card {
            padding: 16px 20px;
            background: var(--bg-surface);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            display: flex;
            gap: 14px;
            align-items: flex-start;
            opacity: 0;
            animation: contentReveal 0.5s ease-out 0.55s forwards;
        }

        .info-icon {
            flex-shrink: 0;
            width: 36px;
            height: 36px;
            background: var(--g-blue-dim);
            border-radius: var(--radius-sm);
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .info-icon svg {
            width: 18px;
            height: 18px;
            color: var(--g-blue);
        }

        .info-content h4 {
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 2px;
        }

        .info-content p {
            font-size: 13px;
            color: var(--text-muted);
            line-height: 1.5;
        }

        .info-content code {
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            background: var(--bg-elevated);
            padding: 2px 6px;
            border-radius: 4px;
            color: var(--g-blue);
        }

        /* Footer */
        .footer {
            text-align: center;
            margin-top: 2rem;
            font-size: 0.8125rem;
            color: var(--text-dim);
            opacity: 0;
            animation: contentReveal 0.5s ease-out 0.6s forwards;
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

        @media (max-width: 480px) {
            .container {
                padding: 32px 16px;
            }

            .actions {
                flex-direction: column;
            }

            .terminal-body {
                padding: 16px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="success-header">
            <div class="success-icon">
                <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                    <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                    <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                    <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                    <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                </svg>
                <div class="success-badge">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="20 6 9 17 4 12"/>
                    </svg>
                </div>
            </div>

            <h1>You're connected</h1>
            <p class="account-email">Authorized as <strong>{{.Email}}</strong></p>

            <div class="services-row">
                {{range .Services}}
                <span class="service-tag {{.}}">{{.}}</span>
                {{end}}
            </div>
        </header>

        <div class="terminal-card">
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

        <div class="actions">
            <a href="/" class="btn btn-primary">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
                    <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
                    <polyline points="9 22 9 12 15 12 15 22"/>
                </svg>
                Manage Accounts
            </a>
            <a href="/auth/start" class="btn btn-secondary">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round">
                    <line x1="12" y1="5" x2="12" y2="19"/>
                    <line x1="5" y1="12" x2="19" y2="12"/>
                </svg>
                Add Another Account
            </a>
        </div>

        <div class="info-card">
            <div class="info-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="4 17 10 11 4 5"></polyline>
                    <line x1="12" y1="19" x2="20" y2="19"></line>
                </svg>
            </div>
            <div class="info-content">
                <h4>Return to your terminal</h4>
                <p>You can close this window. Run <code>gog --help</code> to see available commands.</p>
            </div>
        </div>

        <footer class="footer">
            <a href="https://github.com/salmonumbrella/gog-cli" target="_blank" class="github-link">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                    <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
                </svg>
                View on GitHub
            </a>
        </footer>
    </div>
</body>
</html>` + "`"
