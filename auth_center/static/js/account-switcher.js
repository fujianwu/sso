/**
 * 账户切换模块 v2
 *
 * 设计原则：
 * - localStorage 只存 session_token + 展示信息（email / name / avatar），
 *   不做任何 Cookie 操作（httponly Cookie 只由服务端设置）。
 * - 切换账户：POST /api/auth/switch-account，服务端验证并通过 Set-Cookie 换发 Cookie。
 * - 登出当前账户：POST /api/auth/logout-current，服务端删除 session 并清除 Cookie，
 *   前端从 localStorage 移除该账户后自动切换到下一个已保存的账户（若有）。
 * - 「添加账户」= 直接跳到 /login，登录成功后 login 页面调用 AccountSwitcher.saveAccount() 保存。
 */

const AccountSwitcher = {
    STORAGE_KEY: 'sso_saved_accounts',
    CURRENT_KEY: 'sso_current_account_id',

    // ─── localStorage ────────────────────────────────────────────────

    getSavedAccounts() {
        try {
            const raw = localStorage.getItem(this.STORAGE_KEY);
            return raw ? JSON.parse(raw) : [];
        } catch { return []; }
    },

    _saveAccounts(accounts) {
        localStorage.setItem(this.STORAGE_KEY, JSON.stringify(accounts));
    },

    getCurrentUserId() {
        return localStorage.getItem(this.CURRENT_KEY);
    },

    setCurrentUserId(userId) {
        localStorage.setItem(this.CURRENT_KEY, String(userId));
    },

    /**
     * 保存（或更新）一个账户。登录成功后调用：
     *   AccountSwitcher.saveAccount({ user_id, name, email, avatar_url, session_token })
     */
    saveAccount(info) {
        const accounts = this.getSavedAccounts();
        const idx = accounts.findIndex(a => a.user_id === info.user_id);
        const entry = {
            user_id: info.user_id,
            name: info.name,
            email: info.email,
            avatar_url: info.avatar_url || null,
            session_token: info.session_token,
            last_login: new Date().toISOString(),
        };
        if (idx >= 0) accounts[idx] = entry;
        else accounts.push(entry);
        this._saveAccounts(accounts);
        this.setCurrentUserId(info.user_id);
    },

    _removeAccountLocally(userId) {
        const accounts = this.getSavedAccounts().filter(a => a.user_id !== userId);
        this._saveAccounts(accounts);
        if (this.getCurrentUserId() === String(userId)) {
            const next = accounts[0];
            if (next) this.setCurrentUserId(next.user_id);
            else localStorage.removeItem(this.CURRENT_KEY);
        }
    },

    // ─── 核心操作 ─────────────────────────────────────────────────────

    /** 通过服务端接口换发 Cookie，完成账户切换 */
    async switchAccount(sessionToken, userId) {
        const fd = new FormData();
        fd.append('target_session_token', sessionToken);
        try {
            const resp = await fetch('/api/auth/switch-account', {
                method: 'POST', body: fd, credentials: 'same-origin',
            });
            if (resp.ok) {
                const data = await resp.json();
                this.setCurrentUserId(userId);
                if (data.user) {
                    const accounts = this.getSavedAccounts();
                    const idx = accounts.findIndex(a => a.user_id === userId);
                    if (idx >= 0) {
                        accounts[idx] = { ...accounts[idx], ...data.user, last_login: new Date().toISOString() };
                        this._saveAccounts(accounts);
                    }
                }
                window.location.reload();
            } else {
                const err = await resp.json().catch(() => ({}));
                if (resp.status === 404 || resp.status === 401) {
                    this._removeAccountLocally(userId);
                    this.renderSwitcher('accountSwitcherContainer');
                    alert(err.detail || '该账户会话已过期，请重新登录');
                } else {
                    alert(err.detail || '切换失败，请稍后再试');
                }
            }
        } catch { alert('网络请求失败，请检查连接'); }
    },

    /**
     * 登出当前账户。
     * 服务端清除 Cookie + session → 本地移除该账户 → 自动切换下一个或跳登录页。
     */
    async logoutCurrent() {
        try {
            await fetch('/api/auth/logout-current', { method: 'POST', credentials: 'same-origin' });
        } catch { /* 网络失败也继续本地清理 */ }

        const currentId = this.getCurrentUserId();
        if (currentId) this._removeAccountLocally(parseInt(currentId, 10));

        const remaining = this.getSavedAccounts();
        if (remaining.length > 0) {
            await this.switchAccount(remaining[0].session_token, remaining[0].user_id);
        } else {
            window.location.href = '/login';
        }
    },

    // ─── UI ──────────────────────────────────────────────────────────

    renderSwitcher(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;

        const accounts = this.getSavedAccounts();
        const currentId = this.getCurrentUserId();

        if (accounts.length === 0) {
            container.innerHTML = '<p style="color:#94a3b8;font-size:14px;margin-bottom:1rem;">暂无已保存的账户</p>';
            return;
        }

        let html = '<div class="account-switcher-list">';
        for (const acc of accounts) {
            const isCurrent = String(acc.user_id) === String(currentId);
            const lastLogin = acc.last_login ? new Date(acc.last_login).toLocaleString('zh-CN') : '未知';
            const avatarHtml = acc.avatar_url
                ? `<img src="${this._esc(acc.avatar_url)}" alt="${this._esc(acc.name)}">`
                : `<div class="avatar-placeholder">${this._esc(acc.name).charAt(0).toUpperCase()}</div>`;

            html += `
                <div class="account-item ${isCurrent ? 'current' : ''}" data-user-id="${acc.user_id}">
                    <div class="account-info">
                        <div class="account-avatar">${avatarHtml}</div>
                        <div class="account-details">
                            <div class="account-name">${this._esc(acc.name)}</div>
                            <div class="account-email">${this._esc(acc.email)}</div>
                            <div class="account-meta">最后登录：${lastLogin}</div>
                        </div>
                    </div>
                    <div class="account-actions">
                        ${isCurrent
                            ? `<span class="badge badge-primary">当前</span>
                               <button class="btn btn-sm btn-danger"
                                   onclick="AccountSwitcher.handleLogoutCurrent()">退出此账户</button>`
                            : `<button class="btn btn-sm btn-secondary"
                                   onclick="AccountSwitcher.handleSwitch('${this._esc(acc.session_token)}', ${acc.user_id})">切换</button>`
                        }
                        <button class="btn btn-sm btn-ghost"
                            onclick="AccountSwitcher.handleRemoveLocally(${acc.user_id}, '${this._esc(acc.name)}')">从列表移除</button>
                    </div>
                </div>`;
        }
        html += '</div>';
        container.innerHTML = html;
    },

    // ─── 带确认的事件处理 ─────────────────────────────────────────────

    async handleSwitch(sessionToken, userId) {
        if (confirm('确定切换到此账户？')) await this.switchAccount(sessionToken, userId);
    },

    async handleLogoutCurrent() {
        if (confirm('退出当前账户？若还有其他已保存账户将自动切换，否则跳转登录页。')) {
            await this.logoutCurrent();
        }
    },

    async handleRemoveLocally(userId, name) {
        if (confirm(`从本地列表移除「${name}」？\n这只删除本地记录，不会登出服务器上的会话。`)) {
            this._removeAccountLocally(userId);
            this.renderSwitcher('accountSwitcherContainer');
        }
    },

    _esc(str) {
        if (!str) return '';
        const d = document.createElement('div');
        d.textContent = String(str);
        return d.innerHTML;
    },
};

window.AccountSwitcher = AccountSwitcher;
