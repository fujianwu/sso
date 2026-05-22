/**
 * SSO 平台通用工具库
 * 提供 API 请求、表单验证、UI 反馈等功能
 */

// ===== API 请求封装 =====

async function apiRequest(url, options = {}) {
    const defaultOptions = {
        method: options.method || 'GET',
        headers: {
            'Content-Type': 'application/json',
        },
        credentials: 'include',
    };

    const mergedOptions = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers,
        },
    };

    if (options.body && typeof options.body === 'object') {
        mergedOptions.body = JSON.stringify(options.body);
    }

    try {
        const response = await fetch(url, mergedOptions);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || `请求失败 (${response.status})`);
        }

        return data;
    } catch (error) {
        console.error('[SSO API 错误]:', error);
        throw error;
    }
}

// ===== 表单验证 =====

function validateEmail(email) {
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return regex.test(String(email).toLowerCase());
}

function validatePassword(password) {
    if (!password || password.length < 8) {
        return { valid: false, message: '密码长度至少为 8 位' };
    }
    if (!/[A-Z]/.test(password)) {
        return { valid: false, message: '密码必须包含至少一个大写字母' };
    }
    if (!/[a-z]/.test(password)) {
        return { valid: false, message: '密码必须包含至少一个小写字母' };
    }
    if (!/\d/.test(password)) {
        return { valid: false, message: '密码必须包含至少一个数字' };
    }
    return { valid: true };
}

function validatePasswordSimple(password) {
    return password && password.length >= 8;
}

// ===== UI 反馈函数 =====

function showError(message) {
    showAlert(message, 'error');
}

function showSuccess(message) {
    showAlert(message, 'success');
}

function showWarning(message) {
    showAlert(message, 'warning');
}

function showInfo(message) {
    showAlert(message, 'info');
}

function showAlert(message, type = 'info') {
    const existingToast = document.querySelector('.sso-toast');
    if (existingToast) {
        existingToast.remove();
    }

    const toast = document.createElement('div');
    toast.className = `sso-toast sso-toast-${type}`;

    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };

    toast.innerHTML = `
        <span class="sso-toast-icon">${icons[type] || icons.info}</span>
        <span class="sso-toast-message">${message}</span>
    `;

    document.body.appendChild(toast);

    setTimeout(() => toast.classList.add('sso-toast-show'), 10);

    setTimeout(() => {
        toast.classList.remove('sso-toast-show');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ===== 确认对话框 =====

function showConfirm(options) {
    return new Promise((resolve) => {
        const {
            title = '确认操作',
            message = '确定要执行此操作吗?',
            confirmText = '确定',
            cancelText = '取消',
            type = 'warning'
        } = options;

        const existing = document.querySelector('.sso-modal-overlay');
        if (existing) existing.remove();

        const overlay = document.createElement('div');
        overlay.className = 'sso-modal-overlay';

        const modal = document.createElement('div');
        modal.className = `sso-modal sso-modal-${type}`;

        modal.innerHTML = `
            <div class="sso-modal-header">
                <h3 class="sso-modal-title">${title}</h3>
            </div>
            <div class="sso-modal-body">
                <p>${message}</p>
            </div>
            <div class="sso-modal-footer">
                <button class="sso-modal-btn sso-modal-btn-cancel">${cancelText}</button>
                <button class="sso-modal-btn sso-modal-btn-confirm sso-modal-btn-${type}">${confirmText}</button>
            </div>
        `;

        overlay.appendChild(modal);
        document.body.appendChild(overlay);

        setTimeout(() => {
            overlay.classList.add('sso-modal-overlay-show');
            modal.classList.add('sso-modal-show');
        }, 10);

        const closeModal = (confirmed) => {
            overlay.classList.remove('sso-modal-overlay-show');
            modal.classList.remove('sso-modal-show');
            setTimeout(() => overlay.remove(), 300);
            resolve(confirmed);
        };

        modal.querySelector('.sso-modal-btn-confirm').onclick = () => closeModal(true);
        modal.querySelector('.sso-modal-btn-cancel').onclick = () => closeModal(false);
        overlay.onclick = (e) => {
            if (e.target === overlay) closeModal(false);
        };

        const escHandler = (e) => {
            if (e.key === 'Escape') {
                closeModal(false);
                document.removeEventListener('keydown', escHandler);
            }
        };
        document.addEventListener('keydown', escHandler);
    });
}

// ===== 工具函数 =====

function generateAvatar(name) {
    const initial = name.charAt(0).toUpperCase();
    const colors = [
        '#1a73e8', '#d93025', '#0f9d58', '#f4b400', '#ab47bc',
        '#00acc1', '#ff6f00', '#5e35b1', '#c0ca33', '#00897b'
    ];
    const colorIndex = name.charCodeAt(0) % colors.length;
    const color = colors[colorIndex];

    return {
        initial: initial,
        color: color
    };
}

function createAvatarElement(name, size = 'normal') {
    const avatar = generateAvatar(name);
    const div = document.createElement('div');
    div.className = `user-avatar ${size === 'large' ? 'large' : ''}`;
    div.style.backgroundColor = avatar.color;
    div.textContent = avatar.initial;
    return div;
}

function getUrlParams() {
    const params = {};
    const queryString = window.location.search.substring(1);
    const pairs = queryString.split('&');

    pairs.forEach(pair => {
        const [key, value] = pair.split('=');
        if (key) {
            params[decodeURIComponent(key)] = decodeURIComponent(value || '');
        }
    });

    return params;
}

function setButtonLoading(button, loading) {
    const btn = typeof button === 'string' ? document.getElementById(button) : button;
    if (!btn) return;

    if (loading) {
        btn.disabled = true;
        btn.dataset.originalText = btn.innerHTML;
        btn.innerHTML = '<span class="loading-spinner"></span> 处理中...';
        btn.classList.add('btn-loading');
    } else {
        btn.disabled = false;
        btn.innerHTML = btn.dataset.originalText || btn.textContent;
        btn.classList.remove('btn-loading');
    }
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

// ===== 表单处理 =====

function setupFormValidation() {
    const loginForm = document.querySelector('form[action*="login"]');
    if (loginForm) {
        loginForm.addEventListener('submit', function(e) {
            const email = loginForm.querySelector('input[name="email"]')?.value;
            const password = loginForm.querySelector('input[name="password"]')?.value;

            if (!email || !validateEmail(email)) {
                e.preventDefault();
                showError('请输入有效的邮箱地址');
                return false;
            }

            if (!password || !validatePasswordSimple(password)) {
                e.preventDefault();
                showError('密码长度至少为 8 位');
                return false;
            }
        });
    }

    const registerForm = document.querySelector('form[action*="register"]');
    if (registerForm) {
        registerForm.addEventListener('submit', function(e) {
            const email = registerForm.querySelector('input[name="email"]')?.value;
            const password = registerForm.querySelector('input[name="password"]')?.value;
            const confirmPassword = registerForm.querySelector('input[name="confirm_password"]')?.value;

            if (!email || !validateEmail(email)) {
                e.preventDefault();
                showError('请输入有效的邮箱地址');
                return false;
            }

            if (!password || !validatePasswordSimple(password)) {
                e.preventDefault();
                showError('密码长度至少为 8 位');
                return false;
            }

            if (password !== confirmPassword) {
                e.preventDefault();
                showError('两次输入的密码不一致');
                return false;
            }
        });
    }
}

// ===== 初始化自定义样式 =====

function initCustomStyles() {
    if (document.getElementById('sso-custom-styles')) return;

    const style = document.createElement('style');
    style.id = 'sso-custom-styles';
    style.textContent = `
        /* Toast 通知样式 */
        .sso-toast {
            position: fixed;
            top: -100px;
            left: 50%;
            transform: translateX(-50%);
            background: white;
            padding: 16px 24px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            display: flex;
            align-items: center;
            gap: 12px;
            z-index: 10000;
            transition: top 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            min-width: 300px;
            max-width: 500px;
        }

        .sso-toast-show {
            top: 24px;
        }

        .sso-toast-icon {
            font-size: 20px;
            font-weight: bold;
            width: 24px;
            height: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
            flex-shrink: 0;
        }

        .sso-toast-success {
            border-left: 4px solid #10b981;
        }

        .sso-toast-success .sso-toast-icon {
            background: #d1fae5;
            color: #065f46;
        }

        .sso-toast-error {
            border-left: 4px solid #ef4444;
        }

        .sso-toast-error .sso-toast-icon {
            background: #fee2e2;
            color: #991b1b;
        }

        .sso-toast-warning {
            border-left: 4px solid #f59e0b;
        }

        .sso-toast-warning .sso-toast-icon {
            background: #fef3c7;
            color: #92400e;
        }

        .sso-toast-info {
            border-left: 4px solid #3b82f6;
        }

        .sso-toast-info .sso-toast-icon {
            background: #dbeafe;
            color: #1e40af;
        }

        .sso-toast-message {
            flex: 1;
            color: #1f2937;
            font-size: 14px;
        }

        /* Modal 对话框样式 */
        .sso-modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
            transition: background 0.3s ease;
        }

        .sso-modal-overlay-show {
            background: rgba(0, 0, 0, 0.5);
        }

        .sso-modal {
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
            width: 90%;
            max-width: 450px;
            transform: scale(0.9);
            opacity: 0;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        .sso-modal-show {
            transform: scale(1);
            opacity: 1;
        }

        .sso-modal-header {
            padding: 24px 24px 16px;
            border-bottom: 1px solid #e5e7eb;
        }

        .sso-modal-title {
            margin: 0;
            font-size: 18px;
            font-weight: 600;
            color: #111827;
        }

        .sso-modal-body {
            padding: 24px;
            color: #6b7280;
            font-size: 14px;
            line-height: 1.6;
        }

        .sso-modal-footer {
            padding: 16px 24px 24px;
            display: flex;
            gap: 12px;
            justify-content: flex-end;
        }

        .sso-modal-btn {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }

        .sso-modal-btn-cancel {
            background: #f3f4f6;
            color: #374151;
        }

        .sso-modal-btn-cancel:hover {
            background: #e5e7eb;
        }

        .sso-modal-btn-confirm {
            color: white;
        }

        .sso-modal-btn-warning {
            background: #f59e0b;
        }

        .sso-modal-btn-warning:hover {
            background: #d97706;
        }

        .sso-modal-btn-danger {
            background: #ef4444;
        }

        .sso-modal-btn-danger:hover {
            background: #dc2626;
        }

        .sso-modal-btn-info {
            background: #3b82f6;
        }

        .sso-modal-btn-info:hover {
            background: #2563eb;
        }

        /* 加载动画 */
        .loading-spinner {
            display: inline-block;
            width: 14px;
            height: 14px;
            border: 2px solid rgba(255, 255, 255, 0.3);
            border-top-color: white;
            border-radius: 50%;
            animation: spin 0.6s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .btn-loading {
            position: relative;
            pointer-events: none;
        }
    `;
    document.head.appendChild(style);
}

// ===== 性能监控 =====

function logPerformance() {
    if (window.performance && window.performance.timing) {
        const perfData = window.performance.timing;
        const pageLoadTime = perfData.loadEventEnd - perfData.navigationStart;
        console.log(`[SSO] 页面加载时间: ${pageLoadTime}ms`);

        const domReady = perfData.domContentLoadedEventEnd - perfData.navigationStart;
        console.log(`[SSO] DOM 准备时间: ${domReady}ms`);
    }
}

// ===== 初始化 =====

function init() {
    initCustomStyles();
    setupFormValidation();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
} else {
    init();
}

window.addEventListener('load', logPerformance);

// ===== 导出全局 API =====

window.ssoUtils = {
    apiRequest,
    validateEmail,
    validatePassword,
    validatePasswordSimple,
    showError,
    showSuccess,
    showWarning,
    showInfo,
    showAlert,
    showConfirm,
    generateAvatar,
    createAvatarElement,
    getUrlParams,
    setButtonLoading,
    debounce,
    throttle
};
