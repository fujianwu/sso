// common.js - SSO 通用工具库 (完整合并版)

// API 请求封装
async function apiRequest(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
        },
        credentials: 'include', // 包含 Cookie
    };

    const mergedOptions = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers,
        },
    };

    try {
        const response = await fetch(url, mergedOptions);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || '请求失败');
        }

        return data;
    } catch (error) {
        console.error('API 请求错误:', error);
        throw error;
    }
}

// 显示错误消息
function showError(elementId, message) {
    const errorElement = document.getElementById(elementId);
    if (errorElement) {
        errorElement.textContent = message;
        errorElement.classList.add('show');
    }
}

// 隐藏错误消息
function hideError(elementId) {
    const errorElement = document.getElementById(elementId);
    if (errorElement) {
        errorElement.classList.remove('show');
    }
}

// 显示 Toast/Snackbar 通知
function showAlert(message, type = 'info') {
    // 移除已存在的 toast
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

    // 触发动画
    setTimeout(() => toast.classList.add('sso-toast-show'), 10);

    // 4秒后自动移除
    setTimeout(() => {
        toast.classList.remove('sso-toast-show');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// 自定义确认对话框
function showConfirm(options) {
    return new Promise((resolve) => {
        const {
            title = '确认操作',
            message = '确定要执行此操作吗?',
            confirmText = '确定',
            cancelText = '取消',
            type = 'warning' // warning, danger, info
        } = options;

        // 移除已存在的对话框
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

        // 触发显示动画
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

        // ESC 键关闭
        const escHandler = (e) => {
            if (e.key === 'Escape') {
                closeModal(false);
                document.removeEventListener('keydown', escHandler);
            }
        };
        document.addEventListener('keydown', escHandler);
    });
}

// 生成用户头像
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

// 创建头像元素
function createAvatarElement(name, size = 'normal') {
    const avatar = generateAvatar(name);
    const div = document.createElement('div');
    div.className = `user-avatar ${size === 'large' ? 'large' : ''}`;
    div.style.backgroundColor = avatar.color;
    div.textContent = avatar.initial;
    return div;
}

// 表单验证
function validateEmail(email) {
    const re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return re.test(email);
}

function validatePassword(password) {
    if (password.length < 8) {
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

// 获取 URL 参数
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

// 按钮加载状态
function setButtonLoading(buttonId, loading) {
    const button = document.getElementById(buttonId);
    if (!button) return;

    if (loading) {
        button.disabled = true;
        button.dataset.originalText = button.textContent;
        button.innerHTML = '<span class="loading"></span> 处理中...';
    } else {
        button.disabled = false;
        button.textContent = button.dataset.originalText || button.textContent;
    }
}

// 防抖函数
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

// 初始化自定义组件样式
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
            transition: top 0.3s ease;
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
            transition: all 0.3s ease;
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
    `;
    document.head.appendChild(style);
}

// 页面加载时初始化
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initCustomStyles);
} else {
    initCustomStyles();
}

// 导出
window.ssoUtils = {
    apiRequest,
    showError,
    hideError,
    showAlert,
    showConfirm,
    generateAvatar,
    createAvatarElement,
    validateEmail,
    validatePassword,
    getUrlParams,
    setButtonLoading,
    debounce
};