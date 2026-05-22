// 优化后的脚本 - 减少弹窗，使用内联提示和toast通知

// 替换alert弹窗为toast通知
window.alert = function(message, type = 'info') {
    showToast(message, type);
};

// 显示toast通知
function showToast(message, type = 'info') {
    const container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    // 3秒后自动移除
    setTimeout(() => {
        toast.remove();
        if (container.children.length === 0) {
            container.remove();
        }
    }, 3000);
}

// 显示内联提示
function showInlineAlert(elementId, message, type = 'error') {
    const alert = document.getElementById(elementId);
    if (alert) {
        alert.textContent = message;
        alert.className = `inline-alert inline-alert-${type} show`;

        // 5秒后自动隐藏
        setTimeout(() => {
            alert.classList.remove('show');
        }, 5000);
    }
}

// 表单提交处理 - 替换弹窗提示
document.addEventListener('DOMContentLoaded', function() {
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            // 阻止默认表单提交
            e.preventDefault();

            // 模拟表单验证
            const inputs = form.querySelectorAll('.form-input');
            let isValid = true;

            inputs.forEach(input => {
                if (!input.value.trim()) {
                    const errorId = input.id + '-error';
                    showInlineAlert(errorId, '此字段为必填项', 'error');
                    isValid = false;
                }
            });

            if (isValid) {
                // 模拟提交成功
                showToast('操作成功', 'success');
                // 实际应用中应提交表单
                // form.submit();
            }
        });
    });

    // 替换确认弹窗
    const confirmButtons = document.querySelectorAll('[data-confirm]');
    confirmButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const message = this.getAttribute('data-confirm');
            const action = this.getAttribute('href') || this.getAttribute('data-action');

            // 创建内联确认框
            const confirmBox = document.createElement('div');
            confirmBox.className = 'inline-confirm alert alert-warning show';
            confirmBox.innerHTML = `
                ${message}
                <div class="btn-group mt-2">
                    <button class="btn btn-sm btn-primary confirm-yes">确认</button>
                    <button class="btn btn-sm btn-secondary confirm-no">取消</button>
                </div>
            `;

            this.parentNode.appendChild(confirmBox);

            // 确认按钮事件
            confirmBox.querySelector('.confirm-yes').addEventListener('click', function() {
                if (action) {
                    window.location.href = action;
                }
                confirmBox.remove();
            });

            // 取消按钮事件
            confirmBox.querySelector('.confirm-no').addEventListener('click', function() {
                confirmBox.remove();
            });
        });
    });
});