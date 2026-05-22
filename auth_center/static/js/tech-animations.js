/**
 * SSO 平台科技感动画脚本
 * 实现二进制雨、动态数据流等效果
 */

function initMatrixRain(containerSelector) {
    const container = document.querySelector(containerSelector);
    if (!container) return;

    const width = container.offsetWidth;
    const columnCount = Math.floor(width / 20);

    for (let i = 0; i < columnCount; i++) {
        const column = document.createElement('div');
        column.className = 'matrix-column';
        column.style.left = (i * 20) + 'px';

        // 随机动画参数
        const duration = 5 + Math.random() * 10;
        const delay = Math.random() * 5;
        column.style.animationDuration = duration + 's';
        column.style.animationDelay = delay + 's';

        // 生成随机二进制字符串
        let content = '';
        const rows = 20 + Math.floor(Math.random() * 30);
        for (let j = 0; j < rows; j++) {
            content += Math.round(Math.random()) + '<br>';
        }
        column.innerHTML = content;

        container.appendChild(column);
    }
}

function initDataStreams() {
    const containers = document.querySelectorAll('.tech-data-container');
    containers.forEach(container => {
        for (let i = 0; i < 5; i++) {
            const stream = document.createElement('div');
            stream.className = 'data-stream';
            stream.style.top = Math.random() * 100 + '%';
            stream.style.left = Math.random() * 100 + '%';

            const hex = '0123456789ABCDEF';
            let text = '0x';
            for (let j = 0; j < 8; j++) text += hex[Math.floor(Math.random() * 16)];
            stream.textContent = text;

            container.appendChild(stream);
        }
    });
}

function initTerminalEffect() {
    const lines = document.querySelectorAll('.terminal-line[data-type]');
    lines.forEach(line => {
        const text = line.getAttribute('data-type');
        line.textContent = '> ';
        let i = 0;
        const type = () => {
            if (i < text.length) {
                line.textContent += text.charAt(i);
                i++;
                setTimeout(type, 50 + Math.random() * 100);
            }
        };
        setTimeout(type, 500 + Math.random() * 1000);
    });
}

// 自动初始化
document.addEventListener('DOMContentLoaded', function() {
    // 如果页面有 matrix-bg 容器，则初始化
    if (document.querySelector('.matrix-bg')) {
        initMatrixRain('.matrix-bg');
    }

    initDataStreams();
    initTerminalEffect();
});
