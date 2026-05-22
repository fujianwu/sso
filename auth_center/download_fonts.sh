#!/bin/bash
# 下载 SSO 认证中心所需的本地字体（Inter）
# 在 auth_center 目录下执行

set -e
mkdir -p static/fonts

echo "正在下载 Inter 字体..."
BASE="https://github.com/rsms/inter/raw/v4.0/docs/font-files"
for variant in Regular Medium SemiBold Bold ExtraBold; do
  echo "  Inter-${variant}.woff2"
  curl -fL -o "static/fonts/Inter-${variant}.woff2" \
    "${BASE}/Inter-${variant}.woff2" || \
  curl -fL -o "static/fonts/Inter-${variant}.woff2" \
    "https://rsms.me/inter/font-files/Inter-${variant}.woff2"
done
echo "完成！字体文件已保存到 static/fonts/"
