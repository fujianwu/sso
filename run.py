"""
SSO认证中心启动脚本
使用:
  python run.py              # 开发模式（自动重载）
  python run.py --production # 生产模式
  python run.py --help       # 查看帮助
"""
import uvicorn
import sys
import os
import argparse
from pathlib import Path

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def cleanup_db_locks():
    """清理数据库锁文件"""
    project_root = Path(__file__).resolve().parent
    lock_files = [
        project_root / "sso_auth.db-shm",
        project_root / "sso_auth.db-wal",
        project_root / "sso_auth.db-journal",
    ]

    cleaned = []
    for lock_file in lock_files:
        if lock_file.exists():
            try:
                lock_file.unlink()
                cleaned.append(lock_file.name)
            except Exception as e:
                pass  # 静默处理删除失败的情况

    if cleaned:
        print(f"已清理数据库锁文件: {', '.join(cleaned)}")

if __name__ == "__main__":
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='SSO认证中心启动脚本')
    parser.add_argument('--production', '-p', action='store_true',
                        help='生产模式（关闭自动重载）')
    parser.add_argument('--port', type=int, default=8200,
                        help='服务端口（默认: 8200）')
    parser.add_argument('--host', type=str, default='0.0.0.0',
                        help='监听地址（默认: 0.0.0.0）')
    args = parser.parse_args()

    # 清理数据库锁文件
    cleanup_db_locks()

    print("=" * 70)
    print(" " * 20 + "SSO 认证中心")
    print("=" * 70)
    print(f"运行模式: {'生产模式' if args.production else '开发模式（自动重载）'}")
    print("-" * 70)
    print(f"访问地址: http://127.0.0.1:{args.port}")
    print(f"首页: http://127.0.0.1:{args.port}/")
    print(f"用户中心: http://127.0.0.1:{args.port}/account")
    print(f"管理后台: http://127.0.0.1:{args.port}/admin")
    print(f"API文档: http://127.0.0.1:{args.port}/docs")
    print("-" * 70)
    print("默认管理员: admin@sso.local / admin123456")
    print("=" * 70)
    print("\n✓ 服务器正在启动中...")
    if not args.production:
        print("✓ 文件监控已启用，代码更改将自动重载")
    print("✓ 按 Ctrl+C 停止服务器\n")
    print("⚠ 注意: 服务器启动后会保持运行状态，这是正常的！")
    print("  你可以在浏览器中访问上面的地址，服务器会在后台处理请求。\n")
    print("=" * 70)

    try:
        uvicorn_config = {
            "app": "auth_center.main:app",
            "host": args.host,
            "port": args.port,
            "reload": not args.production,
        }

        if not args.production:
            uvicorn_config["reload_dirs"] = [os.path.dirname(os.path.abspath(__file__))]

        uvicorn.run(**uvicorn_config)
    except KeyboardInterrupt:
        print("\n\n" + "=" * 70)
        print(" " * 20 + "服务器已停止")
        print("=" * 70)
        sys.exit(0)
    except Exception as e:
        print("\n" + "=" * 70)
        print(f"✗ 启动失败: {e}")
        print("=" * 70)
        print("\n可能的原因:")
        print("  1. 数据库被其他程序锁定")
        print(f"  2. 端口 {args.port} 已被占用")
        print("  3. 数据库文件损坏")
        print("\n解决方法:")
        print("  • 关闭所有访问 sso_auth.db 的程序")
        print("  • 手动删除 sso_auth.db-shm 和 sso_auth.db-wal 文件")
        print(f"  • 检查是否有其他进程占用了端口 {args.port}")
        print("  • 运行 'python cleanup_db_locks.py' 清理数据库锁")
        print("=" * 70)
        sys.exit(1)
