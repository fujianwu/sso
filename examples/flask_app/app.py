"""
Flask 示例应用 - 集成 SSO 认证
"""
from flask import Flask, render_template_string, redirect, url_for, session
import sys
import os

# 添加父目录到路径以导入 sso_client
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from sso_client import FlaskSSOClient

app = Flask(__name__)
app.secret_key = 'your-flask-secret-key-change-in-production'

# 初始化 SSO 客户端
sso = FlaskSSOClient(
    client_id=os.getenv('SSO_CLIENT_ID', 'app_sl-i__SR8UF-f13hKro-uQ'),
    client_secret=os.getenv('SSO_CLIENT_SECRET', 'ILRedP9f2pxPL8wgRklsX0kmH80ROeM1lY6SK4wRxnM'),
    auth_server=os.getenv('SSO_AUTH_SERVER', 'http://192.168.1.220:8000'),
    redirect_uri=os.getenv('SSO_REDIRECT_URI', 'http://localhost:5001/callback')
)

# HTML 模板
INDEX_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Flask SSO 示例</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }
        .card {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            background-color: #1a73e8;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            margin: 5px;
        }
        .btn:hover {
            background-color: #1557b0;
        }
        .btn-secondary {
            background-color: #6c757d;
        }
        .btn-secondary:hover {
            background-color: #5a6268;
        }
        .user-info {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 4px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="card">
        <h1>Flask SSO 示例应用</h1>

        {% if user %}
            <div class="user-info">
                <h2>欢迎, {{ user.name }}!</h2>
                <p><strong>邮箱:</strong> {{ user.email }}</p>
                <p><strong>用户 ID:</strong> {{ user.id }}</p>
            </div>

            <div>
                <a href="{{ url_for('protected') }}" class="btn">访问受保护页面</a>
                <a href="{{ url_for('logout') }}" class="btn btn-secondary">注销</a>
            </div>
        {% else %}
            <p>您尚未登录。请点击下方按钮通过 SSO 登录。</p>
            <a href="{{ url_for('login') }}" class="btn">使用 SSO 登录</a>
        {% endif %}
    </div>
</body>
</html>
"""

PROTECTED_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>受保护页面 - Flask SSO 示例</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }
        .card {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .btn {
            display: inline-block;
            padding: 10px 20px;
            background-color: #1a73e8;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }
        .alert {
            padding: 15px;
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 4px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="card">
        <h1>受保护页面</h1>

        <div class="alert">
            <strong>✓ 认证成功!</strong> 这是一个需要登录才能访问的页面。
        </div>

        <p>当前登录用户: <strong>{{ user.name }}</strong></p>

        <a href="{{ url_for('index') }}" class="btn">返回首页</a>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    """首页"""
    user = sso.get_user()
    return render_template_string(INDEX_TEMPLATE, user=user)

@app.route('/login')
def login():
    """登录 - 重定向到 SSO 认证中心"""
    return redirect(sso.get_authorization_url())

@app.route('/callback')
def callback():
    """OAuth 回调处理"""
    try:
        sso.handle_callback()
        next_url = session.pop('next_url', '/')
        return redirect(next_url)
    except Exception as e:
        return f"<h1>登录失败</h1><p>{str(e)}</p><a href='/'>返回首页</a>", 400

@app.route('/protected')
@sso.login_required
def protected():
    """受保护的页面 - 需要登录"""
    user = sso.get_user()

    return render_template_string(PROTECTED_TEMPLATE, user=user)

@app.route('/logout')
def logout():
    """注销"""
    sso.logout()
    return redirect(url_for('index'))

if __name__ == '__main__':
    print("=" * 60)
    print("Flask SSO 示例应用")
    print("=" * 60)
    print(f"应用地址: http://localhost:5001")
    print(f"SSO 服务器: {sso.auth_server}")
    print(f"Client ID: {sso.client_id}")
    print("=" * 60)
    print("\n请确保:")
    print("1. SSO 认证中心已启动 (默认 http://localhost:8000)")
    print("2. 已在认证中心注册此应用并获得 client_id 和 client_secret")
    print("3. 回调地址已添加到应用的白名单中")
    print("\n")

    app.run(host='0.0.0.0', port=5001, debug=True)
