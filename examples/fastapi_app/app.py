"""
FastAPI 示例应用 - 集成 SSO 认证
"""
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
import sys
import os

# 添加父目录到路径以导入 sso_client
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from sso_client import FastAPISSOClient

app = FastAPI(title="FastAPI SSO 示例应用")

# 添加 Session 中间件
app.add_middleware(SessionMiddleware, secret_key="your-fastapi-secret-key-change-in-production")

# 初始化 SSO 客户端
sso = FastAPISSOClient(
    client_id=os.getenv('SSO_CLIENT_ID', 'your_client_id'),
    client_secret=os.getenv('SSO_CLIENT_SECRET', 'your_client_secret'),
    auth_server=os.getenv('SSO_AUTH_SERVER', 'http://localhost:8000'),
    redirect_uri=os.getenv('SSO_REDIRECT_URI', 'http://localhost:5002/callback')
)

# HTML 模板
INDEX_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>FastAPI SSO 示例</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }}
        .card {{
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .btn {{
            display: inline-block;
            padding: 10px 20px;
            background-color: #1a73e8;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            margin: 5px;
        }}
        .btn:hover {{
            background-color: #1557b0;
        }}
        .btn-secondary {{
            background-color: #6c757d;
        }}
        .btn-secondary:hover {{
            background-color: #5a6268;
        }}
        .user-info {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 4px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>FastAPI SSO 示例应用</h1>

        {user_section}
    </div>
</body>
</html>
"""

PROTECTED_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>受保护页面 - FastAPI SSO 示例</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }}
        .card {{
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .btn {{
            display: inline-block;
            padding: 10px 20px;
            background-color: #1a73e8;
            color: white;
            text-decoration: none;
            border-radius: 4px;
        }}
        .alert {{
            padding: 15px;
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 4px;
            margin: 20px 0;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>受保护页面</h1>

        <div class="alert">
            <strong>✓ 认证成功!</strong> 这是一个需要登录才能访问的页面。
        </div>

        <p>当前登录用户: <strong>{user_name}</strong></p>

        <a href="/" class="btn">返回首页</a>
    </div>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """首页"""
    user = await sso.get_current_user(request)

    if user:
        user_section = f"""
            <div class="user-info">
                <h2>欢迎, {user['name']}!</h2>
                <p><strong>邮箱:</strong> {user['email']}</p>
                <p><strong>用户 ID:</strong> {user['id']}</p>
            </div>

            <div>
                <a href="/protected" class="btn">访问受保护页面</a>
                <a href="/api/user" class="btn">查看用户 API</a>
                <a href="/logout" class="btn btn-secondary">注销</a>
            </div>
        """
    else:
        user_section = """
            <p>您尚未登录。请点击下方按钮通过 SSO 登录。</p>
            <a href="/login" class="btn">使用 SSO 登录</a>
        """

    return INDEX_TEMPLATE.format(user_section=user_section)

@app.get("/login")
async def login():
    """登录 - 重定向到 SSO 认证中心"""
    auth_url = sso.get_authorization_url()
    return RedirectResponse(url=auth_url)

@app.get("/callback")
async def callback(request: Request, code: str, state: str = None):
    """OAuth 回调处理"""
    try:
        await sso.handle_callback(request, code, state)
        return RedirectResponse(url="/")
    except Exception as e:
        return HTMLResponse(
            content=f"<h1>登录失败</h1><p>{str(e)}</p><a href='/'>返回首页</a>",
            status_code=400
        )

@app.get("/protected", response_class=HTMLResponse)
async def protected(user: dict = Depends(sso.require_login)):
    """受保护的页面 - 需要登录"""
    return PROTECTED_TEMPLATE.format(user_name=user['name'])

@app.get("/api/user")
async def get_user_api(user: dict = Depends(sso.require_login)):
    """受保护的 API - 返回用户信息"""
    return {
        "message": "认证成功",
        "user": user
    }

@app.get("/logout")
async def logout(request: Request):
    """注销"""
    await sso.logout(request)
    return RedirectResponse(url="/")

if __name__ == "__main__":
    import uvicorn

    print("=" * 60)
    print("FastAPI SSO 示例应用")
    print("=" * 60)
    print(f"应用地址: http://localhost:5002")
    print(f"API 文档: http://localhost:5002/docs")
    print(f"SSO 服务器: {sso.auth_server}")
    print(f"Client ID: {sso.client_id}")
    print("=" * 60)
    print("\n请确保:")
    print("1. SSO 认证中心已启动 (默认 http://localhost:8000)")
    print("2. 已在认证中心注册此应用并获得 client_id 和 client_secret")
    print("3. 回调地址已添加到应用的白名单中")
    print("\n")

    uvicorn.run(app, host="0.0.0.0", port=5002)
