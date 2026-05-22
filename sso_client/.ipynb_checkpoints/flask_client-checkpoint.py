"""
Flask SSO 客户端 SDK - 修复版本
"""
import requests
from functools import wraps
from flask import redirect, request, session, url_for, abort
from typing import Optional, Callable
import secrets

class FlaskSSOClient:
    """Flask SSO 客户端"""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        auth_server: str,
        redirect_uri: str,
        scope: str = "openid profile email"
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_server = auth_server.rstrip('/')
        self.redirect_uri = redirect_uri
        self.scope = scope

    def get_authorization_url(self, state: Optional[str] = None) -> str:
        """获取授权 URL"""
        if not state:
            state = secrets.token_urlsafe(32)
            session['oauth_state'] = state

        params = {
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'scope': self.scope,
            'state': state
        }

        query_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        return f"{self.auth_server}/oauth/authorize?{query_string}"

    def exchange_code_for_token(self, code: str) -> dict:
        """用授权码换取访问令牌"""
        token_url = f"{self.auth_server}/oauth/token"

        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': self.redirect_uri
        }

        response = requests.post(token_url, data=data)

        if response.status_code != 200:
            raise Exception(f"Token exchange failed: {response.text}")

        return response.json()

    def get_user_info(self, access_token: str) -> dict:
        """
        使用 access_token 获取用户信息

        Args:
            access_token: 访问令牌

        Returns:
            用户信息字典
        """
        userinfo_url = f"{self.auth_server}/oauth/userinfo"

        headers = {
            'Authorization': f'Bearer {access_token}'
        }

        response = requests.get(userinfo_url, headers=headers)

        if response.status_code != 200:
            raise Exception(f"Failed to get user info: {response.text}")

        return response.json()

    def verify_token(self, access_token: str) -> dict:
        """验证访问令牌（保持向后兼容）"""
        return self.get_user_info(access_token)

    def get_user(self) -> Optional[dict]:
        """获取当前登录用户"""
        return session.get('user')

    def login_required(self, f: Callable) -> Callable:
        """登录装饰器"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user' not in session:
                session['next_url'] = request.url
                return redirect(self.get_authorization_url())
            return f(*args, **kwargs)
        return decorated_function

    def handle_callback(self):
        """
        处理 OAuth 回调
        """
        # 检查错误
        error = request.args.get('error')
        if error:
            error_description = request.args.get('error_description', 'Unknown error')
            raise Exception(f"Authorization failed: {error} - {error_description}")

        # 验证 state
        state = request.args.get('state')
        if state != session.get('oauth_state'):
            raise Exception("Invalid state parameter")

        # 获取授权码
        code = request.args.get('code')
        if not code:
            raise Exception("No authorization code received")

        # 交换令牌
        token_data = self.exchange_code_for_token(code)

        # 检查返回的数据结构
        if 'access_token' not in token_data:
            raise Exception("No access_token in response")

        access_token = token_data['access_token']

        # 使用 access_token 获取用户信息
        user_info = self.get_user_info(access_token)

        # 保存用户信息和令牌
        session['user'] = user_info
        session['access_token'] = access_token
        session['refresh_token'] = token_data.get('refresh_token')

        # 清理 state
        session.pop('oauth_state', None)

        return user_info

    def logout(self):
        """注销登录"""
        session.pop('user', None)
        session.pop('access_token', None)
        session.pop('refresh_token', None)
        session.pop('next_url', None)

    def init_app(self, app):
        """初始化 Flask 应用"""
        if not app.secret_key:
            raise ValueError("Flask app must have a secret_key set")

        @app.route('/sso/callback')
        def sso_callback():
            try:
                self.handle_callback()
                next_url = session.pop('next_url', '/')
                return redirect(next_url)
            except Exception as e:
                return f"登录失败: {str(e)}", 400