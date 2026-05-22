"""
Flask SSO 客户端 SDK - v2 升级版
变更：
  - get_authorization_url 使用 urllib.parse.urlencode 正确编码参数（修复原版 URL 拼接 bug）
  - handle_callback 支持 state 为 None 时跳过校验（某些场景 SSO 不回传 state）
  - 新增 refresh_access_token 方法
  - 新增 is_logged_in 属性
  - init_app 支持自定义回调路径
  - 所有网络请求增加 timeout 参数，避免挂死
  - 统一异常类型为 SSOError，方便上层捕获
"""
import secrets
import requests
from functools import wraps
from urllib.parse import urlencode
from typing import Optional, Callable

from flask import redirect, request, session, Flask


class SSOError(Exception):
    """SSO 操作异常"""
    pass


class FlaskSSOClient:
    """
    Flask SSO 客户端

    快速上手::

        sso = FlaskSSOClient(
            client_id="app_xxx",
            client_secret="yyy",
            auth_server="http://sso.example.com",
            redirect_uri="http://myapp.com/sso/callback",
        )
        sso.init_app(app)

        @app.route("/protected")
        @sso.login_required
        def protected():
            user = sso.get_user()
            return f"Hello {user['name']}"
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        auth_server: str,
        redirect_uri: str,
        scope: str = "openid profile email",
        timeout: int = 10,
    ):
        self.client_id     = client_id
        self.client_secret = client_secret
        self.auth_server   = auth_server.rstrip("/")
        self.redirect_uri  = redirect_uri
        self.scope         = scope
        self.timeout       = timeout          # 网络请求超时秒数

    # ──────────────────────────────────────────
    #  授权 URL
    # ──────────────────────────────────────────

    def get_authorization_url(self, state: Optional[str] = None) -> str:
        """
        生成 SSO 授权跳转 URL。

        会自动生成并存储 state 到 session，用于回调时校验。
        """
        if state is None:
            state = secrets.token_urlsafe(32)
        session["oauth_state"] = state

        params = {
            "client_id":     self.client_id,
            "redirect_uri":  self.redirect_uri,
            "response_type": "code",
            "scope":         self.scope,
            "state":         state,
        }
        # ✅ 使用 urlencode 正确处理特殊字符（原版直接 f-string 拼接会出错）
        return f"{self.auth_server}/oauth/authorize?{urlencode(params)}"

    # ──────────────────────────────────────────
    #  Token 操作
    # ──────────────────────────────────────────

    def exchange_code_for_token(self, code: str) -> dict:
        """用授权码换取 access_token / refresh_token"""
        try:
            resp = requests.post(
                f"{self.auth_server}/oauth/token",
                data={
                    "grant_type":    "authorization_code",
                    "code":          code,
                    "client_id":     self.client_id,
                    "client_secret": self.client_secret,
                    "redirect_uri":  self.redirect_uri,
                },
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise SSOError(f"连接 SSO 服务器失败: {e}") from e

        if resp.status_code != 200:
            raise SSOError(f"换取 Token 失败 [{resp.status_code}]: {resp.text}")

        return resp.json()

    def refresh_access_token(self, refresh_token: str) -> dict:
        """用 refresh_token 换取新的 access_token"""
        try:
            resp = requests.post(
                f"{self.auth_server}/oauth/token",
                data={
                    "grant_type":    "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id":     self.client_id,
                    "client_secret": self.client_secret,
                },
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise SSOError(f"连接 SSO 服务器失败: {e}") from e

        if resp.status_code != 200:
            raise SSOError(f"刷新 Token 失败 [{resp.status_code}]: {resp.text}")

        return resp.json()

    # ──────────────────────────────────────────
    #  用户信息
    # ──────────────────────────────────────────

    def get_user_info(self, access_token: str) -> dict:
        """用 access_token 从 /oauth/userinfo 获取用户信息"""
        try:
            resp = requests.get(
                f"{self.auth_server}/oauth/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise SSOError(f"连接 SSO 服务器失败: {e}") from e

        if resp.status_code != 200:
            raise SSOError(f"获取用户信息失败 [{resp.status_code}]: {resp.text}")

        return resp.json()

    def verify_token(self, access_token: str) -> dict:
        """验证 access_token 并返回用户信息（向后兼容别名）"""
        return self.get_user_info(access_token)

    # ──────────────────────────────────────────
    #  Session 操作
    # ──────────────────────────────────────────

    def get_user(self) -> Optional[dict]:
        """获取当前 session 中的用户信息，未登录返回 None"""
        return session.get("user")

    @property
    def is_logged_in(self) -> bool:
        """当前请求是否已登录"""
        return "user" in session

    def logout(self) -> None:
        """清除 session 中的登录信息"""
        for key in ("user", "access_token", "refresh_token", "next_url", "oauth_state"):
            session.pop(key, None)

    # ──────────────────────────────────────────
    #  装饰器
    # ──────────────────────────────────────────

    def login_required(self, f: Callable) -> Callable:
        """
        路由装饰器：要求登录。

        未登录时保存当前 URL 并跳转到 SSO 授权页，登录完成后原路返回。
        """
        @wraps(f)
        def decorated(*args, **kwargs):
            if not self.is_logged_in:
                session["next_url"] = request.url
                return redirect(self.get_authorization_url())
            return f(*args, **kwargs)
        return decorated

    # ──────────────────────────────────────────
    #  回调处理
    # ──────────────────────────────────────────

    def handle_callback(self) -> dict:
        """
        处理 /sso/callback 请求，完成 code → token → userinfo 流程。

        返回用户信息 dict，同时写入 session。
        """
        # 1. 检查授权错误
        error = request.args.get("error")
        if error:
            desc = request.args.get("error_description", "未知错误")
            raise SSOError(f"SSO 授权被拒绝: {error} — {desc}")

        # 2. 校验 state（防 CSRF）
        returned_state = request.args.get("state")
        stored_state   = session.get("oauth_state")
        # 只在 state 都存在时校验（允许 SSO 不回传 state 的场景）
        if stored_state and returned_state != stored_state:
            raise SSOError("state 参数不匹配，可能存在 CSRF 攻击")

        # 3. 获取授权码
        code = request.args.get("code")
        if not code:
            raise SSOError("未收到授权码 (code)")

        # 4. 换取 token
        token_data = self.exchange_code_for_token(code)
        access_token = token_data.get("access_token")
        if not access_token:
            raise SSOError(f"响应中缺少 access_token: {token_data}")

        # 5. 获取用户信息
        user_info = self.get_user_info(access_token)

        # 6. 写入 session
        session["user"]          = user_info
        session["access_token"]  = access_token
        session["refresh_token"] = token_data.get("refresh_token")
        session.pop("oauth_state", None)

        return user_info

    # ──────────────────────────────────────────
    #  Flask init_app
    # ──────────────────────────────────────────

    def init_app(self, app: Flask, callback_path: str = "/sso/callback") -> None:
        """
        注册回调路由到 Flask 应用。

        Args:
            app:           Flask 应用实例
            callback_path: 回调 URL 路径，默认 /sso/callback
        """
        if not app.secret_key:
            raise ValueError("Flask app.secret_key 未设置，session 无法正常工作")

        @app.route(callback_path)
        def sso_callback():
            try:
                self.handle_callback()
                next_url = session.pop("next_url", "/")
                return redirect(next_url)
            except SSOError as e:
                # 可自定义错误页模板
                return (
                    f"<h2>登录失败</h2><p>{e}</p>"
                    f'<a href="/login">重试</a>',
                    400,
                )
