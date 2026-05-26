"""
FastAPI SSO 客户端 SDK
"""
import requests
from fastapi import Request, HTTPException, Depends
from fastapi.responses import RedirectResponse
from typing import Optional
import secrets

class FastAPISSOClient:
    """FastAPI SSO 客户端"""
    
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        auth_server: str,
        redirect_uri: str,
        scope: str = "basic"
    ):
        """
        初始化 FastAPI SSO 客户端
        
        Args:
            client_id: 客户端 ID
            client_secret: 客户端密钥
            auth_server: 认证服务器地址 (例如: http://localhost:8000)
            redirect_uri: 回调地址 (例如: http://localhost:5000/callback)
            scope: 权限范围
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_server = auth_server.rstrip('/')
        self.redirect_uri = redirect_uri
        self.scope = scope
        self._user_cache = {}  # 简单的用户缓存
    
    def get_authorization_url(self, state: Optional[str] = None) -> str:
        """
        获取授权 URL
        
        Args:
            state: 状态参数,用于防止 CSRF 攻击
            
        Returns:
            授权 URL
        """
        if not state:
            state = secrets.token_urlsafe(32)
        
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
        """
        用授权码换取访问令牌
        
        Args:
            code: 授权码
            
        Returns:
            包含 access_token 和用户信息的字典
        """
        token_url = f"{self.auth_server}/oauth/token"
        
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_uri': self.redirect_uri
        }
        
        # OAuth 2.0 规范要求使用 application/x-www-form-urlencoded，即 requests 的 data 参数
        response = requests.post(token_url, data=data)
        
        if response.status_code != 200:
            raise HTTPException(status_code=400, detail=f"Token exchange failed: {response.text}")
        
        return response.json()
    
    def get_user_info(self, access_token: str) -> dict:
        """
        使用 access_token 获取用户信息
        
        Args:
            access_token: 访问令牌
            
        Returns:
            用户信息字典
        """
        # 检查缓存
        if access_token in self._user_cache:
            return self._user_cache[access_token]
        
        userinfo_url = f"{self.auth_server}/oauth/userinfo"
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(userinfo_url, headers=headers)
        
        if response.status_code != 200:
            raise HTTPException(status_code=401, detail=f"Failed to get user info: {response.text}")
        
        user = response.json()
        
        # 缓存用户信息
        self._user_cache[access_token] = user
        
        return user

    def verify_token(self, access_token: str) -> dict:
        """
        验证访问令牌（调用 get_user_info 获取用户信息）
        
        Args:
            access_token: 访问令牌
            
        Returns:
            用户信息
        """
        return self.get_user_info(access_token)
    
    async def get_current_user(self, request: Request) -> Optional[dict]:
        """
        获取当前登录用户(依赖注入)
        
        用法:
            @app.get('/protected')
            async def protected_route(user: dict = Depends(sso.get_current_user)):
                if not user:
                    raise HTTPException(status_code=401, detail="Not authenticated")
                return {"message": f"Hello {user['name']}"}
        """
        # 从 session 中获取 access_token
        access_token = request.session.get('access_token')
        
        if not access_token:
            return None
        
        try:
            user = self.verify_token(access_token)
            return user
        except:
            return None
    
    async def require_login(self, request: Request) -> dict:
        """
        要求登录(依赖注入)
        
        用法:
            @app.get('/protected')
            async def protected_route(user: dict = Depends(sso.require_login)):
                return {"message": f"Hello {user['name']}"}
        """
        user = await self.get_current_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return user
    
    def login_required(self):
        """
        登录装饰器(返回依赖函数)
        
        用法:
            @app.get('/protected')
            async def protected_route(user: dict = Depends(sso.login_required())):
                return {"message": f"Hello {user['name']}"}
        """
        return self.require_login
    
    async def handle_callback(self, request: Request, code: str, state: Optional[str] = None):
        """
        处理 OAuth 回调
        
        Args:
            request: FastAPI Request 对象
            code: 授权码
            state: 状态参数
            
        Returns:
            用户信息
        """
        if not code:
            raise HTTPException(status_code=400, detail="No authorization code received")
        
        # 交换令牌
        token_data = self.exchange_code_for_token(code)
        
        if 'access_token' not in token_data:
            raise HTTPException(status_code=400, detail=f"Token exchange failed: {token_data}")
        
        access_token = token_data['access_token']
        
        # 使用 access_token 获取用户信息
        user_info = self.get_user_info(access_token)
        
        # 保存用户信息和令牌到 session
        request.session['user'] = user_info
        request.session['access_token'] = access_token
        if 'refresh_token' in token_data:
            request.session['refresh_token'] = token_data['refresh_token']
        
        return user_info
    
    async def logout(self, request: Request):
        """
        注销登录
        
        用法:
            @app.get('/logout')
            async def logout(request: Request):
                await sso.logout(request)
                return RedirectResponse(url='/')
        """
        request.session.pop('user', None)
        request.session.pop('access_token', None)
        
        # 清理缓存
        access_token = request.session.get('access_token')
        if access_token and access_token in self._user_cache:
            del self._user_cache[access_token]
