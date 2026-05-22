from fastapi import APIRouter, HTTPException, Depends, Response, Request, Form, Header, Query
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Union
from datetime import datetime, timedelta
import json
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse

from ..config import config
from ..database import (
    UserDB, SessionDB, AuthCodeDB, AppDB, UserAuthorizationDB, UserCustomDataDB, CustomFieldDB
)
from ..auth import (
    generate_session_token, generate_authorization_code, create_access_token, verify_jwt_token
)
from ..performance import cache, CacheManager

from ..dependencies import templates, get_current_user, require_login

router = APIRouter()


def _append_query_params(url: str, params: dict) -> str:
    """安全地向 URL 追加查询参数，兼容 redirect_uri 已自带 query 的情况。"""
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key, value in params.items():
        if value is not None:
            query[key] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


@router.get("/oauth/authorize", name="authorize_page")
async def authorize_page(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str = "code",
    scope: str = "openid profile email",
    state: Optional[str] = Query(None),
    current_user: Optional[dict] = Depends(get_current_user)
):
    """OAuth 2.0 授权页面"""
    
    # 1-4. 验证逻辑保持不变...
    if response_type != "code":
        return RedirectResponse(url=build_error_redirect(
            redirect_uri, "unsupported_response_type", "不支持的 response_type", state
        ), status_code=302)
    
    # 增加缓存，TTL 设为 600 秒
    app_info = cache(ttl=600)(AppDB.get_app_by_client_id)(client_id)
    if not app_info:
        raise HTTPException(status_code=400, detail="无效的 client_id")
    
    try:
        allowed_uris = json.loads(app_info["redirect_uris"])
    except:
        allowed_uris = []
    if redirect_uri not in allowed_uris:
        raise HTTPException(status_code=400, detail="无效的 redirect_uri")
    
    # 5. 检查用户是否登录
    if not current_user:
        login_url = request.url_for("login_page").path
        oauth_params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope,
            "state": state
        }
        redirect_to_login = f"{login_url}?{urlencode(oauth_params)}"
        return RedirectResponse(url=redirect_to_login, status_code=302)
    
    # 6. 获取所有活跃会话
    all_sessions = SessionDB.get_active_sessions()
    
    # 7. 检查是否已授权（仅用于在页面上标记状态，不自动跳过）
    is_authorized = UserAuthorizationDB.check_authorization(current_user["id"], client_id)
    
    # 8. 解析 scope 并分类
    scopes = [s.strip() for s in scope.split(' ') if s.strip()]
    
    # 定义基础必选 scope（这些将被锁定为必选）
    base_scopes = ["openid", "profile", "email"]
    
    # 分离基础 scope 和额外字段
    base_scopes_to_show = {}
    extra_scopes_to_show = {}
    oauth_fields = []
    
    for s in scopes:
        if s.startswith("field:"):
            # 自定义字段
            field_key = s.split(":", 1)[1]
            field_info = CustomFieldDB.get_field_by_key(field_key)
            if field_info and field_info.get("show_in_oauth"):
                oauth_fields.append(field_info)
        else:
            # 预定义 scope
            if s in config.AVAILABLE_SCOPES:
                if s in base_scopes:
                    base_scopes_to_show[s] = config.AVAILABLE_SCOPES[s]
                else:
                    extra_scopes_to_show[s] = config.AVAILABLE_SCOPES[s]
    
    # 获取所有标记为 show_in_oauth 的自定义字段
    all_custom_fields = CustomFieldDB.get_all_fields()
    available_oauth_fields = [f for f in all_custom_fields if f.get("show_in_oauth")]
    
    # 9. 显示授权页面（首次授权）
    context = {
        "request": request,
        "app_name": app_info["app_name"],
        "app_description": app_info.get("description"),
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "current_user": current_user,
        "all_sessions": all_sessions,
        "already_authorized": is_authorized,
        "base_scopes": base_scopes_to_show,
        "extra_scopes": extra_scopes_to_show,
        "oauth_fields": available_oauth_fields,
        "requested_field_keys": [s.split(":", 1)[1] for s in scopes if s.startswith("field:")]
    }
    return templates.TemplateResponse(request=request, name="authorize.html", context=context)


@router.post("/oauth/authorize/confirm")
async def authorize_confirm(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(...),
    state: Optional[str] = Form(None),
    user_id: int = Form(None),
    action: str = Form(...)              # "authorize" or "cancel"
):
    """处理用户在授权页面的 POST 提交"""
    
    # 1. 验证 client_id 和 redirect_uri
    app_info = cache(ttl=600)(AppDB.get_app_by_client_id)(client_id)
    if not app_info:
        return RedirectResponse(url=build_error_redirect(
            redirect_uri, "invalid_request", "无效的 client_id", state
        ), status_code=302)
    
    try:
        allowed_uris = json.loads(app_info["redirect_uris"])
    except:
        allowed_uris = []
    if redirect_uri not in allowed_uris:
        return RedirectResponse(url=build_error_redirect(
            redirect_uri, "invalid_request", "无效的 redirect_uri", state
        ), status_code=302)
    
    # 2. 处理取消授权
    if action == "cancel":
        return RedirectResponse(url=build_error_redirect(
            redirect_uri, "access_denied", "用户取消授权", state
        ), status_code=302)
    
    # 3. 验证用户 ID
    if not user_id:
        login_url = request.url_for("login_page").path
        oauth_params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": state
        }
        redirect_to_login = f"{login_url}?{urlencode(oauth_params)}"
        return RedirectResponse(url=redirect_to_login, status_code=302)
    
    # 4. 检查用户是否切换了账户
    current_user_cookie = request.cookies.get("session_token")
    current_session = SessionDB.get_session(current_user_cookie)
    
    if current_session and current_session["user_id"] != user_id:
        # 用户选择了其他账户，需要切换会话
        selected_session = SessionDB.get_latest_session_by_user_id(user_id)
        
        if selected_session:
            # 切换会话后重定向到授权页面（GET请求）
            # 切换会话后重定向回授权页，state 必须无条件带上
            oauth_params = {
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'response_type': 'code',
                'scope': scope,
                'state': state,
            }
            authorize_url = f"/oauth/authorize?{urlencode(oauth_params)}"
            response = RedirectResponse(url=authorize_url, status_code=302)
            response.set_cookie(
                key="session_token",
                value=selected_session["session_token"],
                max_age=config.SESSION_EXPIRE_DAYS * 24 * 60 * 60,
                path="/",
                httponly=True,
                samesite="lax",
                secure=config.COOKIE_SECURE
            )
            return response
        else:
            return RedirectResponse(url=build_error_redirect(
                redirect_uri, "server_error", "找不到用户会话，请重新登录", state
            ), status_code=302)

    # 5. 记录用户授权 - 修复：使用正确的方法名
    UserAuthorizationDB.create_authorization(user_id, client_id, scope)
    
    # 6. 生成授权码
    code = generate_authorization_code()
    expires_at = datetime.utcnow() + timedelta(minutes=config.AUTHORIZATION_CODE_EXPIRE_MINUTES)
    
    AuthCodeDB.create_auth_code(
        code=code,
        user_id=user_id,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        expires_at=expires_at
    )
    
    # 7. state 必须原样带回，不能被 if v 过滤
    return RedirectResponse(
        url=_append_query_params(redirect_uri, {"code": code, "state": state}),
        status_code=302,
    )

def build_error_redirect(redirect_uri: str, error: str, error_description: str, state: Optional[str] = None) -> str:
    """构建 OAuth 错误重定向 URL。"""
    return _append_query_params(
        redirect_uri,
        {
            "error": error,
            "error_description": error_description,
            "state": state,
        },
    )

@router.post("/oauth/token")
async def get_token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    redirect_uri: Optional[str] = Form(None),
    code: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None)
):
    """获取访问令牌"""
    
    # 1. 验证 client_id 和 client_secret
    app_info = cache(ttl=600)(AppDB.get_app_by_client_id)(client_id)
    if not app_info or app_info["client_secret"] != client_secret:
        raise HTTPException(
            status_code=401, 
            detail={"error": "invalid_client", "error_description": "无效的 client_id 或 client_secret"}
        )
    
    # 2. 验证 grant_type
    if grant_type == "authorization_code":
        if not code or not redirect_uri:
            raise HTTPException(
                status_code=400, 
                detail={"error": "invalid_request", "error_description": "缺少 code 或 redirect_uri"}
            )
        
        # 3. 验证授权码
        auth_code_info = AuthCodeDB.get_auth_code(code, client_id)
        if not auth_code_info or auth_code_info["client_id"] != client_id or auth_code_info["redirect_uri"] != redirect_uri:
            raise HTTPException(
                status_code=400, 
                detail={"error": "invalid_grant", "error_description": "无效的授权码"}
            )
        
        # 4. 检查授权码是否过期
        # 数据库中存储的是字符串，需要转换为 datetime 对象
        expires_at = datetime.strptime(auth_code_info["expires_at"], config.DATETIME_FORMAT)
        if expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=400, 
                detail={"error": "invalid_grant", "error_description": "授权码已过期"}
            )
        
        # 5. 销毁授权码 (一次性使用)
        AuthCodeDB.delete_auth_code(code)
        
        # 6. 生成 Access Token 和 Refresh Token
        user_id = auth_code_info["user_id"]
        scope = auth_code_info["scope"]
        
        access_token = create_access_token(user_id=user_id, client_id=client_id, scope=scope, token_type="access")
        refresh_token = create_access_token(user_id=user_id, client_id=client_id, scope=scope, token_type="refresh")
        
        # 7. 存储 Refresh Token
        oauth_session_token = generate_session_token()

        
        # 计算过期时间
        expires_at = datetime.utcnow() + timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)

        SessionDB.create_session(
            user_id=user_id,
            session_token=generate_session_token(),  # 仍然随机生成
            refresh_token=refresh_token,
            expires_at=expires_at,      # ← 添加这个参数
            client_id=client_id,        # ← 新增
            scope=scope                 # ← 新增
        )
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_token": refresh_token,
            "scope": scope
        }
        
    elif grant_type == "refresh_token":
        if not refresh_token:
            raise HTTPException(
                status_code=400, 
                detail={"error": "invalid_request", "error_description": "缺少 refresh_token"}
            )
        
        # 3. 验证 Refresh Token
        try:
            payload = verify_jwt_token(refresh_token)
            if payload["token_type"] != "refresh" or payload["client_id"] != client_id:
                raise ValueError("无效的 refresh token 类型或 client_id")
        except:
            raise HTTPException(
                status_code=401, 
                detail={"error": "invalid_grant", "error_description": "无效的 refresh token"}
            )
            
        # 4. 检查 Refresh Token 是否在数据库中
        session = SessionDB.get_session_by_refresh_token(refresh_token)
        if not session:
            raise HTTPException(
                status_code=401, 
                detail={"error": "invalid_grant", "error_description": "refresh token 已被撤销或不存在"}
            )
            
        # 5. 生成新的 Access Token
        user_id = int(payload["sub"])
        scope = payload["scope"]
        
        access_token = create_access_token(user_id=user_id, client_id=client_id, scope=scope, token_type="access")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": config.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "refresh_token": refresh_token, # refresh token 不变
            "scope": scope
        }
        
    else:
        raise HTTPException(
            status_code=400, 
            detail={"error": "unsupported_grant_type", "error_description": "不支持的 grant_type"}
        )

@router.get("/oauth/userinfo")
async def get_userinfo(authorization: Optional[str] = Header(None)):
    """
    OAuth 2.0 UserInfo 端点
    根据 access_token 返回用户信息
    """
    # 1. 提取 Bearer Token
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "error_description": "缺少或无效的 Authorization header"}
        )
    
    access_token = authorization.replace("Bearer ", "")
    
    # 2. 验证 access_token
    try:
        payload = verify_jwt_token(access_token)
        if not payload or payload.get("token_type") != "access":
            raise ValueError("Invalid token type")
    except:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "error_description": "无效的 access_token"}
        )
    
    # 3. 获取用户信息
    user_id = int(payload["sub"])
    user = UserDB.get_user_by_id(user_id)
    
    if not user:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "error_description": "access_token 对应的用户不存在或已失效"}
        )
    
    # 4. 获取自定义字段数据
    custom_data = UserCustomDataDB.get_all_user_data(user_id)
    
    # 5. 合并用户数据
    user_data = {
        "id": user["id"],
        "external_id": user.get("external_id"),
        "email": user["email"],
        "name": user["name"],
        "username": user.get("username"),
        "avatar_url": user.get("avatar_url"),
        **custom_data  # 添加自定义字段
    }
    
    # 6. 根据 scope 过滤数据
    from ..auth import filter_user_data_by_scope
    scope = payload.get("scope", config.DEFAULT_SCOPE)
    filtered_data = filter_user_data_by_scope(user_data, scope)
    
    return filtered_data

# 删除旧的 Form 格式的路由
# @router.post("/api/admin/fields/add") - 已替换为上面的 POST /api/admin/fields
# @router.post("/api/admin/fields/delete") - 已替换为上面的 DELETE /api/admin/fields/{field_key}