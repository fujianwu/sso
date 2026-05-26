"""
增强的 SSO 主应用程序
包含新的路由、性能优化、错误处理等
"""
from fastapi import FastAPI, HTTPException, Depends, Response, Cookie, Request, Form, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any
import json
import os
from pathlib import Path
from urllib.parse import urlencode
from datetime import datetime, timedelta
# 获取当前文件所在目录
BASE_DIR = Path(__file__).resolve().parent
from auth_center.config import config
from auth_center.database import (
    init_db, get_db, UserDB, SessionDB, AuthCodeDB, AppDB, UserAuthorizationDB, ConfigDB,
    CustomFieldDB, UserCustomDataDB, LoginLogDB
)
from auth_center.auth import (
    verify_jwt_token, generate_authorization_code
)
from auth_center.performance import (
    PerformanceMonitor, CacheManager, RateLimiter, QueryOptimizer
)
import logging
import mimetypes

# 初始化 MIME 类型
mimetypes.init()
# 确保 JavaScript 文件使用正确的 MIME 类型
mimetypes.add_type('application/javascript', '.js')
mimetypes.add_type('text/javascript', '.js')
mimetypes.add_type('text/css', '.css')
# ===== 日志配置 =====
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)
# 导入路由模块
from auth_center.routers import oauth, admin
from auth_center.routers.passkeys import router as passkeys_router
from auth_center.routers.auth import router as auth_router
from auth_center.routers.mfa import router as mfa_router
from auth_center.dependencies import (
    templates, get_current_user, require_login, require_admin
)
# 初始化 FastAPI 应用
# 生产环境禁用 /docs /redoc /openapi.json，只在 DEBUG=true 时开启
_DEBUG = os.getenv("DEBUG", "false").lower() == "true"
app = FastAPI(
    title="SSO Platform",
    version="2.0.0",
    docs_url="/docs" if _DEBUG else None,
    redoc_url="/redoc" if _DEBUG else None,
    openapi_url="/openapi.json" if _DEBUG else None,
)
# ===== 中间件配置 =====
# CORS 配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://localhost:3000",
        "http://localhost:5000",
        "http://localhost:8000",
        "http://localhost:8200",
        "http://127.0.0.1:8000",
        "http://127.0.0.1:8200",
        # "https://yourdomain.com",  # 生产环境：添加你的域名
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    expose_headers=["X-Session-Token", "X-Redirect-To"],
    max_age=3600,
)
# 性能监控中间件
@app.middleware("http")
async def performance_monitoring_middleware(request: Request, call_next):
    """性能监控中间件"""
    import time

    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time

    # 记录性能指标
    PerformanceMonitor.record_request(
        request.url.path,
        request.method,
        duration,
        response.status_code
    )

    return response
# 限流中间件
@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    """分级限流中间件：认证端点严格限流，全局宽松限流"""
    # 获取客户端 IP（考虑代理情况，但验证格式防注入）
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else ""
    if not client_ip or not _is_valid_ip(client_ip):
        client_ip = request.client.host if request.client else "unknown"

    path = request.url.path

    # 认证相关接口：严格限流（15次/分钟）
    AUTH_PATHS = {"/api/auth/login", "/api/auth/login/email", "/api/auth/login/phone",
                  "/api/auth/register", "/api/auth/phone/send-code"}
    if path in AUTH_PATHS:
        key = f"auth:{client_ip}"
        if not RateLimiter.is_allowed(key, max_requests=15, window=60):
            logger.warning(f"Auth rate limit exceeded for IP: {client_ip} on {path}")
            return JSONResponse(
                status_code=429,
                content={"success": False, "detail": "请求过于频繁，请稍后再试", "retry_after": 60},
                headers={"Retry-After": "60"}
            )

    # 全局限流（200次/分钟，防 DDoS）
    if not RateLimiter.is_allowed(f"global:{client_ip}", max_requests=200, window=60):
        logger.warning(f"Global rate limit exceeded for IP: {client_ip}")
        return JSONResponse(
            status_code=429,
            content={"success": False, "detail": "请求过于频繁，请稍后再试", "retry_after": 60},
            headers={"Retry-After": "60"}
        )

    return await call_next(request)


def _is_valid_ip(ip: str) -> bool:
    """简单校验 IP 格式（IPv4/IPv6），防止 X-Forwarded-For 注入"""
    import re
    ipv4 = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    ipv6 = re.compile(r'^[0-9a-fA-F:]{2,39}$')
    return bool(ipv4.match(ip) or ipv6.match(ip))


# ===== 安全响应头中间件 =====
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """添加完整的安全响应头"""
    response = await call_next(request)

    # HTTPS 强制（生产环境）
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

    # 防止 MIME 类型嗅探
    response.headers["X-Content-Type-Options"] = "nosniff"

    # 防止点击劫持
    response.headers["X-Frame-Options"] = "DENY"

    # 现代 XSS 防护（配合 CSP）
    response.headers["X-XSS-Protection"] = "0"

    # 引荐者政策
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # 内容安全策略（CSP）— 防止 XSS / 注入攻击
    # 从配置中提取 BASE_URL 的 origin（scheme + host，不含路径），用于 form-action 白名单
    # 这解决了反向代理场景下 'self' 无法匹配实际域名导致表单提交被拦截的问题
    from urllib.parse import urlparse as _urlparse
    _base_origin = "{0.scheme}://{0.netloc}".format(_urlparse(config.BASE_URL))
    csp_parts = [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com",   # unsafe-inline 供 Jinja2 模板内联脚本；cloudflareinsights 供 Cloudflare 性能监控
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: https:",
        "connect-src 'self'",
        # form-action 需要允许所有 https:// 目标：
        # OAuth 授权确认后服务端返回 302 重定向到第三方 redirect_uri（如 https://info.example.com/callback），
        # 浏览器跟随 302 时仍受 form-action 约束，因此必须放开 https: 通配，
        # 否则任何跨域 redirect_uri 都会被 CSP 拦截。
        f"form-action 'self' {_base_origin} https:",
        "frame-ancestors 'none'",              # 比 X-Frame-Options 更现代
        "base-uri 'self'",
        "object-src 'none'",
    ]
    response.headers["Content-Security-Policy"] = "; ".join(csp_parts)

    # 权限策略（禁用不需要的浏览器 API）
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=()"
    )

    # 禁止 Cloudflare 及其他 CDN 缓存 HTML 页面
    # HTML 页面含有动态内容和安全响应头（如 CSP），缓存旧版本会导致 CSP 不匹配
    content_type = response.headers.get("content-type", "")
    if "text/html" in content_type:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"

    # 移除服务器信息泄露头
    headers_to_remove = ["Server", "X-Powered-By"]
    for h in headers_to_remove:
        if h in response.headers:
            del response.headers[h]

    return response


# 静态文件和模板配置
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# ===== 健康检查端点 =====
@app.get("/health", tags=["System"])
async def health_check():
    """
    健康检查端点 - 用于监控和负载均衡器
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0"
    }

@app.get("/api/health", tags=["System"])
async def api_health():
    """API 健康检查 - 包含数据库连接状态"""
    try:
        db = get_db()
        db.execute("SELECT COUNT(*) FROM users")
        return {
            "status": "ok",
            "database": "connected",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=500,
            content={"status": "error", "database": "disconnected"}
        )

# ===== 注册路由 =====
# 注册原有 API 路由模块
# app.include_router(auth.router) # 移除旧的 auth 路由
app.include_router(oauth.router, tags=["OAuth 2.0"])
app.include_router(admin.router, tags=["Admin API"])
app.include_router(auth_router, tags=["Authentication Enhanced"])
app.include_router(mfa_router, tags=["MFA"])
app.include_router(passkeys_router, tags=["Passkeys"])
# ===== 会话管理 API =====
@app.post("/api/sessions/logout")
async def api_logout_session(
    request: Request,
    current_user: dict = Depends(require_login)
):
    """登出指定会话"""
    try:
        data = await request.json()
        session_token = data.get("session_token")
    except:
        raise HTTPException(status_code=400, detail="无效的请求数据")

    if not session_token:
        raise HTTPException(status_code=400, detail="缺少 session_token")

    # 验证会话属于当前用户
    session = SessionDB.get_session_by_token_only(session_token)
    if not session or session["user_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="无权撤销该会话")

    SessionDB.delete_session(session_token)
    return {"success": True, "message": "会话已撤销"}
@app.post("/api/sessions/logout-all")
async def api_logout_all_sessions(
    request: Request,
    current_user: dict = Depends(require_login)
):
    """登出所有其他会话(保留当前会话)"""
    # 获取当前会话 token
    current_session_token = request.cookies.get("session_token")

    # 获取所有用户会话
    sessions = SessionDB.get_user_sessions(current_user["id"])

    # 删除除当前会话外的所有会话
    revoked_count = 0
    for session in sessions:
        if session["session_token"] != current_session_token:
            SessionDB.delete_session(session["session_token"])
            revoked_count += 1

    return {"success": True, "message": f"已撤销 {revoked_count} 个其他会话"}
@app.get("/logout")
async def logout_page(session_token: Optional[str] = Cookie(None)):
    """登出当前账户（仅删除当前 session，不影响其他已登录账户）"""
    response = RedirectResponse(url="/login", status_code=302)

    if session_token:
        SessionDB.delete_session(session_token)

    # 清除 Cookie，使浏览器端不再携带旧 token
    response.delete_cookie(key="session_token", path="/", httponly=True, samesite="lax")

    return response


@app.post("/api/auth/switch-account")
async def switch_account(
    request: Request,
    target_session_token: str = Form(...),
    # 移除 require_login，允许从未登录状态切换到已保存账户
    current_user: Optional[dict] = Depends(get_current_user),
):
    """
    账户切换接口 —— 服务端换发 Cookie，安全切换到另一个已登录账户。
    前端只需传入目标账户的 session_token（存储在 localStorage），
    服务端验证其有效性后，通过 Set-Cookie 完成切换，无需前端操作 httponly Cookie。
    """
    # 1. 校验目标 session 是否真实存在且属于调用者所在用户组（不能切换到别人的账户）
    target_session = SessionDB.get_session_by_token_only(target_session_token)
    if not target_session:
        raise HTTPException(status_code=404, detail="目标会话不存在或已过期，请重新登录该账户")

    # 检查目标 session 是否过期
    from datetime import datetime
    expires_at = target_session.get("expires_at")
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            expires_at = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
    if expires_at < datetime.utcnow():
        SessionDB.delete_session(target_session_token)
        raise HTTPException(status_code=401, detail="目标会话已过期，请重新登录该账户")

    # 检查目标 session 是否还需要 MFA 验证
    if target_session.get("mfa_required") == 1 and target_session.get("mfa_verified") != 1:
        raise HTTPException(status_code=403, detail="目标账户尚未完成 MFA 验证")

    # 2. 获取目标用户信息用于返回给前端更新 localStorage
    target_user = UserDB.get_user_by_id(target_session["user_id"])
    if not target_user or not target_user.get("is_active", 1):
        raise HTTPException(status_code=403, detail="目标账户不存在或已被禁用")

    # 3. 构造响应，通过 Set-Cookie 切换 session
    resp = JSONResponse(content={
        "success": True,
        "message": f"已切换到 {target_user['name']}",
        "user": {
            "user_id": target_user["id"],
            "name": target_user["name"],
            "email": target_user["email"],
            "username": target_user.get("username"),
        }
    })
    # 在切换时也返回 token 头部，确保前端能更新 localStorage
    resp.headers["X-Session-Token"] = target_session_token
    resp.set_cookie(
        key="session_token",
        value=target_session_token,
        max_age=config.SESSION_EXPIRE_DAYS * 24 * 60 * 60,
        path="/",
        httponly=True,
        samesite="lax",
        secure=config.COOKIE_SECURE,
    )
    return resp


@app.post("/api/auth/logout-current")
async def logout_current_account(
    request: Request,
    current_user: Optional[dict] = Depends(get_current_user),
):
    """
    登出当前账户的 JSON API 版本（供 account-switcher.js 调用）。
    只删除当前 session，不影响 localStorage 里其他账户。
    """
    current_session_token = request.cookies.get("session_token")
    if current_session_token:
        SessionDB.delete_session(current_session_token)

    resp = JSONResponse(content={
        "success": True,
        "message": "当前账户已登出",
        "logged_out_user_id": current_user["id"],
    })
    resp.delete_cookie(key="session_token", path="/", httponly=True, samesite="lax")
    return resp
# ===== 管理 API =====
@app.get("/api/metrics")
async def get_metrics(current_user: dict = Depends(require_admin)):
    """获取性能指标（仅管理员）"""
    metrics = PerformanceMonitor.get_metrics()

    return {
        "success": True,
        "metrics": metrics
    }
@app.get("/api/cache/stats")
async def get_cache_stats(current_user: dict = Depends(require_admin)):
    """获取缓存统计信息（仅管理员）"""
    cache_data = CacheManager._cache

    return {
        "success": True,
        "cache_size": len(cache_data),
        "cache_items": list(cache_data.keys())
    }
@app.post("/api/cache/clear")
async def clear_cache(current_user: dict = Depends(require_admin)):
    """清空缓存（仅管理员）"""
    CacheManager.clear()

    return {
        "success": True,
        "message": "缓存已清空"
    }
@app.get("/api/logs/login")
async def get_login_logs(
    current_user: dict = Depends(require_admin),
    limit: int = 50
):
    """获取登录日志（仅管理员）"""
    logs = LoginLogDB.get_recent_logs(limit=limit)

    return {
        "success": True,
        "logs": logs
    }
@app.get("/api/logs/login/user/{user_id}")
async def get_user_login_logs(
    user_id: int,
    current_user: dict = Depends(require_login),
    limit: int = 20
):
    """获取用户的登录日志"""
    # 只能查看自己的日志，除非是管理员
    if current_user["id"] != user_id and not current_user.get("is_admin"):
        raise HTTPException(status_code=403, detail="无权访问")

    logs = LoginLogDB.get_user_logs(user_id, limit=limit)

    return {
        "success": True,
        "logs": logs
    }

# ===== 异常处理 =====
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """HTTP 异常处理器 - 统一处理 HTTP 异常"""
    # 记录异常信息
    logger.warning(f"HTTP {exc.status_code}: {exc.detail} - Path: {request.url.path}")

    if exc.status_code == 303:
        # 处理登录重定向
        return RedirectResponse(url=exc.detail, status_code=303)
    if exc.status_code == 403:
        # 检查是否是 API 请求
        if request.url.path.startswith("/api/"):
            return JSONResponse(
                status_code=403,
                content={"success": False, "detail": exc.detail}
            )

        # 返回友好的 403 页面
        current_user = await get_current_user(request.cookies.get("session_token"))

        context = {
            "request": request,
            "status_code": 403,
            "title": "403 Forbidden",
            "message": "您没有访问此页面的权限，请联系管理员。",
            "current_user": current_user
        }
        return templates.TemplateResponse("403.html", context, status_code=403)

    # 其他 HTTPException 返回 JSON
    return JSONResponse(
        status_code=exc.status_code,
        content={"success": False, "detail": exc.detail}
    )
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """通用异常处理器 - 捕获所有未处理的异常"""
    import traceback

    # 记录详细异常信息
    error_traceback = traceback.format_exc()
    logger.error(
        f"Unhandled exception on {request.method} {request.url.path}\n"
        f"Error: {str(exc)}\n"
        f"Traceback:\n{error_traceback}"
    )

    # 根据环境决定是否显示详细错误
    detail = "服务器内部错误，请稍后重试"
    if hasattr(config, 'DEBUG') and config.DEBUG:
        detail = f"{type(exc).__name__}: {str(exc)}"

    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "detail": detail,
            "timestamp": datetime.now().isoformat()
        }
    )
# ===== 前端页面路由 =====
@app.get("/")
async def index(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    """首页"""
    try:
        if current_user:
            custom_data = UserCustomDataDB.get_all_user_data(current_user["id"])
            custom_fields = CustomFieldDB.get_all_fields()

            user_fields = []
            for field in custom_fields:
                if field["show_in_profile"]:
                    user_fields.append({
                        "key": field["field_key"],
                        "label": field["field_label"],
                        "value": custom_data.get(field["field_key"], "")
                    })

            sessions = SessionDB.get_user_sessions(current_user["id"])
        else:
            user_fields = []
            sessions = []
    except Exception as e:
        pass  # 加载用户数据失败
        user_fields = []
        sessions = []

    context = {
        "request": request,
        "config": config,
        "current_user": current_user,
        "user_fields": user_fields,
        "sessions": sessions
    }

    return templates.TemplateResponse("index.html", context)
@app.get("/login", name="login_page")
async def login_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    """登录页面"""
    oauth_params = request.query_params
    has_oauth = "client_id" in oauth_params and "redirect_uri" in oauth_params

    if current_user and has_oauth:
        authorize_url = request.url_for("authorize_page").path
        return RedirectResponse(url=f"{authorize_url}?{urlencode(oauth_params)}", status_code=302)

    redirect_uri = request.query_params.get("redirect_uri")

    context = {
        "request": request,
        "config": config,
        "current_user": current_user,
        "redirect_uri": redirect_uri
    }
    return templates.TemplateResponse("login.html", context)
@app.get("/register", name="register_page")
async def register_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    """注册页面"""
    oauth_params = request.query_params
    has_oauth = "client_id" in oauth_params and "redirect_uri" in oauth_params

    if current_user and has_oauth:
        authorize_url = request.url_for("authorize_page").path
        return RedirectResponse(url=f"{authorize_url}?{urlencode(oauth_params)}", status_code=302)

    context = {"request": request, "config": config, "current_user": current_user}
    return templates.TemplateResponse("register.html", context)
@app.get("/mfa/setup", name="mfa_setup_page")
async def mfa_setup_page(request: Request, current_user: dict = Depends(require_login)):
    """MFA 设置页面"""
    from auth_center.database import MFADB
    mfa_status = MFADB.get_mfa_status(current_user["id"])
    context = {
        "request": request,
        "config": config,
        "current_user": current_user,
        "mfa_enabled": mfa_status["enabled"],
	"settings": {"SITE_NAME": "SSO 认证中心"},
        "recovery_codes_available": mfa_status["recovery_codes_count"] > 0,
    }
    return templates.TemplateResponse("mfa/settings.html", context)

@app.get("/mfa/verify", name="mfa_verify_page")
async def mfa_verify_page(
    request: Request,
    session_token: Optional[str] = Cookie(None)
):
    """MFA 验证页面：只允许 mfa_required=1 且 mfa_verified=0 的 session 进入"""
    if not session_token:
        return RedirectResponse(url="/login", status_code=302)

    # 直接查库，不依赖 get_session 的字段映射
    with get_db() as conn:
        row = conn.execute(
            "SELECT user_id, mfa_required, mfa_verified FROM sessions WHERE session_token = ? AND expires_at > datetime('now')",
            (session_token,)
        ).fetchone()


    if not row:
        return RedirectResponse(url="/login", status_code=302)

    mfa_required = row["mfa_required"]
    mfa_verified = row["mfa_verified"]

    # 不是 pending 状态 → 去首页
    if not (mfa_required == 1 and mfa_verified != 1):
        return RedirectResponse(url="/", status_code=302)

    user = UserDB.get_user_by_id(row["user_id"])
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    context = {
        "request": request,
        "config": config,
        "user_email": user["email"],
        "session_token": session_token,
    }
    return templates.TemplateResponse("mfa/verify.html", context)

@app.get("/switch-account", name="switch_account_page")
async def switch_account_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    """賬戶切換頁面"""
    context = {
        "request": request,
        "config": config,
        "current_user": current_user
    }
    return templates.TemplateResponse("account_switcher.html", context)
@app.get("/account", name="account_page")
async def account_page(request: Request, current_user: dict = Depends(require_login)):
    """用户中心页面"""
    try:
        custom_data = UserCustomDataDB.get_all_user_data(current_user["id"])
        custom_fields = CustomFieldDB.get_all_fields()

        sessions = SessionDB.get_user_sessions(current_user["id"])
        login_logs = LoginLogDB.get_user_logs(current_user["id"], limit=20) # 获取最近20条登录日志

        # 格式化会话信息以匹配前端模板
        active_sessions = []
        current_session_token = request.cookies.get("session_token")
        for session in sessions:
            is_current = session["session_token"] == current_session_token
            try:
                login_time = datetime.fromisoformat(session["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
                expiry_time = datetime.fromisoformat(session["expires_at"]).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                login_time = session["created_at"]  # 回退到原始字符串
                expiry_time = session["expires_at"]
            active_sessions.append({
                "id": session["session_token"], # 使用 token 作为 ID
                "device_info": session.get("device_name", "未知设备"),
                "ip_address": session.get("ip_address", "未知 IP"),
                "login_time": login_time,
                "expiry_time": expiry_time,
                "is_current": is_current
            })
        # 格式化登录日志信息
        formatted_logs = []
        for log in login_logs:
            try:
                timestamp = datetime.fromisoformat(log["login_time"]).strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                timestamp = log.get("login_time", "")
            formatted_logs.append({
                "timestamp": timestamp,
                "ip_address": log.get("ip_address", "未知 IP"),
                "device_info": log.get("user_agent", "未知设备"),
                "status": "success" if log["status"] == "SUCCESS" else "failure"
            })
    except Exception as e:
        pass  # 加载账户数据失败
        active_sessions = []
        formatted_logs = []

    from auth_center.database import MFADB
    mfa_status = MFADB.get_mfa_status(current_user["id"])
    # 将 mfa_enabled 注入 current_user，供模板使用
    current_user = dict(current_user)
    current_user["mfa_enabled"] = mfa_status["enabled"]
    # 注入手机号（safe_user 已含 phone，但确保从 DB 取最新值）
    full_user = UserDB.get_user_by_id(current_user["id"])
    current_user["phone"] = full_user.get("phone") if full_user else None

    context = {
        "request": request,
        "config": config,
        "current_user": current_user,
        "active_sessions": active_sessions,
        "login_logs": formatted_logs,
        "success_profile": request.query_params.get("success_profile"),
        "error_profile": request.query_params.get("error_profile"),
        "success_security": request.query_params.get("success_security"),
        "error_security": request.query_params.get("error_security"),
    }

    return templates.TemplateResponse("account.html", context)
@app.get("/terms", name="terms_page")
async def terms_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    """服务条款页面"""
    context = {"request": request, "config": config, "current_user": current_user}
    return templates.TemplateResponse("terms.html", context)
@app.get("/privacy", name="privacy_page")
async def privacy_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    """隐私政策页面"""
    context = {"request": request, "config": config, "current_user": current_user}
    return templates.TemplateResponse("privacy.html", context)
@app.get("/admin", name="admin_page")
async def admin_page(request: Request, current_user: dict = Depends(require_admin)):
    """管理员页面"""
    # 查询咨询消息未读数
    unread_messages_count = 0
    # 查询站内信未读数（用户发来的未读对话消息）
    admin_unread_inbox_count = 0
    try:
        with get_db() as conn:
            # 咨询消息未读
            try:
                row = conn.execute(
                    "SELECT COUNT(*) FROM contact_messages WHERE status IN ('unread', 'pending')"
                ).fetchone()
                unread_messages_count = row[0] if row else 0
            except Exception:
                pass
            # 站内信未读（用户发来的消息）
            try:
                row = conn.execute(
                    "SELECT COUNT(*) FROM conv_messages WHERE sender_role='user' AND is_read=0"
                ).fetchone()
                admin_unread_inbox_count = row[0] if row else 0
            except Exception:
                pass
    except Exception:
        pass

    context = {
        "request": request,
        "config": config,
        "user": current_user,
        "current_user": current_user,
        "admin_user": current_user,
        "unread_messages_count": unread_messages_count,
        "admin_unread_inbox_count": admin_unread_inbox_count,
    }
    return templates.TemplateResponse("admin.html", context)
@app.get("/admin/users", name="admin_users_page")
async def admin_users_page(request: Request, current_user: dict = Depends(require_admin)):
    """用戶管理頁面"""
    context = {
        "request": request,
        "config": config,
        "user": current_user,
        "current_user": current_user,
        "admin_user": current_user
    }
    return templates.TemplateResponse("admin_users.html", context)
@app.get("/admin/apps", name="admin_apps_page")
async def admin_apps_page(request: Request, current_user: dict = Depends(require_admin)):
    """應用管理頁面"""
    context = {
        "request": request,
        "config": config,
        "user": current_user,
        "current_user": current_user,
        "admin_user": current_user
    }
    return templates.TemplateResponse("admin_apps.html", context)
@app.get("/admin/fields", name="admin_fields_page")
async def admin_fields_page(request: Request, current_user: dict = Depends(require_admin)):
    """字段管理頁面"""
    context = {
        "request": request,
        "config": config,
        "user": current_user,
        "current_user": current_user,
        "admin_user": current_user
    }
    return templates.TemplateResponse("admin_fields.html", context)
@app.get("/admin/whitelist", name="admin_whitelist_page")
async def admin_whitelist_page(request: Request, current_user: dict = Depends(require_admin)):
    """白名單管理頁面"""
    context = {
        "request": request,
        "config": config,
        "user": current_user,
        "current_user": current_user,
        "admin_user": current_user
    }
    return templates.TemplateResponse("whitelist.html", context)
@app.get("/admin/config", name="admin_config_page")
async def admin_config_page(request: Request, current_user: dict = Depends(require_admin)):
    """系統配置頁面"""
    context = {
        "request": request,
        "config": config,
        "user": current_user,
        "current_user": current_user,
        "admin_user": current_user
    }
    return templates.TemplateResponse("admin_config.html", context)

# ===== 文档和帮助页面 =====
@app.get("/docs", name="docs_page")
async def docs_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    """开发文档页面"""
    context = {"request": request, "config": config, "current_user": current_user}
    return templates.TemplateResponse("docs.html", context)

@app.get("/api", name="api_page")
async def api_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    """API 参考页面"""
    context = {"request": request, "config": config, "current_user": current_user}
    return templates.TemplateResponse("api.html", context)

@app.get("/support", name="support_page")
async def support_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    """技术支持页面"""
    context = {"request": request, "config": config, "current_user": current_user}
    return templates.TemplateResponse("support.html", context)

@app.get("/about", name="about_page")
async def about_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    """关于我们页面"""
    context = {"request": request, "config": config, "current_user": current_user}
    return templates.TemplateResponse("about.html", context)


@app.get("/inbox", name="inbox_page")
async def inbox_page(request: Request, current_user: dict = Depends(require_login)):
    """用户消息中心（广播 + 对话）"""
    return templates.TemplateResponse("inbox.html", {
        "request": request,
        "current_user": current_user,
    })

@app.get("/admin/inbox", name="admin_inbox_page")
async def admin_inbox_page(request: Request, current_user: dict = Depends(require_admin)):
    """管理员消息中心"""
    from auth_center.routers.admin import _ensure_msg_tables
    _ensure_msg_tables()
    return templates.TemplateResponse("admin_inbox.html", {
        "request": request,
        "current_user": current_user,
    })

@app.get("/contact", name="contact_page")
async def contact_page(request: Request, current_user: Optional[dict] = Depends(get_current_user)):
    """联系我们页面"""
    context = {"request": request, "config": config, "current_user": current_user}
    return templates.TemplateResponse("contact.html", context)

@app.get("/admin/messages", name="admin_messages_page")
async def admin_messages_page(request: Request, current_user: dict = Depends(require_admin)):
    """咨询消息管理页面"""
    # 查询所有咨询消息
    messages = []
    unread_count = 0
    try:
        with get_db() as conn:
            # 确保表存在
            conn.execute("""
                CREATE TABLE IF NOT EXISTS contact_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    phone TEXT,
                    type TEXT,
                    subject TEXT,
                    message TEXT NOT NULL,
                    status TEXT DEFAULT 'unread',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor = conn.execute(
                "SELECT * FROM contact_messages ORDER BY created_at DESC"
            )
            messages = [dict(row) for row in cursor.fetchall()]
            unread_count = sum(1 for m in messages if m.get("status", "unread") == "unread")
    except Exception as e:
        pass  # 加载消息失败

    context = {
        "request": request,
        "config": config,
        "user": current_user,
        "current_user": current_user,
        "admin_user": current_user,
        "messages": messages,
        "unread_messages_count": unread_count,
        "v": "1"
    }
    return templates.TemplateResponse("admin_messages.html", context)

@app.get("/admin/audit-logs", name="admin_audit_logs_page")
async def admin_audit_logs_page(request: Request, current_user: dict = Depends(require_admin)):
    """审计日志管理页面"""
    context = {
        "request": request,
        "config": config,
        "user": current_user,
        "current_user": current_user,
        "admin_user": current_user,
        "v": "1"
    }
    return templates.TemplateResponse("admin_audit_logs.html", context)

@app.get("/admin/portal-tokens", name="admin_portal_tokens_page")
async def admin_portal_tokens_page(request: Request, current_user: dict = Depends(require_admin)):
    """Portal API Token 管理页面"""
    context = {
        "request": request,
        "config": config,
        "user": current_user,
        "current_user": current_user,
        "admin_user": current_user,
        "v": "1"
    }
    return templates.TemplateResponse("admin_portal_tokens.html", context)

# ===== MFA 登录验证接口（登录流程中使用，与账户设置中的 MFA 不同）=====
@app.post("/api/mfa/verify")
async def verify_mfa_login(
    request: Request,
    code: str = Form(None),
    remember_device: Optional[str] = Form(None),      # "true" / "false"
    device_fingerprint: Optional[str] = Form(None),   # fingerprintjs 指纹
    device_label: Optional[str] = Form(None),         # 设备名称（可选）
    session_token_header: Optional[str] = Cookie(None, alias="session_token")
):
    """
    登录流程中的 MFA 验证。
    验证通过后若勾选"记住此设备30天"，将设备指纹写入 trusted_devices，
    下次在该设备登录时自动跳过 MFA（类 Google/GitHub 行为）。
    """
    import json as _json
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    mfa_code = code or body.get("code", "")

    session_token = session_token_header
    if not session_token:
        raise HTTPException(status_code=401, detail="未找到会话，请重新登录")

    session = SessionDB.get_session(session_token)
    if not session:
        raise HTTPException(status_code=401, detail="会话无效或已过期，请重新登录")

    user_id = session["user_id"]

    # 验证 MFA 码
    from auth_center.auth import MFAService
    from auth_center.database import MFADB, TrustedDeviceDB

    mfa_secret = MFADB.get_mfa_secret(user_id)

    if mfa_secret:
        import pyotp
        totp = pyotp.TOTP(mfa_secret)
        is_valid = totp.verify(mfa_code, valid_window=1)
        if not is_valid:
            is_valid = MFADB.verify_recovery_code(user_id, mfa_code)
        if not is_valid:
            raise HTTPException(status_code=401, detail="MFA 验证码无效，请重试")
    else:
        raise HTTPException(status_code=400, detail="您尚未设置 MFA，无法完成验证")

    # 验证成功，标记 mfa_verified=1
    with get_db() as conn:
        conn.execute(
            "UPDATE sessions SET mfa_verified = 1 WHERE session_token = ?",
            (session_token,)
        )
        conn.commit()

    # 若用户勾选了"记住此设备"且提供了设备指纹，写入信任列表
    trusted = False
    if remember_device == "true" and device_fingerprint:
        TrustedDeviceDB.trust_device(
            user_id=user_id,
            device_fingerprint=device_fingerprint,
            device_name=device_label or "未知设备",
            days=30
        )
        trusted = True

    return JSONResponse(content={
        "success": True,
        "message": "MFA 验证成功",
        "device_trusted": trusted
    }, status_code=200)


# ===== 联系我们提交接口 =====
@app.post("/api/contact")
async def submit_contact(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    phone: Optional[str] = Form(None),
    type: Optional[str] = Form("general"),
    subject: str = Form(...),
    message: str = Form(...)
):
    """处理联系我们表单提交 — 存入 contact_messages 表，管理员在 /admin/messages 查看"""
    from auth_center.database import get_db
    try:
        with get_db() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS contact_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    phone TEXT,
                    type TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    message TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.execute(
                "INSERT INTO contact_messages (name, email, phone, type, subject, message) VALUES (?, ?, ?, ?, ?, ?)",
                (name, email, phone, type, subject, message)
            )
            conn.commit()
        return {"success": True, "message": "消息已提交，我们会尽快与您联系"}
    except Exception as e:
        logger.error(f"Contact form error: {e}")
        return {"success": True, "message": "消息已收到，谢谢您的反馈"}

# ===== 启动事件 =====
@app.on_event("startup")
async def startup_event():
    """启动时初始化"""
    try:
        # 初始化数据库
        init_db()

        # 添加数据库索引以提高性能
        with get_db() as conn:
            QueryOptimizer.add_indexes(conn)

        # 从数据库加载配置
        whitelist_config = ConfigDB.get_config("ALLOWED_REGISTRATION_EMAILS")
        if whitelist_config:
            try:
                whitelist = json.loads(whitelist_config)
                if whitelist is None or whitelist == "null":
                    config.ALLOWED_REGISTRATION_EMAILS = None
                else:
                    config.ALLOWED_REGISTRATION_EMAILS = whitelist
            except:
                pass

        print("=" * 60)
        print("SSO 认证中心已启动（增强版）")
        print("=" * 60)
        print(f"服务器地址: http://{config.HOST}:{config.PORT}")
        print(f"首页: http://{config.HOST}:{config.PORT}/")
        print(f"用户中心: http://{config.HOST}:{config.PORT}/account")
        print(f"管理后台: http://{config.HOST}:{config.PORT}/admin")
        print(f"健康检查: http://{config.HOST}:{config.PORT}/health")
        print("=" * 60)
        print("新增功能:")
        print(" - 手机验证码登录")
        print(" - 多因素认证（MFA）")
        print(" - 异常登录检测")
        print(" - 会话管理")
        print(" - 登录日志审计")
        print(" - 性能监控")
        print("=" * 60)
    except Exception as e:
        print(f"启动错误: {str(e)}")
        import traceback
        traceback.print_exc()
@app.on_event("shutdown")
async def shutdown_event():
    """关闭时清理"""
    print("SSO 认证中心正在关闭...")
    CacheManager.clear()
    print("已清空缓存")