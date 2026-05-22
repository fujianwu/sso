"""
增强的认证 API 路由 - 修复版本
包含手机验证码登录、MFA、密码重置、用户管理等功能
修复: 服务器端设置 Cookie 而不是依赖前端 JavaScript
"""

from fastapi import APIRouter, HTTPException, Depends, Request, Form, BackgroundTasks, Response
from fastapi.responses import JSONResponse
from typing import Optional
from datetime import datetime, timedelta
import json
import re
from urllib.parse import urlparse

from auth_center.config import config
from auth_center.database import (
    UserDB, SessionDB, LoginLogDB, get_db, TrustedDeviceDB, PasswordResetDB, AuditLogDB
)
from auth_center.auth import (
    hash_password, verify_password, validate_password, validate_email,
    validate_phone, generate_session_token, generate_verification_code,
    PhoneVerificationService, MFAService, AnomalyDetectionService,
    log_login_attempt, SessionManager
)
from auth_center.dependencies import require_login

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


# ===== 安全工具函数 =====

def _safe_redirect_uri(redirect_uri: Optional[str]) -> str:
    """
    校验 redirect_uri，防止开放重定向攻击。
    只允许同站相对路径（以 / 开头但不以 // 开头），拒绝外部 URL。
    """
    if not redirect_uri:
        return "/account"
    # 只允许相对路径（以 / 开头，不以 // 开头，不含协议）
    parsed = urlparse(redirect_uri)
    if parsed.scheme or parsed.netloc:
        # 拒绝带协议或域名的绝对 URL（防止跳出站点）
        return "/account"
    if not redirect_uri.startswith("/") or redirect_uri.startswith("//"):
        return "/account"
    # 拒绝路径遍历
    if ".." in redirect_uri:
        return "/account"
    return redirect_uri


@router.post("/register")
async def register_user(
    email: str = Form(...),
    password: str = Form(...),
    name: str = Form(...),
    username: Optional[str] = Form(None)
):
    """用户注册(兼容旧路由)"""
    # 验证密码强度
    valid, error = validate_password(password)
    if not valid:
        raise HTTPException(status_code=400, detail=error)

    # 检查邮箱是否已注册
    if UserDB.get_user_by_email(email):
        raise HTTPException(status_code=400, detail="该邮箱已被注册")

    # 检查用户名是否已存在
    if username and UserDB.get_user_by_username(username):
        raise HTTPException(status_code=400, detail="该用户名已被使用")

    # 检查邮箱白名单
    if config.ALLOWED_REGISTRATION_EMAILS:
        if email not in config.ALLOWED_REGISTRATION_EMAILS:
            raise HTTPException(status_code=403, detail="该邮箱不在允许注册的白名单内")

    # 密码哈希
    password_hash = hash_password(password)

    # 创建用户
    user_id = UserDB.create_user(
        email=email,
        password_hash=password_hash,
        name=name,
        username=username
    )

    if not user_id:
        raise HTTPException(status_code=500, detail="用户创建失败")

    return {"success": True, "message": "注册成功", "user_id": user_id}


# ===== 增强的登录接口 =====

@router.post("/login")
@router.post("/login/email")
async def login_with_email(
    request: Request,
    response: Response,
    email: str = Form(...),
    password: str = Form(...),
    redirect_uri: Optional[str] = Form(None),
    device_fingerprint: Optional[str] = Form(None),  # fingerprintjs 生成的设备指纹
    background_tasks: BackgroundTasks = None
):
    """
    邮箱/用户名密码登录
    MFA 策略（类 Google/GitHub 风格）：
    - 开启了 MFA 且设备可信（30天内验证过）→ 跳过 MFA
    - 开启了 MFA 且设备不可信 → 要求 MFA
    - 检测到高风险异常登录 → 强制 MFA，无论设备是否可信
    """

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")

    # 校验 redirect_uri，防止开放重定向
    safe_uri = _safe_redirect_uri(redirect_uri)

    # 1. 查询用户（支持邮箱或用户名）
    user = None
    if validate_email(email):
        user = UserDB.get_user_by_email(email)
    elif email:
        user = UserDB.get_user_by_username(email)

    if not user:
        log_login_attempt(email, "FAILURE", ip_address, user_agent, message="用户不存在")
        raise HTTPException(status_code=401, detail="邮箱/用户名或密码错误")

    # 1b. 检查账户是否被禁用
    if not user.get("is_active", 1):
        log_login_attempt(user["email"], "FAILURE", ip_address, user_agent, user_id=user["id"], message="账户已被禁用")
        raise HTTPException(status_code=403, detail="账户已被禁用，请联系管理员")

    # 1c. 检查账户是否被锁定（暴力破解保护）
    if UserDB.is_locked(user):
        remaining = UserDB.lock_seconds_remaining(user)
        minutes = remaining // 60
        seconds = remaining % 60
        log_login_attempt(user["email"], "FAILURE", ip_address, user_agent, user_id=user["id"], message="账户已锁定")
        raise HTTPException(
            status_code=429,
            detail=f"账户已被临时锁定（连续登录失败次数过多），请 {minutes} 分 {seconds} 秒后再试"
        )

    # 2. 验证密码
    if not verify_password(password, user["password_hash"]):
        UserDB.record_failed_login(user["id"])
        # 重新查询获取最新失败次数
        updated_user = UserDB.get_user_by_id(user["id"])
        attempts = updated_user.get("failed_login_attempts", 0) if updated_user else 0
        remaining_attempts = max(0, UserDB.MAX_FAILED_ATTEMPTS - attempts)
        log_login_attempt(user["email"], "FAILURE", ip_address, user_agent, user_id=user["id"], message="密码错误")
        AuditLogDB.log(
            action_type="LOGIN_FAIL",
            operator_id=user["id"],
            operator_email=user["email"],
            target_type="session",
            detail=f"密码错误 IP:{ip_address}",
            success=False,
            ip_address=ip_address,
        )
        if remaining_attempts == 0:
            raise HTTPException(status_code=429, detail=f"密码错误次数过多，账户已锁定 {UserDB.LOCKOUT_MINUTES} 分钟")
        raise HTTPException(status_code=401, detail=f"邮箱/用户名或密码错误（还剩 {remaining_attempts} 次尝试机会）")

    # 登录成功，重置失败计数
    UserDB.reset_failed_login(user["id"])

    # 3. 异常登录检测
    anomaly_result = AnomalyDetectionService.detect_anomaly(user["id"], ip_address, user_agent)
    is_high_risk = anomaly_result["is_anomaly"] and anomaly_result["risk_level"] == "high"

    # 4. 检查用户是否启用了 MFA
    user_has_mfa = MFAService.is_mfa_enabled(user["id"])

    # 5. 检查设备是否可信（高风险时强制验证，忽略可信设备）
    is_trusted_device = False
    if device_fingerprint and user_has_mfa and not is_high_risk:
        is_trusted_device = TrustedDeviceDB.is_trusted(user["id"], device_fingerprint)

    # 判断是否需要 MFA：
    # - 高风险异常 → 必须验证
    # - 开启了 MFA 且设备不可信 → 需要验证
    # - 开启了 MFA 且设备可信 → 跳过 ✅（类 Google 行为）
    needs_mfa = is_high_risk or (user_has_mfa and not is_trusted_device)

    # 6. 创建新会话
    session_token = generate_session_token()
    refresh_token = generate_session_token()
    expires_at = datetime.utcnow() + timedelta(days=config.SESSION_EXPIRE_DAYS)
    device_name = SessionManager.extract_device_name(user_agent)

    SessionDB.create_session(
        user["id"],
        session_token,
        refresh_token,
        expires_at.strftime(config.DATETIME_FORMAT),
        ip_address=ip_address,
        user_agent=user_agent,
        device_name=device_name
    )

    # 如果需要 MFA，标记 session（mfa_required=1 且 mfa_verified=0）
    if needs_mfa:
        with get_db() as conn:
            conn.execute(
                "UPDATE sessions SET mfa_required = 1, mfa_verified = 0 WHERE session_token = ?",
                (session_token,)
            )
            conn.commit()

    # 7. 记录登录日志
    if needs_mfa:
        reason = f"异常登录: {', '.join(anomaly_result.get('anomalies', []))}" if is_high_risk else "MFA 验证待完成"
        log_login_attempt(user["email"], "MFA_REQUIRED", ip_address, user_agent, user_id=user["id"], message=reason)
    else:
        log_login_attempt(user["email"], "SUCCESS", ip_address, user_agent, user_id=user["id"], message="登录成功")
        AuditLogDB.log(
            action_type="LOGIN",
            operator_id=user["id"],
            operator_email=user["email"],
            target_type="session",
            detail=f"登录成功 IP:{ip_address}",
            success=True,
            ip_address=ip_address,
        )

    # 8. 构建响应
    if needs_mfa:
        resp_content = {
            "success": True,
            "requires_mfa": True,
            "is_anomaly": is_high_risk,
            "anomalies": anomaly_result.get("anomalies", []),
            "redirect_uri": safe_uri,
            "message": "检测到异常登录，请完成二次验证" if is_high_risk else "请完成 MFA 验证"
        }
    else:
        resp_content = {"success": True, "requires_mfa": False, "message": "登录成功"}

    json_response = JSONResponse(content=resp_content, status_code=200)
    json_response.set_cookie(
        key="session_token", value=session_token,
        max_age=config.SESSION_EXPIRE_DAYS * 24 * 60 * 60,
        path="/", httponly=True, samesite="lax",
        secure=config.COOKIE_SECURE
    )
    # 将 session_token 也通过响应头暴露给前端，
    # 供 account-switcher.js 存入 localStorage 用于多账户切换。
    # 这不会降低安全性：实际鉴权始终走 httponly Cookie，
    # localStorage 里的 token 只用于切换时传给 /api/auth/switch-account 接口（服务端再验证）。
    json_response.headers["X-Session-Token"] = session_token

    if not needs_mfa:
        json_response.headers["X-Redirect-To"] = safe_uri

    return json_response

@router.post("/login/phone")
async def login_with_phone(
    request: Request,
    response: Response,
    phone: str = Form(...),
    code: str = Form(...),
    redirect_uri: Optional[str] = Form(None),
    background_tasks: BackgroundTasks = None
):
    """手机验证码登录"""
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent", "")

    # 1. 验证手机号
    if not validate_phone(phone):
        raise HTTPException(status_code=400, detail="手机号格式无效")

    # 2. 验证验证码
    success, message = PhoneVerificationService.verify_code(phone, code)
    if not success:
        raise HTTPException(status_code=400, detail=message)

    # 3. 查询绑定了该手机号的账户
    user = UserDB.get_user_by_phone(phone)
    if not user:
        raise HTTPException(status_code=401, detail="该手机号未绑定任何账户，请先登录后在「账户设置」中绑定手机号")

    if not user.get("is_active", 1):
        raise HTTPException(status_code=403, detail="账户已被禁用，请联系管理员")

    # 4. 创建会话
    session_token = generate_session_token()
    refresh_token = generate_session_token()
    expires_at = datetime.utcnow() + timedelta(days=config.SESSION_EXPIRE_DAYS)

    SessionDB.create_session(
        user["id"],
        session_token,
        refresh_token,
        expires_at.strftime(config.DATETIME_FORMAT)
    )

    # 5. 记录登录
    log_login_attempt(
        user["email"], "SUCCESS", ip_address, user_agent, user_id=user["id"],
        message="手机验证码登录成功"
    )

    # 7. 处理重定向
    resp_content = {"success": True, "message": "登录成功"}
    json_response = JSONResponse(content=resp_content, status_code=200)
    json_response.set_cookie(
        key="session_token",
        value=session_token,
        max_age=config.SESSION_EXPIRE_DAYS * 24 * 60 * 60,
        path="/",
        httponly=True,
        samesite="lax",
        secure=config.COOKIE_SECURE
    )
    json_response.headers["X-Session-Token"] = session_token
    if redirect_uri:
        json_response.headers["X-Redirect-To"] = _safe_redirect_uri(redirect_uri)
    return json_response


# ===== 登出 =====

@router.post("/logout")
async def logout(
    response: Response,
    current_user: Optional[dict] = Depends(require_login)
):
    """登出并删除 Cookie"""
    # 删除服务器端 Cookie
    response.delete_cookie(key="session_token", path="/")

    return {"success": True, "message": "已登出"}


# ===== 手机验证码相关 =====

@router.post("/phone/bind")
async def bind_phone(
    phone: str = Form(...),
    code: str = Form(...),
    current_user: dict = Depends(require_login)
):
    """绑定手机号到当前账户"""
    if not validate_phone(phone):
        raise HTTPException(status_code=400, detail="手机号格式无效")

    success, message = PhoneVerificationService.verify_code(phone, code)
    if not success:
        raise HTTPException(status_code=400, detail=message)

    # 检查该手机号是否已被其他账户绑定
    existing = UserDB.get_user_by_phone(phone)
    if existing and existing["id"] != current_user["id"]:
        raise HTTPException(status_code=409, detail="该手机号已被其他账户绑定")

    UserDB.update_user(current_user["id"], phone=phone)
    return {"success": True, "message": "手机号绑定成功"}


@router.post("/phone/unbind")
async def unbind_phone(
    current_user: dict = Depends(require_login)
):
    """解绑当前账户的手机号"""
    user = UserDB.get_user_by_id(current_user["id"])
    if not user or not user.get("phone"):
        raise HTTPException(status_code=400, detail="当前账户未绑定手机号")

    UserDB.update_user(current_user["id"], phone=None)
    return {"success": True, "message": "手机号解绑成功"}


@router.post("/phone/send-code")
async def send_phone_code(phone: str = Form(...)):
    """发送手机验证码"""
    success, message = PhoneVerificationService.send_verification_code(phone)

    if not success:
        raise HTTPException(status_code=400, detail=message)

    return {"success": True, "message": message}


@router.post("/phone/verify-code")
async def verify_phone_code(phone: str = Form(...), code: str = Form(...)):
    """验证手机验证码(不登录,仅验证)"""
    success, message = PhoneVerificationService.verify_code(phone, code)

    if not success:
        raise HTTPException(status_code=400, detail=message)

    return {"success": True, "message": "验证码验证成功"}


# ===== 密码重置 =====

@router.post("/password/reset-request")
async def request_password_reset(email: str = Form(...)):
    """请求密码重置 — 生成令牌并（若已配置邮件服务）发送重置链接"""
    if not validate_email(email):
        raise HTTPException(status_code=400, detail="邮箱格式无效")

    # 固定返回，不泄露邮箱是否已注册
    generic_resp = {"success": True, "message": "如果该邮箱已注册，您将收到重置链接（30 分钟内有效）"}

    user = UserDB.get_user_by_email(email)
    if not user:
        return generic_resp

    # 生成令牌并持久化到数据库（30 分钟有效）
    reset_token = generate_verification_code(32)
    ok = PasswordResetDB.create_token(user["id"], reset_token, expires_minutes=30)
    if not ok:
        # 数据库写入失败，静默返回通用提示，避免泄露内部错误
        return generic_resp

    # 构造重置链接（供邮件正文使用）
    reset_link = f"{config.BASE_URL}/password/reset?token={reset_token}"

    # 邮件发送（如已配置 SMTP 则实际发送，否则打印到日志供开发调试）
    import os
    if os.getenv("SMTP_HOST"):
        # TODO: 调用邮件服务 send_email(to=email, subject="密码重置", body=reset_link)
        pass
    else:
        # 开发模式：仅在服务器控制台输出，不在 API 响应中暴露
        print(f"[DEV] 密码重置链接: {reset_link}")

    return generic_resp


@router.post("/password/reset")
async def reset_password(
    token: str = Form(...),
    new_password: str = Form(...)
):
    """使用重置令牌重置密码"""
    if not token:
        raise HTTPException(status_code=400, detail="无效的重置令牌")

    # 验证密码强度
    valid, error = validate_password(new_password)
    if not valid:
        raise HTTPException(status_code=400, detail=error)

    # 从数据库验证令牌
    token_info = PasswordResetDB.verify_token(token)
    if not token_info:
        raise HTTPException(status_code=400, detail="重置令牌无效或已过期，请重新申请")

    user_id = token_info["user_id"]
    user = UserDB.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=400, detail="用户不存在")

    # 更新密码
    new_hash = hash_password(new_password)
    UserDB.update_password(user_id, new_hash)

    # 标记令牌已使用，并使该用户所有会话失效（强制重新登录）
    PasswordResetDB.mark_used(token)
    sessions = SessionDB.get_user_sessions(user_id)
    for s in sessions:
        SessionDB.delete_session(s["session_token"])

    # 异步清理过期令牌
    PasswordResetDB.cleanup_expired()

    AuditLogDB.log(
        action_type="PASSWORD_RESET",
        operator_id=user_id,
        operator_email=user["email"],
        target_type="user",
        target_id=user_id,
        detail="通过重置令牌重置密码",
    )
    return {"success": True, "message": "密码重置成功，请用新密码登录"}


# ===== 多因素认证(MFA) =====

@router.post("/mfa/setup")
async def setup_mfa(current_user: dict = Depends(require_login)):
    """设置 MFA(生成密钥和二维码)"""
    user_id = current_user["id"]
    email = current_user["email"]

    # 检查是否已设置 MFA
    if MFAService.is_mfa_enabled(user_id):
        raise HTTPException(status_code=400, detail="MFA 已启用")

    # 生成 MFA 密钥
    secret_key, qr_code_url = MFAService.generate_mfa_secret(email)

    # 临时存储密钥,等待验证
    MFAService._temp_secrets[user_id] = secret_key

    return {
        "success": True,
        "secret_key": secret_key,
        "qr_code_url": qr_code_url
    }


@router.post("/mfa/verify")
async def verify_mfa(
    code: str = Form(...),
    current_user: dict = Depends(require_login)
):
    """验证并启用 MFA"""
    user_id = current_user["id"]

    # 获取临时密钥
    secret_key = MFAService._temp_secrets.get(user_id)
    if not secret_key:
        raise HTTPException(status_code=400, detail="请先获取 MFA 设置")

    # 验证 MFA Code
    if not MFAService.verify_mfa_code(secret_key, code):
        raise HTTPException(status_code=400, detail="MFA 验证码无效")

    # 启用 MFA
    MFAService.enable_mfa(user_id, secret_key)

    # 清理临时密钥
    del MFAService._temp_secrets[user_id]

    AuditLogDB.log(
        action_type="MFA_ENABLE",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="user",
        target_id=current_user["id"],
        detail="用户启用了多因素认证",
    )
    return {"success": True, "message": "MFA 已成功启用"}


@router.post("/mfa/disable")
async def disable_mfa(
    code: str = Form(...),
    current_user: dict = Depends(require_login)
):
    """禁用 MFA"""
    user_id = current_user["id"]

    # 验证 MFA Code
    if not MFAService.validate_user_mfa(user_id, code):
        raise HTTPException(status_code=400, detail="MFA 验证码无效")

    # 禁用 MFA
    MFAService.disable_mfa(user_id)
    AuditLogDB.log(
        action_type="MFA_DISABLE",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="user",
        target_id=current_user["id"],
        detail="用户禁用了多因素认证",
    )
    return {"success": True, "message": "MFA 已禁用"}


@router.post("/mfa/validate")
async def validate_mfa(
    user_id: int = Form(...),
    code: str = Form(...)
):
    """在登录流程中验证 MFA"""
    if not MFAService.validate_user_mfa(user_id, code):
        raise HTTPException(status_code=401, detail="MFA 验证码无效")

    return {"success": True, "message": "MFA 验证成功"}


# ===== 会话管理 =====

@router.get("/sessions")
async def get_user_sessions(current_user: dict = Depends(require_login)):
    """获取当前用户的所有会话"""
    sessions = SessionManager.get_user_sessions(current_user["id"])
    return {"success": True, "sessions": sessions}


@router.post("/sessions/revoke")
async def revoke_session(
    session_token: str = Form(...),
    current_user: dict = Depends(require_login)
):
    """撤销指定会话"""
    # 验证会话属于当前用户
    session = SessionDB.get_session_by_token_only(session_token)
    if not session or session["user_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="无权撤销该会话")

    SessionDB.delete_session(session_token)
    return {"success": True, "message": "会话已撤销"}


@router.post("/sessions/revoke-all")
async def revoke_all_sessions(
    request: Request,
    current_user: dict = Depends(require_login)
):
    """撤销所有其他会话(保留当前会话)"""
    current_session_token = request.cookies.get("session_token")
    sessions = SessionDB.get_user_sessions(current_user["id"])



    revoked_count = 0
    for session in sessions:
        if session["session_token"] != current_session_token:
            SessionDB.delete_session(session["session_token"])
            revoked_count += 1

    return {"success": True, "message": f"已撤销 {revoked_count} 个其他会话"}


# ===== 用户信息管理 =====

@router.get("/me")
async def get_current_user_info(current_user: dict = Depends(require_login)):
    """获取当前用户信息"""
    return {
        "success": True,
        "user": current_user
    }





@router.put("/me")
async def update_current_user_info(
    name: Optional[str] = Form(None),
    username: Optional[str] = Form(None),
    avatar_url: Optional[str] = Form(None),
    current_user: dict = Depends(require_login)
):
    """更新当前用户信息"""
    user_id = current_user["id"]
    updates = {}

    if name:
        updates["name"] = name
    if username:
        # 检查用户名是否已被使用
        existing_user = UserDB.get_user_by_username(username)
        if existing_user and existing_user["id"] != user_id:
            raise HTTPException(status_code=400, detail="该用户名已被使用")
        updates["username"] = username
    if avatar_url:
        updates["avatar_url"] = avatar_url

    if not updates:
        raise HTTPException(status_code=400, detail="没有提供任何更新信息")

    UserDB.update_user(user_id, **updates)
    AuditLogDB.log(
        action_type="PROFILE_UPDATE",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="user",
        target_id=current_user["id"],
        detail=f"更新个人资料字段: {', '.join(updates.keys())}",
    )
    return {"success": True, "message": "用户信息更新成功"}


@router.post("/password/update")
async def update_password(
    current_password: str = Form(...),
    new_password: str = Form(...),
    current_user: dict = Depends(require_login)
):
    """已登录用户更新密码"""
    user_id = current_user["id"]
    user = UserDB.get_user_by_id(user_id)

    # 1. 验证当前密码
    if not verify_password(current_password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="当前密码不正确")

    # 2. 验证新密码强度
    valid, error = validate_password(new_password)
    if not valid:
        raise HTTPException(status_code=400, detail=error)

    # 3. 更新密码
    new_password_hash = hash_password(new_password)
    UserDB.update_user(user_id, password_hash=new_password_hash)

    AuditLogDB.log(
        action_type="PASSWORD_CHANGE",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="user",
        target_id=current_user["id"],
        detail="用户主动修改密码",
    )
    return {"success": True, "message": "密码更新成功"}