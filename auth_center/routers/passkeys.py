"""
Passkeys（WebAuthn 通行密钥）路由
支持：
  - 注册新的 Passkey（绑定到已登录账户）
  - 使用 Passkey 登录（免密，Face ID / Touch ID / 系统密码验证）
  - 列出 / 删除已注册的 Passkey

iOS/macOS 上使用苹果钥匙串（iCloud Keychain）原生弹窗完成 Face ID / Touch ID 验证。
Windows 上使用 Windows Hello。
Android 上使用 Google Password Manager 或设备锁屏。
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from typing import Optional
import base64
import json
from urllib.parse import urlparse
import webauthn
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AuthenticatorAttachment,
    PublicKeyCredentialDescriptor,
    AttestationConveyancePreference,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers import bytes_to_base64url, base64url_to_bytes

from auth_center.dependencies import require_login, get_current_user
from auth_center.database import PasskeyDB, SessionDB, UserDB
from auth_center.auth import generate_session_token
from auth_center.config import config

router = APIRouter(prefix="/api/passkeys", tags=["Passkeys"])


def _get_rp_id(request: Request) -> str:
    """
    获取 WebAuthn RP ID（必须是纯域名，不含协议和端口）。

    优先级：
      1. 环境变量 WEBAUTHN_RP_ID（最明确，推荐生产环境显式设置）
      2. 环境变量 BASE_URL 中的 hostname
      3. 请求头 Host 中的 hostname（自动适应任意域名，开发友好）
      4. 兜底 "localhost"
    """
    # 1. 显式环境变量
    rp_id_env = getattr(config, "WEBAUTHN_RP_ID", "")
    if rp_id_env:
        return rp_id_env

    # 2. BASE_URL（已被显式配置为非默认值时）
    base_url = getattr(config, "BASE_URL", "")
    if base_url and base_url not in ("http://localhost:8200", "http://localhost"):
        parsed = urlparse(base_url)
        if parsed.hostname:
            return parsed.hostname

    # 3. 从当前请求的 Host 头自动推断（最灵活，无需任何配置）
    host_header = request.headers.get("host", "")
    if host_header:
        # 去掉端口部分（WebAuthn rpId 不含端口）
        hostname = host_header.split(":")[0]
        if hostname and hostname != "localhost":
            return hostname

    return "localhost"


def _get_rp_name() -> str:
    return getattr(config, "SITE_NAME", "SSO 认证中心")


def _get_origin(request: Request) -> str:
    """
    获取 WebAuthn expected_origin（完整 URL，含协议，不含路径）。

    优先级：
      1. 环境变量 WEBAUTHN_ORIGIN
      2. 环境变量 BASE_URL（已显式配置时）
      3. 请求头 Origin
      4. 根据请求头 Host + X-Forwarded-Proto / scheme 自动构造
      5. 兜底 BASE_URL
    """
    # 1. 显式环境变量
    origin_env = getattr(config, "WEBAUTHN_ORIGIN", "")
    if origin_env:
        return origin_env

    # 2. BASE_URL 已被显式配置
    base_url = getattr(config, "BASE_URL", "")
    if base_url and base_url not in ("http://localhost:8200", "http://localhost"):
        # 只保留 scheme + host，去掉路径
        parsed = urlparse(base_url)
        return f"{parsed.scheme}://{parsed.netloc}"

    # 3. 请求头 Origin（浏览器发出的 CORS origin，最准确）
    origin_header = request.headers.get("origin")
    if origin_header:
        return origin_header

    # 4. 根据请求自动构造（反向代理场景下 X-Forwarded-Proto 携带真实协议）
    proto = (
        request.headers.get("x-forwarded-proto")
        or ("https" if request.url.scheme == "https" else "http")
    )
    host = request.headers.get("host", "localhost")
    return f"{proto}://{host}"


# ─── 注册 Passkey ──────────────────────────────────────────────────────────────

@router.post("/register/begin")
async def passkey_register_begin(
    request: Request,
    current_user: dict = Depends(require_login),
):
    """
    注册流程第一步：生成注册选项，返回给前端。
    前端用 navigator.credentials.create() 调起系统验证器（Face ID / Touch ID）。
    """
    rp_id = _get_rp_id(request)
    rp_name = _get_rp_name()

    # 获取用户已有凭证，prevent 重复注册同一设备
    existing = PasskeyDB.get_passkeys_by_user(current_user["id"])
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(pk["credential_id"]))
        for pk in existing
    ]

    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=str(current_user["id"]).encode(),
        user_name=current_user["email"],
        user_display_name=current_user["name"],
        exclude_credentials=exclude_credentials,
        authenticator_selection=AuthenticatorSelectionCriteria(
            # resident_key=required 表示凭证存在设备上（钥匙串），支持无用户名登录
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
            # 不限制 authenticator_attachment，允许平台（Face ID）和跨平台（安全密钥）
        ),
        attestation=AttestationConveyancePreference.NONE,
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
        timeout=120000,
    )

    # 保存 challenge（5 分钟有效）
    challenge_b64 = bytes_to_base64url(options.challenge)
    PasskeyDB.save_challenge(challenge_b64, "registration", user_id=current_user["id"])

    return JSONResponse(content=json.loads(options_to_json(options)))


@router.post("/register/complete")
async def passkey_register_complete(
    request: Request,
    current_user: dict = Depends(require_login),
):
    """
    注册流程第二步：验证浏览器返回的凭证，保存 Passkey。
    """
    body = await request.json()
    rp_id = _get_rp_id(request)
    origin = _get_origin(request)

    # 从请求体恢复 challenge
    try:
        client_data_json = base64url_to_bytes(body["response"]["clientDataJSON"])
        client_data = json.loads(client_data_json)
        challenge_b64 = client_data["challenge"]
    except Exception:
        raise HTTPException(status_code=400, detail="无法解析 clientDataJSON")

    # 验证 challenge 存在且未过期
    stored = PasskeyDB.pop_challenge(challenge_b64, "registration")
    if not stored:
        raise HTTPException(status_code=400, detail="Challenge 无效或已过期，请重新开始注册")
    if stored["user_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="Challenge 与当前用户不匹配")

    try:
        verification = verify_registration_response(
            credential=body,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=True,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Passkey 注册验证失败：{str(e)}")

    # 提取设备名称（User-Agent 粗略解析）
    ua = request.headers.get("user-agent", "")
    device_name = _parse_device_name(ua)

    credential_id_b64 = bytes_to_base64url(verification.credential_id)
    PasskeyDB.add_passkey(
        user_id=current_user["id"],
        credential_id=credential_id_b64,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        device_name=device_name,
    )

    return {"success": True, "message": f"Passkey 已成功注册（{device_name}）"}


# ─── 使用 Passkey 登录 ────────────────────────────────────────────────────────

@router.post("/auth/begin")
async def passkey_auth_begin(request: Request):
    """
    登录流程第一步：生成认证选项。
    支持「无用户名登录」——不传 allow_credentials，让设备自己选可用凭证。
    """
    rp_id = _get_rp_id(request)

    options = generate_authentication_options(
        rp_id=rp_id,
        # allow_credentials=[] 表示不限制，设备会展示所有可用 Passkey（推荐）
        allow_credentials=[],
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=120000,
    )

    challenge_b64 = bytes_to_base64url(options.challenge)
    PasskeyDB.save_challenge(challenge_b64, "authentication")

    return JSONResponse(content=json.loads(options_to_json(options)))


@router.post("/auth/complete")
async def passkey_auth_complete(request: Request):
    """
    登录流程第二步：验证认证响应，创建 session，返回 Set-Cookie。
    """
    body = await request.json()
    rp_id = _get_rp_id(request)
    origin = _get_origin(request)

    # 从 clientDataJSON 提取 challenge
    try:
        client_data_json = base64url_to_bytes(body["response"]["clientDataJSON"])
        client_data = json.loads(client_data_json)
        challenge_b64 = client_data["challenge"]
    except Exception:
        raise HTTPException(status_code=400, detail="无法解析 clientDataJSON")

    stored = PasskeyDB.pop_challenge(challenge_b64, "authentication")
    if not stored:
        raise HTTPException(status_code=400, detail="Challenge 无效或已过期，请重新尝试")

    # 找到对应凭证
    credential_id_b64 = body.get("id") or body.get("rawId")
    passkey = PasskeyDB.get_passkey_by_credential_id(credential_id_b64)
    if not passkey:
        raise HTTPException(status_code=404, detail="未找到此 Passkey，请先在账户设置中注册")

    user = UserDB.get_user_by_id(passkey["user_id"])
    if not user or not user.get("is_active", 1):
        raise HTTPException(status_code=403, detail="账户不存在或已被禁用")

    try:
        verification = verify_authentication_response(
            credential=body,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=passkey["public_key"],
            credential_current_sign_count=passkey["sign_count"],
            require_user_verification=True,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Passkey 验证失败：{str(e)}")

    # 更新签名计数
    PasskeyDB.update_sign_count(credential_id_b64, verification.new_sign_count)

    # 创建 session
    from datetime import datetime, timedelta
    session_token = generate_session_token()
    refresh_token = generate_session_token()
    expires_at = (datetime.utcnow() + timedelta(days=config.SESSION_EXPIRE_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    ua = request.headers.get("user-agent", "")
    ip = request.client.host if request.client else None
    from auth_center.auth import SessionManager
    device_name = SessionManager.extract_device_name(ua)

    SessionDB.create_session(
        passkey["user_id"],
        session_token,
        refresh_token,
        expires_at,
        ip_address=ip,
        user_agent=ua,
        device_name=device_name,
    )

    resp = JSONResponse(content={
        "success": True,
        "message": f"欢迎回来，{user['name']}",
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
        },
    })
    resp.set_cookie(
        key="session_token",
        value=session_token,
        max_age=config.SESSION_EXPIRE_DAYS * 24 * 60 * 60,
        path="/",
        httponly=True,
        samesite="lax",
        secure=config.COOKIE_SECURE,
    )
    resp.headers["X-Session-Token"] = session_token
    return resp


# ─── 管理 Passkey 列表 ────────────────────────────────────────────────────────

@router.get("/list")
async def list_passkeys(current_user: dict = Depends(require_login)):
    """列出当前用户的所有 Passkey"""
    passkeys = PasskeyDB.get_passkeys_by_user(current_user["id"])
    return {
        "success": True,
        "passkeys": [
            {
                "id": pk["id"],
                "device_name": pk["device_name"] or "未知设备",
                "created_at": pk["created_at"],
                "last_used_at": pk["last_used_at"],
            }
            for pk in passkeys
        ],
    }


@router.delete("/{passkey_id}")
async def delete_passkey(
    passkey_id: int,
    current_user: dict = Depends(require_login),
):
    """删除指定 Passkey"""
    PasskeyDB.delete_passkey(passkey_id, current_user["id"])
    return {"success": True, "message": "Passkey 已删除"}


# ─── 工具函数 ─────────────────────────────────────────────────────────────────

def _parse_device_name(ua: str) -> str:
    """从 User-Agent 提取简短设备描述"""
    ua_lower = ua.lower()
    if "iphone" in ua_lower:
        return "iPhone"
    elif "ipad" in ua_lower:
        return "iPad"
    elif "macintosh" in ua_lower or "mac os" in ua_lower:
        return "Mac"
    elif "android" in ua_lower:
        return "Android 设备"
    elif "windows" in ua_lower:
        return "Windows 设备"
    elif "linux" in ua_lower:
        return "Linux 设备"
    return "未知设备"
