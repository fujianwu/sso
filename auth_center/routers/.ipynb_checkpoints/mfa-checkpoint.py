from fastapi import APIRouter, Request, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import pyotp
import qrcode
from io import BytesIO
import base64
from datetime import datetime, timedelta

from auth_center.dependencies import get_current_user, require_login
from auth_center.db.user import UserDB
from auth_center.db.mfa import MFADB
from auth_center.templates import templates
from auth_center.config import settings
import auth_center.utils as utils

router = APIRouter(tags=["多因素认证"])

class VerifyMFAData(BaseModel):
    code: str

@router.get("/account/mfa", response_class=HTMLResponse)
async def mfa_settings(
    request: Request,
    current_user: dict = Depends(require_login)
):
    """多因素认证设置页面"""
    # 检查用户是否已启用MFA
    mfa_status = MFADB.get_mfa_status(current_user["id"])

    context = {
        "request": request,
        "current_user": current_user,
        "mfa_enabled": mfa_status["enabled"],
        "recovery_codes_available": mfa_status["recovery_codes_count"] > 0
    }

    return templates.TemplateResponse("mfa/settings.html", context)

@router.post("/api/mfa/enable/init")
async def init_mfa_setup(
    current_user: dict = Depends(require_login)
):
    """初始化MFA设置，生成密钥和二维码"""
    # 检查是否已启用MFA
    if MFADB.get_mfa_status(current_user["id"])["enabled"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="您已启用多因素认证"
        )

    # 生成TOTP密钥
    totp_secret = pyotp.random_base32()

    # 生成QR码URL
    totp = pyotp.TOTP(totp_secret)
    issuer_name = f"SSO认证中心 ({settings.SITE_NAME})"
    account_name = current_user["email"]
    qr_code_url = totp.provisioning_uri(account_name, issuer_name=issuer_name)

    # 生成QR码图像
    qr = qrcode.make(qr_code_url)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    qr_code_base64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    # 临时存储密钥，有效期10分钟
    MFADB.store_temporary_secret(
        user_id=current_user["id"],
        secret=totp_secret,
        expires_at=datetime.utcnow() + timedelta(minutes=10)
    )

    return {
        "secret": totp_secret,
        "qr_code": f"data:image/png;base64,{qr_code_base64}",
        "issuer": issuer_name,
        "account": account_name
    }

@router.post("/api/mfa/enable/verify")
async def verify_mfa_setup(
    data: VerifyMFAData,
    current_user: dict = Depends(require_login)
):
    """验证MFA设置并启用"""
    # 获取临时密钥
    temp_secret = MFADB.get_temporary_secret(current_user["id"])
    if not temp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA设置已过期，请重新开始"
        )

    # 验证验证码
    totp = pyotp.TOTP(temp_secret["secret"])
    if not totp.verify(data.code, valid_window=1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="验证码无效，请重试"
        )

    # 生成恢复码
    recovery_codes = [utils.generate_random_string(16) for _ in range(10)]

    # 启用MFA
    MFADB.enable_mfa(
        user_id=current_user["id"],
        secret=temp_secret["secret"],
        recovery_codes=recovery_codes
    )

    # 删除临时密钥
    MFADB.delete_temporary_secret(current_user["id"])

    return {
        "message": "多因素认证已成功启用",
        "recovery_codes": recovery_codes
    }

@router.post("/api/mfa/disable")
async def disable_mfa(
    data: VerifyMFAData,
    current_user: dict = Depends(require_login)
):
    """禁用MFA"""
    # 检查是否已启用MFA
    mfa_status = MFADB.get_mfa_status(current_user["id"])
    if not mfa_status["enabled"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="您尚未启用多因素认证"
        )

    # 获取MFA密钥
    mfa_secret = MFADB.get_mfa_secret(current_user["id"])
    if not mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="获取MFA信息失败"
        )

    # 验证验证码或恢复码
    totp = pyotp.TOTP(mfa_secret)
    is_valid_code = totp.verify(data.code, valid_window=1)

    if not is_valid_code:
        # 检查是否是恢复码
        is_valid_recovery = MFADB.verify_recovery_code(current_user["id"], data.code)
        if not is_valid_recovery:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="验证码或恢复码无效"
            )

    # 禁用MFA
    MFADB.disable_mfa(current_user["id"])

    return {
        "message": "多因素认证已成功禁用"
    }

@router.post("/api/mfa/recovery-codes/regenerate")
async def regenerate_recovery_codes(
    data: VerifyMFAData,
    current_user: dict = Depends(require_login)
):
    """重新生成恢复码"""
    # 检查是否已启用MFA
    mfa_status = MFADB.get_mfa_status(current_user["id"])
    if not mfa_status["enabled"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="您尚未启用多因素认证"
        )

    # 获取MFA密钥
    mfa_secret = MFADB.get_mfa_secret(current_user["id"])
    if not mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="获取MFA信息失败"
        )

    # 验证验证码
    totp = pyotp.TOTP(mfa_secret)
    if not totp.verify(data.code, valid_window=1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="验证码无效，请重试"
        )

    # 生成新的恢复码
    new_recovery_codes = [utils.generate_random_string(16) for _ in range(10)]

    # 更新恢复码
    MFADB.update_recovery_codes(current_user["id"], new_recovery_codes)

    return {
        "message": "恢复码已重新生成",
        "recovery_codes": new_recovery_codes
    }

@router.get("/mfa/verify", response_class=HTMLResponse)
async def mfa_verify_page(
    request: Request,
    session_token: str = None
):
    """MFA验证页面"""
    # 验证会话
    if not session_token:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    # 检查会话是否需要MFA验证
    session = SessionDB.get_session(session_token)
    if not session or session.get("mfa_verified", False):
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    # 获取用户信息
    user = UserDB.get_user_by_id(session["user_id"])
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    context = {
        "request": request,
        "user_email": user["email"],
        "session_token": session_token
    }

    return templates.TemplateResponse("mfa/verify.html", context)