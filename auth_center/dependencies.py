from fastapi import Depends, HTTPException, Cookie, Request, status
from fastapi.templating import Jinja2Templates
from typing import Optional, Dict, Any
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode
# Note: Removed unused RedirectResponse import
from .config import config
from .database import SessionDB, UserDB, CustomFieldDB, UserCustomDataDB

# 获取当前文件所在目录(auth_center/)
BASE_DIR = Path(__file__).resolve().parent
# 静态文件和模板配置
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# ==================== 依赖函数 ====================
async def get_current_user(session_token: Optional[str] = Cookie(None)) -> Optional[Dict[str, Any]]:
    if not session_token:
        return None

    session = SessionDB.get_session(session_token)
    if not session:
        return None

    # 检查会话是否过期
    expires_at = session["expires_at"]

    # 确保 expires_at 是 datetime 对象，如果不是，尝试转换 (兼容旧数据)
    if isinstance(expires_at, str):
        try:
            # 尝试包含微秒的格式
            expires_at = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            try:
                # 如果失败，尝试不包含微秒的格式
                expires_at = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                # 如果还是失败，删除会话并返回
                SessionDB.delete_session(session_token)
                return None

    if expires_at < datetime.utcnow():
        SessionDB.delete_session(session_token)
        return None

    user = UserDB.get_user_by_id(session["user_id"])
    if not user:
        return None

    # 如果 session 处于 MFA 待验证状态，不认为已登录（防绕过）
    # 如果 session 需要 MFA 且尚未完成验证，不认为已登录（防绕过）
    if session.get("mfa_required") == 1 and session.get("mfa_verified") != 1:
        return None

    # 过滤敏感信息
    safe_user = {
        "id": user["id"],
        "email": user["email"],
        "name": user["name"],
        "username": user["username"],
        "phone": user.get("phone"),
        "is_admin": bool(user.get("is_admin", 0)),  # 使用数据库字段，不再硬编码邮箱
    }
    return safe_user

async def require_login(request: Request, current_user: dict = Depends(get_current_user)):
    """要求用户必须登录"""
    if not current_user:
        from fastapi.responses import RedirectResponse
        # 获取当前路径，用于登录后重定向
        current_path = request.url.path
        query_params = request.url.query

        # 构造重定向 URL
        redirect_url = f"/login?redirect_uri={current_path}"
        if query_params:
            redirect_url += f"?{query_params}"

        raise HTTPException(
            status_code=303,
            detail=redirect_url
        )
    return current_user

def require_admin(request: Request, current_user: dict = Depends(require_login)):
    """要求用户为管理员"""
    if not current_user.get("is_admin"):
        # 抛出 403 异常，并在 main.py 的异常处理器中渲染模板
        raise HTTPException(status_code=403, detail="无管理员权限")
    return current_user