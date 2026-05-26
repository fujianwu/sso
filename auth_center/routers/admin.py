"""
管理员路由 - 修复版本
"""
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from typing import Optional, List
import json

from ..config import config
from ..database import UserDB, SessionDB, AppDB, ConfigDB, CustomFieldDB, UserCustomDataDB, PortalTokenDB, AuditLogDB
from ..auth import hash_password, validate_password
from ..performance import CacheManager
from ..dependencies import require_admin, require_login

router = APIRouter()

# ==================== 数据模型 ====================

class AppRegister(BaseModel):
    app_name: str = Field(..., min_length=1, max_length=100)
    redirect_uris: str  # 逗号分隔的字符串或 JSON
    description: Optional[str] = None
    app_url: Optional[str] = None
    icon_url: Optional[str] = None

class WhitelistEmail(BaseModel):
    email: str

class WhitelistImport(BaseModel):
    emails: List[str]

class RegistrationConfig(BaseModel):
    emails: Optional[str] = None  # 逗号分隔或 JSON 字符串

# ==================== 应用管理 API ====================

@router.get("/api/admin/apps")
async def get_admin_apps(current_user: dict = Depends(require_admin)):
    """获取所有注册应用列表"""
    apps = AppDB.get_all_apps()
    full_apps = [
        {
            "client_id": a["client_id"],
            "client_secret": a["client_secret"],
            "app_name": a["app_name"],
            "redirect_uris": json.loads(a["redirect_uris"]) if isinstance(a["redirect_uris"], str) else a["redirect_uris"],
            "description": a["description"],
            "app_url": a.get("app_url"),
            "icon_url": a.get("icon_url"),
            "created_at": a["created_at"]
        }
        for a in apps
    ]
    return full_apps

@router.post("/api/admin/app")
async def register_app(app_data: AppRegister, current_user: dict = Depends(require_admin)):
    """注册新应用"""

    # 1. 解析 redirect_uris - 支持逗号分隔或 JSON 格式
    try:
        # 先尝试作为 JSON 解析
        if app_data.redirect_uris.strip().startswith('['):
            redirect_uris = json.loads(app_data.redirect_uris)
        else:
            # 按逗号分隔解析
            redirect_uris = [uri.strip() for uri in app_data.redirect_uris.split(',') if uri.strip()]

        if not redirect_uris or not all(isinstance(uri, str) and uri.startswith(('http://', 'https://')) for uri in redirect_uris):
            raise ValueError("redirect_uris 必须是以 http:// 或 https:// 开头的有效 URL 列表")

    except json.JSONDecodeError:
        # 如果 JSON 解析失败，尝试逗号分隔
        redirect_uris = [uri.strip() for uri in app_data.redirect_uris.split(',') if uri.strip()]
        if not redirect_uris:
            raise HTTPException(status_code=400, detail="redirect_uris 不能为空")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 2. 创建应用
    app_result = AppDB.create_app(
        app_data.app_name,
        redirect_uris,
        app_data.description,
        app_data.app_url,
        app_data.icon_url
    )

    # 清除缓存，确保新创建的应用能即时生效
    CacheManager.delete(f"get_app_by_client_id:('{app_result['client_id']}',):{{}}")

    AuditLogDB.log(
        action_type="APP_CREATE",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="app",
        target_id=app_result["client_id"],
        detail=f"注册应用: {app_data.app_name}",
    )
    return {
        "message": "应用注册成功",
        "client_id": app_result["client_id"],
        "client_secret": app_result["client_secret"],
        "app_name": app_result["app_name"]
    }

@router.put("/api/admin/apps/{client_id}")
async def update_app(client_id: str, app_data: AppRegister, current_user: dict = Depends(require_admin)):
    """更新应用信息"""
    app = AppDB.get_app_by_client_id(client_id)
    if not app:
        raise HTTPException(status_code=404, detail="应用不存在")

    # 解析 redirect_uris
    try:
        if app_data.redirect_uris.strip().startswith('['):
            redirect_uris = json.loads(app_data.redirect_uris)
        else:
            redirect_uris = [uri.strip() for uri in app_data.redirect_uris.split(',') if uri.strip()]
        if not redirect_uris or not all(isinstance(uri, str) and uri.startswith(('http://', 'https://')) for uri in redirect_uris):
            raise ValueError("redirect_uris 必须是以 http:// 或 https:// 开头的有效 URL 列表")
    except json.JSONDecodeError:
        redirect_uris = [uri.strip() for uri in app_data.redirect_uris.split(',') if uri.strip()]
        if not redirect_uris:
            raise HTTPException(status_code=400, detail="redirect_uris 不能为空")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    AppDB.update_app(
        client_id,
        app_data.app_name,
        redirect_uris,
        app_data.description,
        app_data.app_url,
        app_data.icon_url
    )

    # 清除缓存
    CacheManager.delete(f"get_app_by_client_id:('{client_id}',):{{}}")

    AuditLogDB.log(
        action_type="APP_UPDATE",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="app",
        target_id=client_id,
        detail=f"更新应用: {app_data.app_name}",
    )
    return {"message": "应用更新成功"}


@router.delete("/api/admin/apps/{client_id}")
async def delete_app(client_id: str, current_user: dict = Depends(require_admin)):
    """删除应用"""
    app = AppDB.get_app_by_client_id(client_id)
    if not app:
        raise HTTPException(status_code=404, detail="应用不存在")

    AppDB.delete_app(client_id)

    # 清除缓存
    CacheManager.delete(f"get_app_by_client_id:('{client_id}',):{{}}")

    AuditLogDB.log(
        action_type="APP_DELETE",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="app",
        target_id=client_id,
        detail=f"删除应用: {app['app_name'] if app else client_id}",
    )
    return {"message": "应用删除成功"}

# ==================== 白名单管理 API ====================

@router.get("/api/admin/whitelist")
async def get_whitelist(current_user: dict = Depends(require_admin)):
    """获取注册白名单"""
    whitelist = config.ALLOWED_REGISTRATION_EMAILS
    is_enabled = whitelist is not None

    return {
        "enabled": is_enabled,
        "emails": whitelist if whitelist else []
    }

@router.post("/api/admin/whitelist/add")
async def add_to_whitelist(
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """添加邮箱到白名单 - 支持 JSON"""
    try:
        data = await request.json()
        email = data.get("email")
    except:
        raise HTTPException(status_code=400, detail="无效的请求数据")

    if not email:
        raise HTTPException(status_code=400, detail="邮箱不能为空")

    whitelist = config.ALLOWED_REGISTRATION_EMAILS
    if whitelist is None:
        whitelist = []

    if email in whitelist:
        raise HTTPException(status_code=400, detail="邮箱已在白名单中")

    whitelist.append(email)
    ConfigDB.set_config("ALLOWED_REGISTRATION_EMAILS", json.dumps(whitelist))
    config.ALLOWED_REGISTRATION_EMAILS = whitelist
    AuditLogDB.log(
        action_type="WHITELIST_ADD",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="whitelist",
        detail=f"添加白名单: {email}",
    )
    return {"message": "添加成功"}

@router.post("/api/admin/whitelist/delete")
async def remove_from_whitelist(
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """从白名单删除邮箱 - 支持 JSON"""
    try:
        data = await request.json()
        email = data.get("email")
    except:
        raise HTTPException(status_code=400, detail="无效的请求数据")

    if not email:
        raise HTTPException(status_code=400, detail="邮箱不能为空")

    whitelist = config.ALLOWED_REGISTRATION_EMAILS
    if whitelist is None or email not in whitelist:
        raise HTTPException(status_code=404, detail="邮箱不在白名单中")

    whitelist.remove(email)
    ConfigDB.set_config("ALLOWED_REGISTRATION_EMAILS", json.dumps(whitelist))
    config.ALLOWED_REGISTRATION_EMAILS = whitelist
    AuditLogDB.log(
        action_type="WHITELIST_REMOVE",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="whitelist",
        detail=f"移除白名单: {email}",
    )
    return {"message": "删除成功"}

@router.post("/api/admin/whitelist/clear")
async def clear_whitelist(current_user: dict = Depends(require_admin)):
    """清空白名单"""
    ConfigDB.set_config("ALLOWED_REGISTRATION_EMAILS", "[]")
    config.ALLOWED_REGISTRATION_EMAILS = []
    AuditLogDB.log(
        action_type="WHITELIST_CLEAR",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="whitelist",
        detail="清空白名单",
    )
    return {"message": "白名单已清空"}

@router.post("/api/admin/whitelist/import")
async def import_whitelist(
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """批量导入白名单 - 支持 JSON"""
    try:
        data = await request.json()
        emails = data.get("emails", [])
    except:
        raise HTTPException(status_code=400, detail="无效的请求数据")

    if not emails:
        raise HTTPException(status_code=400, detail="邮箱列表不能为空")

    # 去重并过滤空值
    unique_emails = list(set([e.strip() for e in emails if e and e.strip()]))

    if not unique_emails:
        raise HTTPException(status_code=400, detail="没有有效的邮箱地址")

    # 合并现有白名单
    existing = config.ALLOWED_REGISTRATION_EMAILS or []
    all_emails = list(set(existing + unique_emails))

    ConfigDB.set_config("ALLOWED_REGISTRATION_EMAILS", json.dumps(all_emails))
    config.ALLOWED_REGISTRATION_EMAILS = all_emails

    return {
        "message": f"成功导入 {len(unique_emails)} 个邮箱",
        "success": len(unique_emails),
        "skipped": len(unique_emails) - (len(all_emails) - len(existing))
    }

@router.post("/api/admin/whitelist/enable")
async def enable_whitelist(current_user: dict = Depends(require_admin)):
    """启用白名单"""
    if config.ALLOWED_REGISTRATION_EMAILS is None:
        config.ALLOWED_REGISTRATION_EMAILS = []
        ConfigDB.set_config("ALLOWED_REGISTRATION_EMAILS", "[]")

    AuditLogDB.log(
        action_type="WHITELIST_ENABLE",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="whitelist",
        detail="启用注册白名单",
    )
    return {"message": "白名单已启用"}

@router.post("/api/admin/whitelist/disable")
async def disable_whitelist(current_user: dict = Depends(require_admin)):
    """禁用白名单"""
    config.ALLOWED_REGISTRATION_EMAILS = None
    ConfigDB.set_config("ALLOWED_REGISTRATION_EMAILS", "null")

    AuditLogDB.log(
        action_type="WHITELIST_DISABLE",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="whitelist",
        detail="禁用注册白名单",
    )
    return {"message": "白名单已禁用"}

# ==================== 注册配置 API ====================

@router.get("/api/admin/config/registration")
async def get_registration_config(current_user: dict = Depends(require_admin)):
    """获取注册配置"""
    emails = config.ALLOWED_REGISTRATION_EMAILS
    return {
        "emails": ",".join(emails) if emails else "",
        "enabled": emails is not None
    }

@router.post("/api/admin/config/registration")
async def update_registration_config(
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """更新注册配置 - 支持 JSON"""
    try:
        data = await request.json()
        emails_str = data.get("emails", "")
    except:
        raise HTTPException(status_code=400, detail="无效的请求数据")

    # 解析邮箱列表
    if not emails_str or emails_str.strip() == "":
        # 空字符串表示禁用注册
        config.ALLOWED_REGISTRATION_EMAILS = None
        ConfigDB.set_config("ALLOWED_REGISTRATION_EMAILS", "null")
        return {"message": "自主注册已禁用"}

    # 解析邮箱 - 支持逗号或换行分隔
    emails = []
    for line in emails_str.replace(',', '\n').split('\n'):
        email = line.strip()
        if email and '@' in email:
            emails.append(email)

    if not emails:
        raise HTTPException(status_code=400, detail="没有有效的邮箱地址")

    # 保存配置
    unique_emails = list(set(emails))
    ConfigDB.set_config("ALLOWED_REGISTRATION_EMAILS", json.dumps(unique_emails))
    config.ALLOWED_REGISTRATION_EMAILS = unique_emails

    return {"message": f"配置已更新，共 {len(unique_emails)} 个邮箱"}

# ==================== 自定义字段管理 ====================

@router.get("/api/admin/fields")
async def get_admin_fields(current_user: dict = Depends(require_admin)):
    """获取所有自定义字段定义"""
    fields = CustomFieldDB.get_all_fields()
    return fields

@router.post("/api/admin/fields")
async def add_custom_field(
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """添加自定义字段"""
    try:
        data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="无效的 JSON 数据")

    field_key = data.get("field_key")
    field_label = data.get("field_label")
    field_type = data.get("field_type", "text")
    field_options = data.get("field_options")
    is_required = data.get("is_required", False)
    show_in_profile = data.get("show_in_profile", True)
    show_in_oauth = data.get("show_in_oauth", False)
    display_order = data.get("display_order", 0)

    if not field_key or not field_label:
        raise HTTPException(status_code=400, detail="field_key 和 field_label 是必填项")

    valid_types = ["text", "textarea", "number", "date", "email", "phone", "select", "radio", "checkbox"]
    if field_type not in valid_types:
        raise HTTPException(status_code=400, detail="无效的字段类型")

    if CustomFieldDB.get_field_by_key(field_key):
        raise HTTPException(status_code=400, detail="字段 Key 已存在")

    # 处理 field_options
    if field_options:
        if isinstance(field_options, str):
            try:
                field_options = json.loads(field_options)
            except:
                raise HTTPException(status_code=400, detail="field_options 必须是有效的 JSON")
        if isinstance(field_options, list):
            field_options = json.dumps(field_options)

    CustomFieldDB.create_field(
        field_key, field_label, field_type, field_options,
        is_required, show_in_profile, show_in_oauth, display_order
    )

    return {"message": "自定义字段添加成功"}

@router.put("/api/admin/fields/{field_key}")
async def update_custom_field(
    field_key: str,
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """更新自定义字段"""
    if not CustomFieldDB.get_field_by_key(field_key):
        raise HTTPException(status_code=404, detail="字段 Key 不存在")

    try:
        data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="无效的 JSON 数据")

    field_label = data.get("field_label")
    field_type = data.get("field_type", "text")
    field_options = data.get("field_options")
    is_required = data.get("is_required", False)
    show_in_profile = data.get("show_in_profile", True)
    show_in_oauth = data.get("show_in_oauth", False)
    display_order = data.get("display_order", 0)

    if not field_label:
        raise HTTPException(status_code=400, detail="field_label 是必填项")

    if field_options:
        if isinstance(field_options, str):
            try:
                field_options = json.loads(field_options)
            except:
                raise HTTPException(status_code=400, detail="field_options 必须是有效的 JSON")
        if isinstance(field_options, list):
            field_options = json.dumps(field_options)

    CustomFieldDB.update_field(
        field_key, field_label, field_type, field_options,
        is_required, show_in_profile, show_in_oauth, display_order
    )

    return {"message": "自定义字段更新成功"}

@router.delete("/api/admin/fields/{field_key}")
async def delete_custom_field(
    field_key: str,
    current_user: dict = Depends(require_admin)
):
    """删除自定义字段"""
    if not CustomFieldDB.get_field_by_key(field_key):
        raise HTTPException(status_code=404, detail="字段 Key 不存在")

    CustomFieldDB.delete_field(field_key)
    return {"message": "自定义字段删除成功"}

# ==================== 用户管理 ====================

@router.get("/api/admin/users")
async def get_admin_users(current_user: dict = Depends(require_admin)):
    """获取所有用户列表"""
    users = UserDB.get_all_users()
    safe_users = [
        {
            "id": u["id"],
            "email": u["email"],
            "name": u["name"],
            "username": u.get("username"),
            "is_admin": bool(u.get("is_admin")),
            "avatar_url": u.get("avatar_url"),
            "created_at": u["created_at"]
        }
        for u in users
    ]
    return safe_users

@router.post("/api/admin/user")
async def add_user(
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """添加新用户"""
    try:
        data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="无效的 JSON 数据")

    email = data.get("email")
    password = data.get("password")
    name = data.get("name")
    username = data.get("username")
    is_admin = data.get("is_admin", 0)
    custom_data = data.get("custom_data", {})

    if not email or not password or not name:
        raise HTTPException(status_code=400, detail="email, password 和 name 是必填项")

    from ..auth import validate_email
    if not validate_email(email):
        raise HTTPException(status_code=400, detail="邮箱格式不正确")

    if UserDB.get_user_by_email(email):
        raise HTTPException(status_code=400, detail="该邮箱已被注册")

    if username and UserDB.get_user_by_username(username):
        raise HTTPException(status_code=400, detail="该用户名已被使用")

    is_valid, error_msg = validate_password(password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)

    password_hash = hash_password(password)
    user_id = UserDB.create_user(email, password_hash, name, username=username)

    if is_admin:
        UserDB.update_user(user_id, is_admin=1)

    for field_key, field_value in custom_data.items():
        if field_value:
            UserCustomDataDB.set_user_data(user_id, field_key, field_value)

    AuditLogDB.log(
        action_type="USER_CREATE",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="user",
        target_id=user_id,
        detail=f"创建用户: {email}",
        ip_address=request.client.host if request.client else None,
    )
    return {"message": "用户添加成功", "user_id": user_id}

@router.put("/api/admin/users/{user_id}")
async def update_user(
    user_id: int,
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """更新用户信息"""
    db_user = UserDB.get_user_by_id(user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="用户不存在")

    try:
        data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="无效的 JSON 数据")

    name = data.get("name")
    username = data.get("username")
    password = data.get("password")
    is_admin = data.get("is_admin")
    custom_data = data.get("custom_data", {})

    update_fields = {}
    if name:
        update_fields["name"] = name
    if is_admin is not None:
        update_fields["is_admin"] = 1 if is_admin else 0
    if username is not None:
        existing = UserDB.get_user_by_username(username)
        if existing and existing["id"] != user_id:
            raise HTTPException(status_code=400, detail="该用户名已被使用")
        update_fields["username"] = username

    if password:
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error_msg)
        update_fields["password_hash"] = hash_password(password)
        SessionDB.delete_user_sessions(user_id)

    if update_fields:
        UserDB.update_user(user_id, **update_fields)

    for field_key, field_value in custom_data.items():
        UserCustomDataDB.set_user_data(user_id, field_key, field_value)

    changed = list(update_fields.keys())
    AuditLogDB.log(
        action_type="USER_UPDATE",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="user",
        target_id=user_id,
        detail=f"更新字段: {', '.join(changed) or '自定义数据'} (用户: {db_user['email']})",
        ip_address=request.client.host if request.client else None,
    )
    return {"message": "用户信息更新成功"}

@router.get("/api/user/{user_id}/custom-data")
async def get_user_custom_data(
    user_id: int,
    current_user: dict = Depends(require_admin)
):
    """获取用户的自定义字段数据"""
    custom_data = UserCustomDataDB.get_all_user_data(user_id)
    return {"custom_data": custom_data}

@router.post("/api/admin/users/import")
async def import_users(
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """批量导入用户"""
    try:
        data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="无效的 JSON 数据")

    users = data.get("users", [])
    if not users:
        raise HTTPException(status_code=400, detail="没有提供用户数据")

    success_count = 0
    failed_count = 0
    errors = []

    for user_data in users:
        try:
            email = user_data.get("email")
            password = user_data.get("password")
            name = user_data.get("name")
            username = user_data.get("username")

            if not email or not password or not name:
                errors.append(f"{email or '未知'}: 缺少必填字段")
                failed_count += 1
                continue

            if UserDB.get_user_by_email(email):
                errors.append(f"{email}: 邮箱已存在")
                failed_count += 1
                continue

            if username and UserDB.get_user_by_username(username):
                errors.append(f"{email}: 用户名已被使用")
                failed_count += 1
                continue

            password_hash = hash_password(password)
            UserDB.create_user(email, password_hash, name, username=username)
            success_count += 1

        except Exception as e:
            errors.append(f"{user_data.get('email', '未知')}: {str(e)}")
            failed_count += 1

    return {
        "message": "导入完成",
        "success": success_count,
        "failed": failed_count,
        "errors": errors[:10]
    }

@router.delete("/api/admin/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: dict = Depends(require_admin)
):
    """删除用户"""
    db_user = UserDB.get_user_by_id(user_id)
    if not db_user:
        raise HTTPException(status_code=404, detail="用户不存在")

    if user_id == current_user["id"]:
        raise HTTPException(status_code=400, detail="不能删除自己的账户")

    UserDB.delete_user(user_id)
    AuditLogDB.log(
        action_type="USER_DELETE",
        operator_id=current_user["id"],
        operator_email=current_user["email"],
        target_type="user",
        target_id=user_id,
        detail=f"删除用户: {db_user['email']}",
    )
    return {"message": f"用户 {db_user['email']} 已删除"}

# ==================== Portal Token 管理 ====================

class PortalTokenCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)

@router.get("/api/admin/portal-tokens")
async def get_portal_tokens(current_user: dict = Depends(require_admin)):
    """获取所有 Portal API Token"""
    tokens = PortalTokenDB.get_all_tokens(current_user["id"])
    # 脱敏：只显示前8位
    for t in tokens:
        t["token_preview"] = t["token"][:15] + "..."
    return {"tokens": tokens}

@router.post("/api/admin/portal-tokens")
async def create_portal_token(data: PortalTokenCreate, current_user: dict = Depends(require_admin)):
    """创建新的 Portal API Token"""
    token = PortalTokenDB.create_token(data.name, current_user["id"])
    return {"success": True, "token": token, "name": data.name}

@router.delete("/api/admin/portal-tokens/{token_id}")
async def delete_portal_token(token_id: int, current_user: dict = Depends(require_admin)):
    """删除 Portal API Token"""
    PortalTokenDB.delete_token(token_id, current_user["id"])
    return {"success": True, "message": "Token 已删除"}

# ==================== Portal 公开 API（供门户平台调用）====================

@router.get("/api/portal/apps")
async def portal_get_apps(request: Request):
    """
    Portal 公开 API：获取应用列表（需要 Portal API Token）
    供一站式门户平台调用，返回有 app_url 的应用列表
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="缺少 Authorization header")

    token = auth_header.replace("Bearer ", "").strip()
    token_info = PortalTokenDB.verify_token(token)
    if not token_info:
        raise HTTPException(status_code=401, detail="无效的 Portal API Token")

    apps = AppDB.get_all_apps()
    portal_apps = []
    for a in apps:
        try:
            redirect_uris = json.loads(a["redirect_uris"]) if isinstance(a["redirect_uris"], str) else a["redirect_uris"]
        except Exception:
            redirect_uris = []

        portal_apps.append({
            "client_id": a["client_id"],
            "app_name": a["app_name"],
            "description": a.get("description"),
            "app_url": a.get("app_url"),
            "icon_url": a.get("icon_url"),
            "redirect_uris": redirect_uris,
        })

    return {"apps": portal_apps, "sso_server": str(request.base_url).rstrip("/")}


# ===== 咨询消息管理 API =====

@router.patch("/api/admin/messages/{msg_id}/status")
@router.post("/api/admin/messages/{msg_id}/status")
async def update_message_status(
    msg_id: int,
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """更新咨询消息状态"""
    from auth_center.database import get_db
    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    status = body.get("status", "processed")

    with get_db() as conn:
        result = conn.execute(
            "UPDATE contact_messages SET status = ? WHERE id = ?",
            (status, msg_id)
        )
        conn.commit()
        if result.rowcount == 0:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="消息不存在")

    return {"success": True, "message": "状态已更新"}


@router.delete("/api/admin/messages/{msg_id}")
async def delete_message(
    msg_id: int,
    current_user: dict = Depends(require_admin)
):
    """删除咨询消息"""
    from auth_center.database import get_db
    with get_db() as conn:
        conn.execute("DELETE FROM contact_messages WHERE id = ?", (msg_id,))
        conn.commit()
    return {"success": True, "message": "消息已删除"}


# ═══════════════════════════════════════════════════════
# 消息系统 v2
# 两种模式：
#   1. 广播 (broadcast)  — 管理员 → 所有用户，单向，类公众号推文
#   2. 对话 (conversation) — 用户 ↔ 管理员，双向聊天，类微信私聊
# ═══════════════════════════════════════════════════════

def _ensure_msg_tables():
    """建表（首次调用自动初始化）"""
    from auth_center.database import get_db
    with get_db() as conn:
        conn.executescript("""
            -- 广播表
            CREATE TABLE IF NOT EXISTS broadcasts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                title       TEXT NOT NULL,
                body        TEXT NOT NULL,
                admin_id    INTEGER NOT NULL,
                admin_name  TEXT NOT NULL DEFAULT '管理员',
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- 对话会话表（每个用户可开多个会话）
            CREATE TABLE IF NOT EXISTS conversations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                subject     TEXT NOT NULL DEFAULT '新会话',
                status      TEXT NOT NULL DEFAULT 'open',  -- open / closed
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- 对话消息表
            CREATE TABLE IF NOT EXISTS conv_messages (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                conv_id         INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                sender_id       INTEGER NOT NULL,   -- 用户ID 或 0=管理员
                sender_role     TEXT NOT NULL,       -- 'user' | 'admin'
                sender_name     TEXT NOT NULL,
                body            TEXT NOT NULL,
                is_read         INTEGER NOT NULL DEFAULT 0,
                created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()


# ──────────────── 广播 API ────────────────

@router.get("/api/admin/broadcasts")
async def admin_list_broadcasts(current_user: dict = Depends(require_admin)):
    _ensure_msg_tables()
    from auth_center.database import get_db
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM broadcasts ORDER BY created_at DESC"
        ).fetchall()
    return {"success": True, "broadcasts": [dict(r) for r in rows]}


@router.post("/api/admin/broadcasts")
async def admin_create_broadcast(request: Request, current_user: dict = Depends(require_admin)):
    _ensure_msg_tables()
    from auth_center.database import get_db
    body = await request.json()
    title = body.get("title", "").strip()
    text  = body.get("body", "").strip()
    if not title or not text:
        raise HTTPException(status_code=400, detail="标题和内容不能为空")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO broadcasts (title, body, admin_id, admin_name) VALUES (?,?,?,?)",
            (title, text, current_user["id"], current_user.get("name","管理员"))
        )
        conn.commit()
    return {"success": True, "message": "广播已发送"}


@router.delete("/api/admin/broadcasts/{bid}")
async def admin_delete_broadcast(bid: int, current_user: dict = Depends(require_admin)):
    from auth_center.database import get_db
    with get_db() as conn:
        conn.execute("DELETE FROM broadcasts WHERE id=?", (bid,))
        conn.commit()
    return {"success": True}


# ──────────────── 管理员对话 API ────────────────

@router.get("/api/admin/conversations")
async def admin_list_conversations(current_user: dict = Depends(require_admin)):
    """管理员查看所有对话（带未读数、最新消息、用户信息）"""
    _ensure_msg_tables()
    from auth_center.database import get_db
    with get_db() as conn:
        rows = conn.execute("""
            SELECT
                c.id, c.subject, c.status, c.updated_at,
                u.id   AS user_id,
                u.name AS user_name,
                u.email AS user_email,
                (SELECT body FROM conv_messages WHERE conv_id=c.id ORDER BY created_at DESC LIMIT 1) AS last_msg,
                (SELECT COUNT(*) FROM conv_messages WHERE conv_id=c.id AND sender_role='user' AND is_read=0) AS unread
            FROM conversations c
            JOIN users u ON c.user_id = u.id
            ORDER BY c.updated_at DESC
        """).fetchall()
    return {"success": True, "conversations": [dict(r) for r in rows]}


@router.get("/api/admin/conversations/{cid}/messages")
async def admin_get_conv_messages(cid: int, current_user: dict = Depends(require_admin)):
    from auth_center.database import get_db
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM conv_messages WHERE conv_id=? ORDER BY created_at ASC", (cid,)
        ).fetchall()
        # 标记用户消息已读
        conn.execute(
            "UPDATE conv_messages SET is_read=1 WHERE conv_id=? AND sender_role='user'", (cid,)
        )
        conn.commit()
    return {"success": True, "messages": [dict(r) for r in rows]}


@router.post("/api/admin/conversations/{cid}/reply")
async def admin_reply(cid: int, request: Request, current_user: dict = Depends(require_admin)):
    from auth_center.database import get_db
    body = (await request.json()).get("body", "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="内容不能为空")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO conv_messages (conv_id, sender_id, sender_role, sender_name, body) VALUES (?,?,?,?,?)",
            (cid, current_user["id"], "admin", current_user.get("name","管理员"), body)
        )
        conn.execute(
            "UPDATE conversations SET updated_at=CURRENT_TIMESTAMP WHERE id=?", (cid,)
        )
        conn.commit()
    return {"success": True}


@router.post("/api/admin/conversations/{cid}/close")
async def admin_close_conv(cid: int, current_user: dict = Depends(require_admin)):
    from auth_center.database import get_db
    with get_db() as conn:
        conn.execute("UPDATE conversations SET status='closed' WHERE id=?", (cid,))
        conn.commit()
    return {"success": True}


@router.get("/api/admin/conversations/unread-count")
async def admin_unread_count(current_user: dict = Depends(require_admin)):
    _ensure_msg_tables()
    from auth_center.database import get_db
    with get_db() as conn:
        count = conn.execute("""
            SELECT COUNT(*) FROM conv_messages
            WHERE sender_role='user' AND is_read=0
        """).fetchone()[0]
    return {"success": True, "count": count}


# ──────────────── 用户侧 API ────────────────

@router.get("/api/broadcasts")
async def user_list_broadcasts(current_user: dict = Depends(require_login)):
    """用户查看广播列表"""
    _ensure_msg_tables()
    from auth_center.database import get_db
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM broadcasts ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
    return {"success": True, "broadcasts": [dict(r) for r in rows]}


@router.get("/api/conversations")
async def user_list_conversations(current_user: dict = Depends(require_login)):
    """用户查看自己的对话列表"""
    _ensure_msg_tables()
    from auth_center.database import get_db
    uid = current_user["id"]
    with get_db() as conn:
        # 建软删除表（如果还没建）
        conn.execute("""
            CREATE TABLE IF NOT EXISTS conv_user_deletes (
                user_id INTEGER NOT NULL,
                conv_id INTEGER NOT NULL,
                deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, conv_id)
            )
        """)
        rows = conn.execute("""
            SELECT
                c.id, c.subject, c.status, c.updated_at,
                (SELECT body FROM conv_messages WHERE conv_id=c.id ORDER BY created_at DESC LIMIT 1) AS last_msg,
                (SELECT COUNT(*) FROM conv_messages WHERE conv_id=c.id AND sender_role='admin' AND is_read=0) AS unread
            FROM conversations c
            WHERE c.user_id=?
              AND c.id NOT IN (
                SELECT conv_id FROM conv_user_deletes WHERE user_id=?
              )
            ORDER BY c.updated_at DESC
        """, (uid, uid)).fetchall()
    return {"success": True, "conversations": [dict(r) for r in rows]}


@router.post("/api/conversations")
async def user_create_conversation(request: Request, current_user: dict = Depends(require_login)):
    """用户发起新对话（来自联系我们或收件箱）"""
    _ensure_msg_tables()
    from auth_center.database import get_db
    body = await request.json()
    subject = body.get("subject", "新咨询").strip() or "新咨询"
    first_msg = body.get("body", "").strip()
    if not first_msg:
        raise HTTPException(status_code=400, detail="消息内容不能为空")
    uid = current_user["id"]
    uname = current_user.get("name", "用户")
    with get_db() as conn:
        cur = conn.execute(
            "INSERT INTO conversations (user_id, subject) VALUES (?,?)", (uid, subject)
        )
        cid = cur.lastrowid
        conn.execute(
            "INSERT INTO conv_messages (conv_id, sender_id, sender_role, sender_name, body) VALUES (?,?,?,?,?)",
            (cid, uid, "user", uname, first_msg)
        )
        conn.commit()
    return {"success": True, "conversation_id": cid}


@router.get("/api/conversations/{cid}/messages")
async def user_get_messages(cid: int, current_user: dict = Depends(require_login)):
    from auth_center.database import get_db
    uid = current_user["id"]
    with get_db() as conn:
        # 验证权限
        conv = conn.execute(
            "SELECT id FROM conversations WHERE id=? AND user_id=?", (cid, uid)
        ).fetchone()
        if not conv:
            raise HTTPException(status_code=404, detail="对话不存在")
        rows = conn.execute(
            "SELECT * FROM conv_messages WHERE conv_id=? ORDER BY created_at ASC", (cid,)
        ).fetchall()
        # 标记管理员消息已读
        conn.execute(
            "UPDATE conv_messages SET is_read=1 WHERE conv_id=? AND sender_role='admin'", (cid,)
        )
        conn.commit()
    return {"success": True, "messages": [dict(r) for r in rows]}


@router.post("/api/conversations/{cid}/messages")
async def user_send_message(cid: int, request: Request, current_user: dict = Depends(require_login)):
    from auth_center.database import get_db
    uid = current_user["id"]
    body = (await request.json()).get("body", "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="内容不能为空")
    with get_db() as conn:
        conv = conn.execute(
            "SELECT id, status FROM conversations WHERE id=? AND user_id=?", (cid, uid)
        ).fetchone()
        if not conv:
            raise HTTPException(status_code=404, detail="对话不存在")
        if conv["status"] == "closed":
            raise HTTPException(status_code=400, detail="该对话已关闭")
        conn.execute(
            "INSERT INTO conv_messages (conv_id, sender_id, sender_role, sender_name, body) VALUES (?,?,?,?,?)",
            (cid, uid, "user", current_user.get("name","用户"), body)
        )
        conn.execute("UPDATE conversations SET updated_at=CURRENT_TIMESTAMP WHERE id=?", (cid,))
        conn.commit()
    return {"success": True}


@router.delete("/api/conversations/{cid}")
async def user_delete_conversation(cid: int, current_user: dict = Depends(require_login)):
    """
    用户删除对话——仅从自己视角隐藏，对方（管理员）仍可见。
    用 conv_user_deletes 表记录，查询时过滤。
    """
    _ensure_msg_tables()
    from auth_center.database import get_db
    uid = current_user["id"]
    with get_db() as conn:
        # 建软删除表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS conv_user_deletes (
                user_id INTEGER NOT NULL,
                conv_id INTEGER NOT NULL,
                deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, conv_id)
            )
        """)
        # 确认对话属于自己
        conv = conn.execute(
            "SELECT id FROM conversations WHERE id=? AND user_id=?", (cid, uid)
        ).fetchone()
        if not conv:
            raise HTTPException(status_code=404, detail="对话不存在")
        conn.execute(
            "INSERT OR REPLACE INTO conv_user_deletes (user_id, conv_id) VALUES (?,?)",
            (uid, cid)
        )
        conn.commit()
    return {"success": True}


@router.post("/api/conversations/{cid}/restore")
async def user_restore_conversation(cid: int, current_user: dict = Depends(require_login)):
    """恢复被自己删除的对话"""
    from auth_center.database import get_db
    uid = current_user["id"]
    with get_db() as conn:
        conn.execute(
            "DELETE FROM conv_user_deletes WHERE user_id=? AND conv_id=?", (uid, cid)
        )
        conn.commit()
    return {"success": True}


@router.get("/api/inbox/unread-count")
async def user_inbox_unread(current_user: dict = Depends(require_login)):
    """未读数（管理员回复中未读的消息数）"""
    _ensure_msg_tables()
    from auth_center.database import get_db
    uid = current_user["id"]
    with get_db() as conn:
        count = conn.execute("""
            SELECT COUNT(*) FROM conv_messages m
            JOIN conversations c ON m.conv_id=c.id
            WHERE c.user_id=? AND m.sender_role='admin' AND m.is_read=0
        """, (uid,)).fetchone()[0]
    return {"success": True, "count": count}


# ──────────────── 图片上传 ────────────────

@router.post("/api/conversations/upload-image")
async def upload_conv_image(
    request: Request,
    current_user: dict = Depends(require_login)
):
    """聊天图片上传（存为 base64 data URL，适合小图）"""
    import base64
    from fastapi import UploadFile, File
    form = await request.form()
    file: UploadFile = form.get("image")
    if not file:
        raise HTTPException(status_code=400, detail="未收到文件")
    # 限制大小 2MB
    data = await file.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="图片不能超过 2MB")
    # 校验类型
    ct = file.content_type or ""
    if not ct.startswith("image/"):
        raise HTTPException(status_code=400, detail="只支持图片格式")
    b64 = base64.b64encode(data).decode()
    data_url = f"data:{ct};base64,{b64}"
    return {"success": True, "data_url": data_url}


# ──────────────── 管理员主动发起对话 ────────────────

@router.post("/api/admin/conversations/start")
async def admin_start_conversation(
    request: Request,
    current_user: dict = Depends(require_admin)
):
    """管理员主动向某用户发起对话"""
    _ensure_msg_tables()
    from auth_center.database import get_db
    body = await request.json()
    user_id = body.get("user_id")
    subject = body.get("subject", "管理员消息").strip() or "管理员消息"
    first_msg = body.get("body", "").strip()
    if not user_id or not first_msg:
        raise HTTPException(status_code=400, detail="收件人和消息内容不能为空")
    admin_name = current_user.get("name", "管理员")
    with get_db() as conn:
        # 检查用户存在
        user = conn.execute("SELECT id, name FROM users WHERE id=?", (int(user_id),)).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="用户不存在")
        cur = conn.execute(
            "INSERT INTO conversations (user_id, subject) VALUES (?,?)",
            (int(user_id), subject)
        )
        cid = cur.lastrowid
        conn.execute(
            "INSERT INTO conv_messages (conv_id, sender_id, sender_role, sender_name, body) VALUES (?,?,?,?,?)",
            (cid, current_user["id"], "admin", admin_name, first_msg)
        )
        conn.commit()
    return {"success": True, "conversation_id": cid, "message": f"已向 {user['name']} 发起对话"}


# ──────────────── 撤回消息 ────────────────

@router.delete("/api/conversations/{cid}/messages/{mid}")
async def retract_conv_message(
    cid: int, mid: int,
    current_user: dict = Depends(require_login)
):
    """
    撤回消息：
    - 用户/管理员只能撤回自己发的
    - 普通用户视角显示 [已撤回]
    - 管理员查询时同时返回 retracted_body（原始内容），供审核
    """
    from auth_center.database import get_db
    uid = current_user["id"]
    with get_db() as conn:
        # 自动补列（兼容旧数据库没有 retracted_body 列的情况）
        try:
            conn.execute("ALTER TABLE conv_messages ADD COLUMN retracted_body TEXT")
            conn.commit()
        except Exception:
            pass  # 列已存在，忽略

        msg = conn.execute(
            "SELECT sender_id, sender_role, body FROM conv_messages WHERE id=? AND conv_id=?",
            (mid, cid)
        ).fetchone()
        if not msg:
            raise HTTPException(status_code=404, detail="消息不存在")

        # 只能撤回自己发的
        if msg["sender_id"] != uid:
            raise HTTPException(status_code=403, detail="只能撤回自己发的消息")

        if msg["body"] == "[已撤回]":
            raise HTTPException(status_code=400, detail="消息已经撤回过了")

        # 备份原始内容到 retracted_body，正文替换为 [已撤回]
        conn.execute(
            "UPDATE conv_messages SET retracted_body=body, body='[已撤回]' WHERE id=?",
            (mid,)
        )
        conn.commit()
    return {"success": True}


# ──────────────── 审计日志 API ────────────────

@router.get("/api/admin/login-logs")
async def admin_get_login_logs(
    request: Request,
    current_user: dict = Depends(require_admin),
    limit: int = 20,
    offset: int = 0,
    email: Optional[str] = None,
    status: Optional[str] = None,
    login_source: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    """登录日志查询 — 支持分页和多维筛选"""
    from auth_center.database import get_db
    with get_db() as conn:
        conditions = []
        params = []

        if email:
            conditions.append("email LIKE ?")
            params.append(f"%{email}%")
        if status:
            conditions.append("status = ?")
            params.append(status)
        if login_source:
            conditions.append("message LIKE ?")
            params.append(f"%{login_source}%")
        if start_time:
            conditions.append("login_time >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("login_time <= ?")
            params.append(end_time)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM login_logs {where}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"SELECT * FROM login_logs {where} ORDER BY login_time DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()

    return {
        "success": True,
        "total": total,
        "data": [dict(r) for r in rows],
    }


@router.get("/api/admin/audit-logs")
async def admin_get_audit_logs(
    request: Request,
    current_user: dict = Depends(require_admin),
    limit: int = 20,
    offset: int = 0,
    operator_id: Optional[str] = None,
    user_id: Optional[str] = None,
    action_type: Optional[str] = None,
    target_type: Optional[str] = None,
    success: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    """操作审计日志查询 — 支持分页和多维筛选。

    审计日志通过解析 login_logs 中的操作记录生成，并额外暴露来自
    用户操作（密码修改、资料更新、MFA 变更等）的记录。
    后续可扩展独立 audit_logs 表来记录更细粒度的操作。
    """
    from auth_center.database import get_db

    # 确保 audit_logs 表存在（懒建表，兼容旧库）
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operator_id INTEGER,
                operator_email TEXT,
                action_type TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                detail TEXT,
                success INTEGER DEFAULT 1,
                ip_address TEXT,
                action_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

    with get_db() as conn:
        conditions = []
        params = []

        if operator_id:
            conditions.append("(operator_id = ? OR operator_email LIKE ?)")
            params.extend([operator_id, f"%{operator_id}%"])
        if user_id:
            conditions.append("target_id = ?")
            params.append(user_id)
        if action_type:
            conditions.append("action_type = ?")
            params.append(action_type)
        if target_type:
            conditions.append("target_type = ?")
            params.append(target_type)
        if success is not None and success != "":
            conditions.append("success = ?")
            params.append(1 if success in ("true", "1", "True") else 0)
        if start_time:
            conditions.append("action_time >= ?")
            params.append(start_time)
        if end_time:
            conditions.append("action_time <= ?")
            params.append(end_time)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM audit_logs {where}", params
        ).fetchone()[0]

        rows = conn.execute(
            f"SELECT * FROM audit_logs {where} ORDER BY action_time DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        ).fetchall()

    return {
        "success": True,
        "total": total,
        "data": [dict(r) for r in rows],
    }
