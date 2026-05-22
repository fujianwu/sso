"""
管理员路由 - 修复版本
"""
from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from typing import Optional, List
import json

from ..config import config
from ..database import UserDB, SessionDB, AppDB, ConfigDB, CustomFieldDB, UserCustomDataDB
from ..auth import hash_password, validate_password
from ..dependencies import require_admin

router = APIRouter()

# ==================== 数据模型 ====================

class AppRegister(BaseModel):
    app_name: str = Field(..., min_length=1, max_length=100)
    redirect_uris: str  # 逗号分隔的字符串或 JSON
    description: Optional[str] = None

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
        app_data.description
    )

    return {
        "message": "应用注册成功",
        "client_id": app_result["client_id"],
        "client_secret": app_result["client_secret"],
        "app_name": app_result["app_name"]
    }

@router.delete("/api/admin/apps/{client_id}")
async def delete_app(client_id: str, current_user: dict = Depends(require_admin)):
    """删除应用"""
    app = AppDB.get_app_by_client_id(client_id)
    if not app:
        raise HTTPException(status_code=404, detail="应用不存在")

    AppDB.delete_app(client_id)
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

    return {"message": "删除成功"}

@router.post("/api/admin/whitelist/clear")
async def clear_whitelist(current_user: dict = Depends(require_admin)):
    """清空白名单"""
    ConfigDB.set_config("ALLOWED_REGISTRATION_EMAILS", "[]")
    config.ALLOWED_REGISTRATION_EMAILS = []

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

    return {"message": "白名单已启用"}

@router.post("/api/admin/whitelist/disable")
async def disable_whitelist(current_user: dict = Depends(require_admin)):
    """禁用白名单"""
    config.ALLOWED_REGISTRATION_EMAILS = None
    ConfigDB.set_config("ALLOWED_REGISTRATION_EMAILS", "null")

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

    for field_key, field_value in custom_data.items():
        if field_value:
            UserCustomDataDB.set_user_data(user_id, field_key, field_value)

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
    custom_data = data.get("custom_data", {})

    update_fields = {}
    if name:
        update_fields["name"] = name
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
    return {"message": f"用户 {db_user['email']} 已删除"}