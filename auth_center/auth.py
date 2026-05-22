"""
增强的认证模块
包含手机验证码、MFA、异常登录检测等功能
"""

import bcrypt
import jwt
import secrets
import re
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
from .config import config
# from .database import LoginLogDB, UserDB, get_db # 避免循环引用

# ===== 密码相关 =====

def hash_password(password: str) -> str:
    """密码哈希"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """验证密码"""
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def validate_password(password: str) -> Tuple[bool, Optional[str]]:
    """
    验证密码强度
    返回: (是否有效, 错误信息)
    """
    if len(password) < config.MIN_PASSWORD_LENGTH:
        return False, f"密码长度至少为 {config.MIN_PASSWORD_LENGTH} 位"

    if config.REQUIRE_PASSWORD_COMPLEXITY:
        # 至少包含一个大写字母、一个小写字母、一个数字
        if not re.search(r'[A-Z]', password):
            return False, "密码必须包含至少一个大写字母"
        if not re.search(r'[a-z]', password):
            return False, "密码必须包含至少一个小写字母"
        if not re.search(r'\d', password):
            return False, "密码必须包含至少一个数字"

    return True, None


def validate_email(email: str) -> bool:
    """验证邮箱格式"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_phone(phone: str) -> bool:
    """验证手机号格式（中国）"""
    pattern = r'^1[3-9]\d{9}$'
    return re.match(pattern, phone) is not None


# ===== JWT Token 相关 =====

def create_jwt_token(data: dict, expires_delta: timedelta) -> str:
    """创建 JWT Token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, config.SECRET_KEY, algorithm=config.ALGORITHM)


def verify_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    """验证 JWT Token"""
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.JWTError:
        return None


def create_access_token(user_id: int, client_id: str, scope: str, token_type: str = "access") -> str:
    """
    创建 Access Token 或 Refresh Token
    """
    if token_type == "access":
        expires_delta = timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    elif token_type == "refresh":
        expires_delta = timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)
    else:
        raise ValueError("Invalid token_type")

    data = {
        "sub": str(user_id),
        "client_id": client_id,
        "scope": scope,
        "token_type": token_type
    }
    return create_jwt_token(data, expires_delta)


def create_refresh_token(user_id: int) -> str:
    """创建刷新令牌"""
    return create_jwt_token(
        {
            "sub": str(user_id),
            "type": "refresh"
        },
        timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)
    )


# ===== 令牌生成 =====

def generate_session_token() -> str:
    """生成会话令牌"""
    return secrets.token_urlsafe(32)


def generate_authorization_code() -> str:
    """生成授权码"""
    return secrets.token_urlsafe(32)


def generate_client_credentials() -> Tuple[str, str]:
    """生成客户端凭证 (client_id, client_secret)"""
    client_id = f"app_{secrets.token_urlsafe(16)}"
    client_secret = secrets.token_urlsafe(32)
    return client_id, client_secret


def generate_verification_code(length: int = 6) -> str:
    """生成验证码（用于手机验证码、邮箱验证码等）"""
    return ''.join([str(secrets.randbelow(10)) for _ in range(length)])


def generate_mfa_secret() -> str:
    """生成 MFA 密钥（用于 TOTP）"""
    return secrets.token_urlsafe(32)


# ===== 手机验证码相关 =====

class PhoneVerificationService:
    """手机验证码服务"""

    # 存储验证码（实际应用中应使用 Redis）
    _verification_codes: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def send_verification_code(cls, phone: str) -> Tuple[bool, str]:
        """
        发送验证码到手机
        返回: (是否成功, 消息)
        """
        if not validate_phone(phone):
            return False, "无效的手机号格式"

        # 生成验证码
        code = generate_verification_code(6)

        # 存储验证码（有效期 5 分钟）
        cls._verification_codes[phone] = {
            "code": code,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(minutes=5),
            "attempts": 0
        }

        # TODO: 调用短信服务发送验证码
        # 这里仅作示例，实际应集成真实的短信服务（如阿里云、腾讯云等）
        print(f"[SMS] 向 {phone} 发送验证码: {code}")

        return True, "验证码已发送，请在 5 分钟内输入"

    @classmethod
    def verify_code(cls, phone: str, code: str) -> Tuple[bool, str]:
        """
        验证手机验证码
        返回: (是否成功, 消息)
        """
        if phone not in cls._verification_codes:
            return False, "请先请求验证码"

        code_data = cls._verification_codes[phone]

        # 检查是否过期
        if datetime.utcnow() > code_data["expires_at"]:
            del cls._verification_codes[phone]
            return False, "验证码已过期，请重新请求"

        # 检查尝试次数
        if code_data["attempts"] >= 5:
            del cls._verification_codes[phone]
            return False, "尝试次数过多，请重新请求验证码"

        # 验证码
        if code_data["code"] != code:
            code_data["attempts"] += 1
            return False, f"验证码错误，还有 {5 - code_data['attempts']} 次尝试机会"

        # 验证成功，删除验证码
        del cls._verification_codes[phone]
        return True, "验证码验证成功"


# ===== 多因素认证（MFA）相关 =====

class MFAService:
    """多因素认证服务"""

    @staticmethod
    def generate_totp_secret() -> str:
        """生成 TOTP 密钥"""
        import base64
        random_bytes = secrets.token_bytes(32)
        return base64.b32encode(random_bytes).decode('utf-8')

    @staticmethod
    def verify_totp(secret: str, token: str) -> bool:
        """验证 TOTP Token"""
        try:
            import pyotp
            totp = pyotp.TOTP(secret)
            return totp.verify(token)
        except ImportError:
            # 如果未安装 pyotp，返回 False
            return False

    @staticmethod
    def get_totp_uri(secret: str, email: str, issuer: str = "SSO Platform") -> str:
        """获取 TOTP URI（用于生成二维码）"""
        try:
            import pyotp
            totp = pyotp.TOTP(secret)
            return totp.provisioning_uri(name=email, issuer_name=issuer)
        except ImportError:
            return ""

    # --- 以下为 routers/auth.py 所需的扩展方法 ---

    _temp_secrets: Dict[int, str] = {}

    @staticmethod
    def is_mfa_enabled(user_id: int) -> bool:
        """检查用户是否已启用 MFA"""
        from auth_center.database import MFADB
        return MFADB.get_mfa_status(user_id)["enabled"]

    @staticmethod
    def generate_mfa_secret(email: str):
        """生成 MFA 密钥和二维码 URL，返回 (secret, qr_code_url)"""
        try:
            import pyotp, qrcode, base64
            from io import BytesIO
            secret = pyotp.random_base32()
            totp = pyotp.TOTP(secret)
            uri = totp.provisioning_uri(name=email, issuer_name="SSO Platform")
            qr = qrcode.make(uri)
            buf = BytesIO()
            qr.save(buf, format="PNG")
            qr_b64 = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
            return secret, qr_b64
        except ImportError:
            import secrets as _s, base64 as _b
            secret = _b.b32encode(_s.token_bytes(20)).decode()
            return secret, ""

    @staticmethod
    def verify_mfa_code(secret: str, code: str) -> bool:
        """验证 TOTP 验证码"""
        try:
            import pyotp
            return pyotp.TOTP(secret).verify(code, valid_window=1)
        except Exception:
            return False

    @staticmethod
    def enable_mfa(user_id: int, secret: str) -> None:
        """在数据库中启用 MFA"""
        from auth_center.database import MFADB
        import secrets as _s
        recovery_codes = [_s.token_hex(8) for _ in range(10)]
        MFADB.enable_mfa(user_id, secret, recovery_codes)

    @staticmethod
    def disable_mfa(user_id: int) -> None:
        """在数据库中禁用 MFA"""
        from auth_center.database import MFADB
        MFADB.disable_mfa(user_id)

    @staticmethod
    def validate_user_mfa(user_id: int, code: str) -> bool:
        """验证用户当前的 MFA 验证码"""
        from auth_center.database import MFADB
        secret = MFADB.get_mfa_secret(user_id)
        if not secret:
            return False
        try:
            import pyotp
            return pyotp.TOTP(secret).verify(code, valid_window=1)
        except Exception:
            return False


# ===== 异常登录检测 =====

class AnomalyDetectionService:
    """异常登录检测服务"""

    # 已知的 IP 地址（实际应存储在数据库）
    _known_ips: Dict[int, set] = {}

    @staticmethod
    def detect_anomaly(user_id: int, ip_address: str, user_agent: str) -> Dict[str, Any]:
        """
        检测异常登录
        返回: {
            "is_anomaly": bool,
            "risk_level": "low" | "medium" | "high",
            "message": str,
            "actions": list  # 建议的安全措施
        }
        """
        anomalies = []
        risk_level = "low"

        # 1. 检查登录 IP 是否异常
        from .database import get_db # 局部导入以避免循环引用
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT DISTINCT ip_address FROM login_logs WHERE user_id = ? AND status = 'SUCCESS' LIMIT 10",
                (user_id,)
            )
            known_ips = {row[0] for row in cursor.fetchall() if row[0]}

        if ip_address and ip_address not in known_ips and known_ips:
            anomalies.append("新的登录 IP 地址")
            risk_level = "medium"

        # 2. 检查是否在短时间内有多次登录失败
        from .database import get_db # 局部导入以避免循环引用
        with get_db() as conn:
            cursor = conn.execute(
                """
                SELECT COUNT(*) FROM login_logs
                WHERE user_id = ? AND status = 'FAILURE'
                AND login_time > datetime('now', '-30 minutes')
                """,
                (user_id,)
            )
            failed_attempts = cursor.fetchone()[0]

        if failed_attempts >= 5:
            anomalies.append("短时间内登录失败次数过多")
            risk_level = "high"

        # 3. 检查是否在不同地区短时间内登录
        from .database import get_db # 局部导入以避免循环引用
        with get_db() as conn:
            cursor = conn.execute(
                """
                SELECT ip_address, login_time FROM login_logs
                WHERE user_id = ? AND status = 'SUCCESS'
                ORDER BY login_time DESC LIMIT 2
                """,
                (user_id,)
            )
            recent_logins = cursor.fetchall()

        if len(recent_logins) >= 2:
            prev_ip = recent_logins[1][0]
            prev_time = recent_logins[1][1]

            if prev_ip != ip_address:
                time_diff = (datetime.utcnow() - datetime.fromisoformat(prev_time)).total_seconds()
                if time_diff < 3600:  # 1 小时内
                    anomalies.append("短时间内从不同 IP 登录")
                    risk_level = "high"

        return {
            "is_anomaly": len(anomalies) > 0,
            "risk_level": risk_level,
            "anomalies": anomalies,
            "actions": AnomalyDetectionService._get_recommended_actions(risk_level)
        }

    @staticmethod
    def _get_recommended_actions(risk_level: str) -> List[str]:
        """获取建议的安全措施"""
        if risk_level == "high":
            return [
                "要求重新输入密码",
                "发送安全警告邮件",
                "启用双因素认证验证",
                "记录详细的登录信息"
            ]
        elif risk_level == "medium":
            return [
                "发送登录通知邮件",
                "记录登录信息",
                "建议启用双因素认证"
            ]
        else:
            return ["记录登录信息"]


# ===== 登录日志记录 =====

def log_login_attempt(
    email: str,
    status: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    user_id: Optional[int] = None,
    message: Optional[str] = None,
):
    """记录登录尝试"""
    from .database import LoginLogDB # 局部导入以避免循环引用
    LoginLogDB.create_log(
        email=email,
        status=status,
        ip_address=ip_address,
        user_agent=user_agent,
        user_id=user_id,
        message=message
    )


# ===== 数据过滤 =====

def filter_user_data_by_scope(user_data: dict, scope: str) -> dict:
    """
    根据 scope 过滤用户数据

    Args:
        user_data: 完整的用户数据字典 (包含基础信息和自定义字段)
        scope: 授权范围字符串 (空格分隔)

    Returns:
        过滤后的用户数据字典
    """
    # 解析 scope
    scopes = [s.strip() for s in scope.split(' ') if s.strip()]

    # 基础字段 (始终包含) - sub 对应 external_id
    filtered_data = {
        "sub": user_data.get("external_id", str(user_data.get("id"))),
        "id": user_data.get("external_id", str(user_data.get("id"))),
        "type": "access"
    }

    allowed_fields = set()

    # 1. 处理预定义 Scope (如 profile, email)
    for scope_name in scopes:
        if scope_name in config.AVAILABLE_SCOPES:
            scope_config = config.AVAILABLE_SCOPES[scope_name]
            allowed_fields.update(scope_config.get("fields", []))

    # 2. 处理动态字段 Scope (格式为 field:key)
    for scope_name in scopes:
        if scope_name.startswith("field:"):
            try:
                field_key = scope_name.split(":", 1)[1]
                if field_key:
                    allowed_fields.add(field_key)
            except IndexError:
                pass

    # 3. 填充数据
    # 基础字段映射
    field_mapping = {
        "name": "name",
        "email": "email",
        "username": "username",
        "avatar_url": "avatar_url"
    }

    # 添加基础字段
    for field_key, user_key in field_mapping.items():
        if field_key in allowed_fields and user_key in user_data:
            filtered_data[field_key] = user_data[user_key]

    # 添加自定义字段 (假设 user_data 已经包含了扁平化的自定义数据)
    for key, value in user_data.items():
        if key in allowed_fields and key not in field_mapping.values() and key != "sub":
            filtered_data[key] = value

    return filtered_data


# ===== 会话管理 =====

class SessionManager:
    """会话管理器"""

    @staticmethod
    def get_user_sessions(user_id: int) -> List[Dict[str, Any]]:
        """获取用户的所有活跃会话"""
        from .database import SessionDB
        return SessionDB.get_user_sessions(user_id)

    @staticmethod
    def logout_session(session_token: str) -> bool:
        """登出指定会话"""
        from .database import SessionDB
        return SessionDB.delete_session(session_token)

    @staticmethod
    def extract_device_name(user_agent: str) -> str:
        """从 User-Agent 字符串中提取设备信息"""
        if not user_agent:
            return "Unknown Device"

        # 简化版设备检测
        if "Windows" in user_agent:
            os_name = "Windows"
        elif "Macintosh" in user_agent or "Mac OS" in user_agent:
            os_name = "macOS"
        elif "Linux" in user_agent:
            os_name = "Linux"
        elif "Android" in user_agent:
            os_name = "Android"
        elif "iPhone" in user_agent or "iPad" in user_agent:
            os_name = "iOS"
        else:
            os_name = "Other OS"

        if "Chrome" in user_agent and "Edg" not in user_agent:
            browser = "Chrome"
        elif "Firefox" in user_agent:
            browser = "Firefox"
        elif "Safari" in user_agent and "Chrome" not in user_agent:
            browser = "Safari"
        elif "Edg" in user_agent:
            browser = "Edge"
        else:
            browser = "Other Browser"

        return f"{browser} on {os_name}"

    @staticmethod
    def logout_all_sessions(user_id: int) -> bool:
        """登出用户的所有会话"""
        from .database import SessionDB
        sessions = SessionDB.get_user_sessions(user_id)
        for session in sessions:
            SessionDB.delete_session(session["session_token"])
        return True

    @staticmethod
    def is_session_valid(session_token: str) -> bool:
        """检查会话是否有效"""
        from .database import SessionDB
        session = SessionDB.get_session_by_token(session_token)
        if not session:
            return False

        # 检查是否过期
        expires_at = datetime.fromisoformat(session["expires_at"])
        return datetime.utcnow() < expires_at
