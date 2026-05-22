"""
认证中心配置文件
"""
import os
from pathlib import Path
from typing import List, Optional, Dict, Any

# 自动加载项目根目录下的 .env 文件（优先级低于已存在的系统环境变量）
def _load_dotenv():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            # 不覆盖已有的系统环境变量
            if key and key not in os.environ:
                os.environ[key] = value

_load_dotenv()

class Config:
    """配置类"""

    # 安全配置
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    ALGORITHM: str = "HS256"

    # Token 过期时间
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    AUTHORIZATION_CODE_EXPIRE_MINUTES: int = 5
    SESSION_EXPIRE_DAYS: int = 30 # 新增会话过期时间，默认为 30 天

    # 日期时间格式 (用于数据库存储和读取)
    DATETIME_FORMAT: str = "%Y-%m-%d %H:%M:%S.%f"

    # 数据库配置
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./sso_auth.db")

    # CORS 配置
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5000",
        "http://localhost:8001",
        "http://localhost:8002",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5000",
        "http://127.0.0.1:8001",
        "http://127.0.0.1:8002",
    ]

    # Cookie 配置
    COOKIE_DOMAIN: str = os.getenv("COOKIE_DOMAIN", None)
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    COOKIE_SAMESITE: str = "lax"

    # WebAuthn / Passkeys 配置
    # WEBAUTHN_RP_ID   : 纯域名，不含协议和端口，例如 sso.example.com
    #                    留空则自动从 BASE_URL 中提取（推荐做法）
    # WEBAUTHN_ORIGIN  : 完整来源 URL，例如 https://sso.example.com
    #                    留空则自动从 BASE_URL 中构造（推荐做法）
    WEBAUTHN_RP_ID: str = os.getenv("WEBAUTHN_RP_ID", "")
    WEBAUTHN_ORIGIN: str = os.getenv("WEBAUTHN_ORIGIN", "")

    # 密码策略
    MIN_PASSWORD_LENGTH: int = 8
    REQUIRE_PASSWORD_COMPLEXITY: bool = True

    # 注册配置
    REGISTRATION_SECRET: str = os.getenv("REGISTRATION_SECRET", "")

    # 注册白名单 (仅允许列表中的邮箱自主注册)
    # 格式: ["user@domain.com", "another@domain.com"]
    # 如果列表为空,则允许所有邮箱注册 (与旧行为一致)
    # 如果设置为 None, 则禁止所有自主注册
    # 注意: 此处仅为默认值，实际值将在 main.py 启动时从 ConfigDB 加载
    ALLOWED_REGISTRATION_EMAILS: Optional[List[str]] = None

    # 服务器配置
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8200"))

    # 前端 URL(用于重定向)
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:8200")

    # 服务对外可访问的基础 URL（用于生成密码重置链接等）
    BASE_URL: str = os.getenv("BASE_URL", "http://localhost:8200")

    # 授权范围配置
    # 键为 scope 名称, 值为描述和包含的用户信息字段
    # 在 config.py 的 AVAILABLE_SCOPES 中更新
    AVAILABLE_SCOPES: Dict[str, Dict[str, Any]] = {
        "basic": {
            "description": "基本用户 ID",
            "fields": []  # 只返回 sub (external_id)
        },
        "profile": {
            "description": "基本个人信息 (姓名, 头像)",
            "fields": ["name", "avatar_url"]
        },
        "email": {
            "description": "电子邮箱地址",
            "fields": ["email"]
        },
        "username": {
            "description": "用户名称 (如果设置)",
            "fields": ["username"]
        },
        "full_info": {
            "description": "所有基本信息 (profile, email, username)",
            "fields": ["name", "avatar_url", "email", "username"]
        },
        "openid": {
            "description": "OpenID Connect 标准信息",
            "fields": ["name", "email", "avatar_url"]
        }
    }

    # 默认 scope - 改为返回完整信息
    DEFAULT_SCOPE: str = "openid profile email"


import secrets as _secrets
import logging as _logging
_log = _logging.getLogger(__name__)

def _validate_config(cfg):
    """启动时校验关键配置，防止弱密钥上线"""
    weak_placeholders = {
        "your-secret-key", "change-in-production", "change-me",
        "secret", "test", "dev", ""
    }
    if not cfg.SECRET_KEY or any(p in cfg.SECRET_KEY.lower() for p in weak_placeholders):
        import os
        if os.getenv("ENV", "development").lower() == "production":
            raise RuntimeError(
                "[FATAL] SECRET_KEY 未设置或使用了默认弱密钥，生产环境禁止启动。"
                "请设置环境变量 SECRET_KEY=<随机64字节字符串>"
            )
        else:
            cfg.SECRET_KEY = _secrets.token_urlsafe(64)
            _log.warning(
                "[SECURITY] SECRET_KEY 未配置，已自动生成临时密钥（每次重启失效，仅供开发使用）。"
                "生产环境请设置 SECRET_KEY 环境变量。"
            )
    if not cfg.REGISTRATION_SECRET or any(p in cfg.REGISTRATION_SECRET.lower() for p in weak_placeholders):
        cfg.REGISTRATION_SECRET = _secrets.token_urlsafe(32)
        _log.warning("[SECURITY] REGISTRATION_SECRET 未配置，已自动生成临时值。")
    return cfg


config = _validate_config(Config())