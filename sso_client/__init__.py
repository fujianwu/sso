"""
SSO 客户端 SDK
用于 Flask 和 FastAPI 应用集成 SSO 认证
"""
from .flask_client import FlaskSSOClient
from .fastapi_client import FastAPISSOClient

__version__ = "1.0.0"
__all__ = ["FlaskSSOClient", "FastAPISSOClient"]
