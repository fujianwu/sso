"""
性能优化和稳定性增强模块
包含缓存、连接池、错误处理等功能
"""

import sqlite3
import time
from functools import wraps
from typing import Any, Callable, Dict, Optional
from datetime import datetime, timedelta
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ===== 缓存装饰器 =====

class CacheManager:
    """缓存管理器"""

    _cache: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def set(cls, key: str, value: Any, ttl: int = 300):
        """
        设置缓存

        Args:
            key: 缓存键
            value: 缓存值
            ttl: 缓存过期时间（秒）
        """
        cls._cache[key] = {
            "value": value,
            "expires_at": datetime.utcnow() + timedelta(seconds=ttl)
        }
        logger.debug(f"Cache set: {key} (TTL: {ttl}s)")

    @classmethod
    def get(cls, key: str) -> Optional[Any]:
        """
        获取缓存

        Args:
            key: 缓存键

        Returns:
            缓存值，如果不存在或已过期则返回 None
        """
        if key not in cls._cache:
            return None

        cache_item = cls._cache[key]

        # 检查是否过期
        if datetime.utcnow() > cache_item["expires_at"]:
            del cls._cache[key]
            logger.debug(f"Cache expired: {key}")
            return None

        logger.debug(f"Cache hit: {key}")
        return cache_item["value"]

    @classmethod
    def delete(cls, key: str):
        """删除缓存"""
        if key in cls._cache:
            del cls._cache[key]
            logger.debug(f"Cache deleted: {key}")

    @classmethod
    def clear(cls):
        """清空所有缓存"""
        cls._cache.clear()
        logger.info("Cache cleared")


def cache(ttl: int = 300):
    """
    缓存装饰器

    Args:
        ttl: 缓存过期时间（秒）
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # 生成缓存键
            cache_key = f"{func.__name__}:{args}:{kwargs}"

            # 尝试从缓存获取
            cached_value = CacheManager.get(cache_key)
            if cached_value is not None:
                return cached_value

            # 执行函数
            result = func(*args, **kwargs)

            # 存储到缓存
            CacheManager.set(cache_key, result, ttl)

            return result

        return wrapper

    return decorator


# ===== 性能监控 =====

class PerformanceMonitor:
    """性能监控器"""

    _metrics: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def record_request(cls, endpoint: str, method: str, duration: float, status_code: int):
        """
        记录请求性能指标

        Args:
            endpoint: 端点路径
            method: HTTP 方法
            duration: 请求耗时（秒）
            status_code: 响应状态码
        """
        key = f"{method} {endpoint}"

        if key not in cls._metrics:
            cls._metrics[key] = {
                "count": 0,
                "total_duration": 0,
                "min_duration": float('inf'),
                "max_duration": 0,
                "error_count": 0
            }

        metrics = cls._metrics[key]
        metrics["count"] += 1
        metrics["total_duration"] += duration
        metrics["min_duration"] = min(metrics["min_duration"], duration)
        metrics["max_duration"] = max(metrics["max_duration"], duration)

        if status_code >= 400:
            metrics["error_count"] += 1

        # 计算平均耗时
        avg_duration = metrics["total_duration"] / metrics["count"]

        # 如果平均耗时超过 1 秒，记录警告
        if avg_duration > 1.0:
            logger.warning(
                f"Slow endpoint: {key} (avg: {avg_duration:.2f}s, count: {metrics['count']})"
            )

    @classmethod
    def get_metrics(cls) -> Dict[str, Dict[str, Any]]:
        """获取所有性能指标"""
        return cls._metrics

    @classmethod
    def get_endpoint_metrics(cls, endpoint: str, method: str) -> Optional[Dict[str, Any]]:
        """获取特定端点的性能指标"""
        key = f"{method} {endpoint}"
        return cls._metrics.get(key)


def monitor_performance(func: Callable) -> Callable:
    """
    性能监控装饰器
    """
    @wraps(func)
    async def async_wrapper(*args, **kwargs) -> Any:
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            return result
        finally:
            duration = time.time() - start_time
            logger.info(f"{func.__name__} took {duration:.3f}s")

    @wraps(func)
    def sync_wrapper(*args, **kwargs) -> Any:
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            duration = time.time() - start_time
            logger.info(f"{func.__name__} took {duration:.3f}s")

    # 判断是否为异步函数
    import asyncio
    if asyncio.iscoroutinefunction(func):
        return async_wrapper
    else:
        return sync_wrapper


# ===== 数据库连接池 =====

class DatabaseConnectionPool:
    """数据库连接池（简单实现）"""

    _pool: list = []
    _max_size: int = 10
    _timeout: float = 5.0

    @classmethod
    def get_connection(cls, db_path: str) -> sqlite3.Connection:
        """
        获取数据库连接

        Args:
            db_path: 数据库文件路径

        Returns:
            数据库连接
        """
        # 简单实现：直接创建新连接
        # 实际应用中应使用更复杂的连接池管理
        conn = sqlite3.connect(db_path, timeout=cls._timeout)
        conn.row_factory = sqlite3.Row
        return conn

    @classmethod
    def return_connection(cls, conn: sqlite3.Connection):
        """
        归还数据库连接

        Args:
            conn: 数据库连接
        """
        if conn:
            conn.close()


# ===== 错误处理和重试 =====

class RetryConfig:
    """重试配置"""

    def __init__(
        self,
        max_retries: int = 3,
        initial_delay: float = 0.1,
        max_delay: float = 10.0,
        exponential_base: float = 2.0
    ):
        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base


def retry_with_backoff(config: Optional[RetryConfig] = None):
    """
    带指数退避的重试装饰器

    Args:
        config: 重试配置
    """
    if config is None:
        config = RetryConfig()

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            delay = config.initial_delay
            last_exception = None

            for attempt in range(config.max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e

                    if attempt < config.max_retries:
                        logger.warning(
                            f"{func.__name__} failed (attempt {attempt + 1}/{config.max_retries + 1}), "
                            f"retrying in {delay:.2f}s: {str(e)}"
                        )
                        time.sleep(delay)
                        delay = min(delay * config.exponential_base, config.max_delay)
                    else:
                        logger.error(
                            f"{func.__name__} failed after {config.max_retries + 1} attempts: {str(e)}"
                        )

            raise last_exception

        return wrapper

    return decorator


# ===== 数据库查询优化 =====

class QueryOptimizer:
    """查询优化器"""

    @staticmethod
    def add_indexes(conn: sqlite3.Connection):
        """
        添加数据库索引以提高查询性能

        Args:
            conn: 数据库连接
        """
        cursor = conn.cursor()

        # 用户表索引
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_users_external_id ON users(external_id)",

            # 会话表索引
            "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)",

            # 授权码表索引
            "CREATE INDEX IF NOT EXISTS idx_auth_codes_user_id ON authorization_codes(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_auth_codes_client_id ON authorization_codes(client_id)",
            "CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at ON authorization_codes(expires_at)",

            # 登录日志表索引
            "CREATE INDEX IF NOT EXISTS idx_login_logs_user_id ON login_logs(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_login_logs_email ON login_logs(email)",
            "CREATE INDEX IF NOT EXISTS idx_login_logs_login_time ON login_logs(login_time)",
            "CREATE INDEX IF NOT EXISTS idx_login_logs_status ON login_logs(status)",

            # 用户授权表索引
            "CREATE INDEX IF NOT EXISTS idx_user_auth_user_id ON user_authorizations(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_user_auth_client_id ON user_authorizations(client_id)",
        ]

        for index_sql in indexes:
            try:
                cursor.execute(index_sql)
                logger.debug(f"Index created: {index_sql}")
            except sqlite3.OperationalError as e:
                logger.debug(f"Index already exists or error: {str(e)}")

        conn.commit()

    @staticmethod
    def analyze_query_performance(conn: sqlite3.Connection, query: str) -> Dict[str, Any]:
        """
        分析查询性能

        Args:
            conn: 数据库连接
            query: SQL 查询语句

        Returns:
            性能分析结果
        """
        cursor = conn.cursor()

        # 获取查询执行计划
        cursor.execute(f"EXPLAIN QUERY PLAN {query}")
        plan = cursor.fetchall()

        return {
            "query": query,
            "plan": plan
        }


# ===== 限流 =====

class RateLimiter:
    """速率限制器"""

    _requests: Dict[str, list] = {}

    @classmethod
    def is_allowed(cls, key: str, max_requests: int = 100, window: int = 60) -> bool:
        """
        检查是否允许请求

        Args:
            key: 限流键（如 IP 地址或用户 ID）
            max_requests: 时间窗口内的最大请求数
            window: 时间窗口（秒）

        Returns:
            是否允许请求
        """
        now = time.time()

        if key not in cls._requests:
            cls._requests[key] = []

        # 清除过期的请求记录
        cls._requests[key] = [
            req_time for req_time in cls._requests[key]
            if now - req_time < window
        ]

        # 检查是否超过限制
        if len(cls._requests[key]) >= max_requests:
            return False

        # 记录请求
        cls._requests[key].append(now)
        return True

    @classmethod
    def get_remaining_requests(cls, key: str, max_requests: int = 100, window: int = 60) -> int:
        """获取剩余请求数"""
        now = time.time()

        if key not in cls._requests:
            return max_requests

        # 清除过期的请求记录
        cls._requests[key] = [
            req_time for req_time in cls._requests[key]
            if now - req_time < window
        ]

        return max(0, max_requests - len(cls._requests[key]))
