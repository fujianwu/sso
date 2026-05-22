"""
数据库模型和操作
"""
"""
数据库模型和操作
"""
import sqlite3
import uuid
import json
from contextlib import contextmanager
from typing import Optional, List, Dict, Any
from datetime import datetime
from .auth import hash_password
from .config import config
from dateutil import parser

@contextmanager
def get_db():
    """获取数据库连接"""
    # 使用配置中的 DATABASE_URL
    # 注意:如果 DATABASE_URL 是 sqlite:///./sso_auth.db 形式,需要提取路径
    db_path = config.DATABASE_URL.replace("sqlite:///./", "")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        raise
    finally:
        conn.close()

def init_db():
    """初始化数据库"""
    with get_db() as conn:
        # 用户表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                external_id TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                avatar_url TEXT,
                phone TEXT UNIQUE,
                is_admin INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                failed_login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 会话表 - 包含所有必需的列
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                refresh_token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                client_id TEXT,
                scope TEXT,
                ip_address TEXT,
                user_agent TEXT,
                device_name TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)

        # 尝试为现有表添加新列（如果表已存在但缺少这些列）
        try:
            conn.execute("ALTER TABLE sessions ADD COLUMN client_id TEXT")
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute("ALTER TABLE sessions ADD COLUMN scope TEXT")
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute("ALTER TABLE sessions ADD COLUMN ip_address TEXT")
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute("ALTER TABLE sessions ADD COLUMN user_agent TEXT")
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute("ALTER TABLE sessions ADD COLUMN device_name TEXT")
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute("ALTER TABLE sessions ADD COLUMN mfa_verified INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute("ALTER TABLE sessions ADD COLUMN mfa_required INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass

        try:
            conn.execute("ALTER TABLE users ADD COLUMN phone TEXT UNIQUE")
        except sqlite3.OperationalError:
            pass

        # 可信设备表（MFA 记住设备，30天内免验证）
        conn.execute("""
            CREATE TABLE IF NOT EXISTS trusted_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_fingerprint TEXT NOT NULL,
                device_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, device_fingerprint)
            )
        """)

        conn.commit()

        # 授权码表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS authorization_codes (
                code TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scope TEXT,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (client_id) REFERENCES registered_apps (client_id)
            )
        """)

        # 注册应用表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS registered_apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT UNIQUE NOT NULL,
                client_secret TEXT NOT NULL,
                app_name TEXT NOT NULL,
                redirect_uris TEXT NOT NULL,
                description TEXT,
                app_url TEXT,
                icon_url TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 数据库迁移：为旧数据库添加新字段（兼容升级）
        try:
            conn.execute("ALTER TABLE registered_apps ADD COLUMN app_url TEXT")
        except Exception:
            pass
        try:
            conn.execute("ALTER TABLE registered_apps ADD COLUMN icon_url TEXT")
        except Exception:
            pass

        # Portal API Token 表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS portal_api_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                created_by INTEGER,
                last_used_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users (id)
            )
        """)

        # 用户授权记录表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_authorizations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                client_id TEXT NOT NULL,
                scope TEXT,
                authorized_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (client_id) REFERENCES registered_apps (client_id),
                UNIQUE(user_id, client_id)
            )
        """)

        # 配置表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        # 动态字段定义表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS custom_fields (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                field_key TEXT UNIQUE NOT NULL,
                field_label TEXT NOT NULL,
                field_type TEXT NOT NULL,
                field_options TEXT,
                is_required BOOLEAN DEFAULT 0,
                show_in_profile BOOLEAN DEFAULT 1,
                show_in_oauth BOOLEAN DEFAULT 0,
                display_order INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 用户扩展数据表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_custom_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                field_key TEXT NOT NULL,
                field_value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (field_key) REFERENCES custom_fields (field_key),
                UNIQUE(user_id, field_key)
            )
        """)

        # 登录日志表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                email TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT NOT NULL,
                message TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)

        # MFA 配置表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mfa_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                secret TEXT NOT NULL,
                enabled BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)

        # MFA 临时密钥表（设置过程中使用）
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mfa_temp_secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                secret TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)

        # MFA 恢复码表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                used BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)

        # Passkeys（WebAuthn 通行密钥）表
        conn.execute("""
            CREATE TABLE IF NOT EXISTS passkeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                credential_id TEXT NOT NULL UNIQUE,
                public_key BLOB NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                device_name TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # WebAuthn challenge 临时存储表（注册/登录流程）
        conn.execute("""
            CREATE TABLE IF NOT EXISTS webauthn_challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                challenge TEXT NOT NULL UNIQUE,
                type TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 为现有 users 表迁移新列
        for col, definition in [
            ("is_admin", "INTEGER DEFAULT 0"),
            ("is_active", "INTEGER DEFAULT 1"),
            ("failed_login_attempts", "INTEGER DEFAULT 0"),
            ("locked_until", "TIMESTAMP"),
        ]:
            try:
                conn.execute(f"ALTER TABLE users ADD COLUMN {col} {definition}")
            except sqlite3.OperationalError:
                pass

        conn.commit()

        # 检查用户表是否为空，如果为空，则创建默认管理员账户
        cursor = conn.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]

        if user_count == 0:
            admin_email = "admin@sso.local"
            admin_name = "System Admin"
            import secrets as _s
            admin_password = _s.token_urlsafe(16)

            password_hash = hash_password(admin_password)
            admin_external_id = str(uuid.uuid4())

            conn.execute(
                "INSERT INTO users (external_id, email, password_hash, name, username, is_admin) VALUES (?, ?, ?, ?, ?, 1)",
                (admin_external_id, admin_email, password_hash, admin_name, "admin")
            )
            conn.commit()
            print(f"--- 警告: 已创建默认管理员账户 ---")
            print(f"邮箱: {admin_email}")
            print(f"密码: {admin_password}  ← 请立即修改！")
            print(f"----------------------------------")
        else:
            # 确保第一个用户或 admin@sso.local 拥有管理员权限
            conn.execute(
                "UPDATE users SET is_admin = 1 WHERE email = 'admin@sso.local' AND is_admin = 0"
            )
            conn.commit()


class ConfigDB:
    """配置数据库操作"""

    @staticmethod
    def get_config(key: str) -> Optional[str]:
        """获取配置值"""
        with get_db() as conn:
            cursor = conn.execute("SELECT value FROM config WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row[0] if row else None

    @staticmethod
    def set_config(key: str, value: str):
        """设置或更新配置值"""
        with get_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
                (key, value)
            )
            conn.commit()

class UserDB:
    """用户数据库操作"""

    MAX_FAILED_ATTEMPTS = 5        # 最大失败次数
    LOCKOUT_MINUTES = 15           # 锁定分钟数

    @staticmethod
    def record_failed_login(user_id: int):
        """记录一次登录失败，超限则锁定账户"""
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?",
                (user_id,)
            )
            conn.commit()
            cursor = conn.execute(
                "SELECT failed_login_attempts FROM users WHERE id = ?", (user_id,)
            )
            row = cursor.fetchone()
            attempts = row[0] if row else 0
            if attempts >= UserDB.MAX_FAILED_ATTEMPTS:
                locked_until = datetime.utcnow() + __import__('datetime').timedelta(minutes=UserDB.LOCKOUT_MINUTES)
                conn.execute(
                    "UPDATE users SET locked_until = ? WHERE id = ?",
                    (locked_until.strftime("%Y-%m-%d %H:%M:%S.%f"), user_id)
                )
                conn.commit()

    @staticmethod
    def reset_failed_login(user_id: int):
        """登录成功后重置失败计数"""
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
                (user_id,)
            )
            conn.commit()

    @staticmethod
    def is_locked(user: dict) -> bool:
        """检查账户是否被锁定"""
        locked_until = user.get("locked_until")
        if not locked_until:
            return False
        if isinstance(locked_until, str):
            try:
                locked_until = datetime.strptime(locked_until, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                try:
                    locked_until = datetime.strptime(locked_until, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    return False
        return datetime.utcnow() < locked_until

    @staticmethod
    def lock_seconds_remaining(user: dict) -> int:
        """返回账户还有多少秒解锁"""
        locked_until = user.get("locked_until")
        if not locked_until:
            return 0
        if isinstance(locked_until, str):
            try:
                locked_until = datetime.strptime(locked_until, "%Y-%m-%d %H:%M:%S.%f")
            except ValueError:
                try:
                    locked_until = datetime.strptime(locked_until, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    return 0
        delta = (locked_until - datetime.utcnow()).total_seconds()
        return max(0, int(delta))


    @staticmethod
    def get_all_users() -> List[Dict[str, Any]]:
        """获取所有用户列表"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT id, external_id, email, username, name, avatar_url, is_admin, is_active, failed_login_attempts, locked_until, created_at FROM users ORDER BY created_at DESC"
            )
            users = []
            for row in cursor.fetchall():
                data = dict(row)
                # SQLite 存储的时间戳是字符串,需要转换成 datetime 对象
                if isinstance(data.get("created_at"), str):
                    # from datetime import datetime
                    try:
                        data["created_at"] = datetime.strptime(data["created_at"], config.DATETIME_FORMAT)
                    except ValueError:
                        pass
                users.append(data)
            return users

    @staticmethod
    def update_password(user_id: int, password_hash: str):
        """更新用户密码"""
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, user_id)
            )
            conn.commit()
    @staticmethod
    def create_user(email: str, password_hash: str, name: str, username: Optional[str] = None, avatar_url: Optional[str] = None) -> int:
        """创建用户"""
        external_id = str(uuid.uuid4())
        with get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO users (external_id, email, password_hash, name, username, avatar_url) VALUES (?, ?, ?, ?, ?, ?)",
                (external_id, email, password_hash, name, username, avatar_url)
            )
            conn.commit()
            return cursor.lastrowid

    @staticmethod
    def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
        """根据邮箱获取用户"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT id, external_id, email, username, password_hash, name, avatar_url, is_admin, is_active, failed_login_attempts, locked_until, created_at FROM users WHERE email = ?",
                (email,)
            )
            row = cursor.fetchone()
            if row:
                data = dict(row)
                # SQLite 存储的时间戳是字符串，需要转换成 datetime 对象
                # 检查 created_at 字段
                if isinstance(data.get("created_at"), str):
                    # from datetime import datetime
                    try:
                        # 尝试解析 SQLite 默认格式 'YYYY-MM-DD HH:MM:SS.f'
                        data["created_at"] = datetime.strptime(data["created_at"], config.DATETIME_FORMAT)
                    except ValueError:
                        pass # 忽略解析错误
                return data
            return None

    @staticmethod
    def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
        """根据用户名获取用户"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT id, external_id, email, username, password_hash, name, avatar_url, is_admin, is_active, failed_login_attempts, locked_until, created_at FROM users WHERE username = ?",
                (username,)
            )
            row = cursor.fetchone()
            if row:
                data = dict(row)
                # SQLite 存储的时间戳是字符串，需要转换成 datetime 对象
                # 检查 created_at 字段
                if isinstance(data.get("created_at"), str):
                    # from datetime import datetime
                    try:
                        # 尝试解析 SQLite 默认格式 'YYYY-MM-DD HH:MM:SS.f'
                        data["created_at"] = datetime.strptime(data["created_at"], config.DATETIME_FORMAT)
                    except ValueError:
                        pass # 忽略解析错误
                return data
            return None

    @staticmethod
    def get_user_by_phone(phone: str) -> Optional[Dict[str, Any]]:
        """根据手机号获取用户"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT id, external_id, email, username, password_hash, name, avatar_url, phone, is_admin, is_active, failed_login_attempts, locked_until, created_at FROM users WHERE phone = ?",
                (phone,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    @staticmethod
    def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
        """根据 ID 获取用户"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT id, external_id, email, username, name, avatar_url, phone, password_hash, is_admin, is_active, failed_login_attempts, locked_until, created_at FROM users WHERE id = ?",
                (user_id,)
            )
            row = cursor.fetchone()
            if row:
                data = dict(row)
                # SQLite 存储的时间戳是字符串，需要转换成 datetime 对象
                # 检查 created_at 字段
                if isinstance(data.get("created_at"), str):
                    from datetime import datetime
                    try:
                        # 尝试解析 SQLite 默认格式 'YYYY-MM-DD HH:MM:SS.f'
                        data["created_at"] = datetime.strptime(data["created_at"], config.DATETIME_FORMAT)
                    except ValueError:
                        pass # 忽略解析错误
                return data
            return None

    @staticmethod
    def update_user_avatar(user_id: int, avatar_url: str):
        """更新用户头像"""
        with get_db() as conn:
            conn.execute(
                "UPDATE users SET avatar_url = ? WHERE id = ?",
                (avatar_url, user_id)
            )
            conn.commit()

    @staticmethod
    def update_user(user_id: int, **kwargs):
        """更新用户信息（通用方法）"""
        if not kwargs:
            return

        # 构建 SQL 更新语句
        set_clauses = []
        values = []
        for key, value in kwargs.items():
            if key in ["email", "username", "name", "avatar_url", "password_hash", "phone"]:
                set_clauses.append(f"{key} = ?")
                values.append(value)

        if not set_clauses:
            return

        sql = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?"
        values.append(user_id)

        with get_db() as conn:
            conn.execute(sql, tuple(values))
            conn.commit()

    @staticmethod
    def delete_user(user_id: int):
        """删除用户及其所有相关数据"""
        with get_db() as conn:
            # 删除用户授权记录
            conn.execute("DELETE FROM user_authorizations WHERE user_id = ?", (user_id,))
            # 删除用户会话
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            # 删除用户授权码
            conn.execute("DELETE FROM authorization_codes WHERE user_id = ?", (user_id,))
            # 删除用户自定义数据
            conn.execute("DELETE FROM user_custom_data WHERE user_id = ?", (user_id,))
            # 删除用户
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

            conn.commit()

class SessionDB:
    """会话数据库操作"""

    @staticmethod
    def create_session(user_id: int, session_token: str, refresh_token: str, expires_at,
                      ip_address: str = None, user_agent: str = None, device_name: str = None,
                      client_id: str = None, scope: str = None):
        """创建会话 - 支持所有字段"""
        # 处理 expires_at - 可能是 datetime 对象或字符串
        if isinstance(expires_at, datetime):
            expires_at_str = expires_at.strftime(config.DATETIME_FORMAT)
        elif isinstance(expires_at, str):
            expires_at_str = expires_at
        else:
            raise ValueError("expires_at must be datetime or string")

        with get_db() as conn:
            cursor = conn.execute(
                """
                INSERT INTO sessions (user_id, session_token, refresh_token, expires_at,
                                     ip_address, user_agent, device_name, client_id, scope)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, session_token, refresh_token, expires_at_str,
                 ip_address, user_agent, device_name, client_id, scope)
            )
            conn.commit()
            print(f"Session created successfully, ID: {cursor.lastrowid}")

    @staticmethod
    def get_session(session_token: str) -> Optional[Dict[str, Any]]:
        """获取会话信息（并检查是否过期）"""
        with get_db() as conn:
            cursor = conn.execute(
                """
                SELECT s.id, s.user_id, s.session_token, s.refresh_token, s.expires_at, s.created_at,
                       s.ip_address, s.user_agent, s.device_name, s.mfa_verified, s.mfa_required,
                       u.email, u.name, u.avatar_url
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.session_token = ? AND s.expires_at > ?
                """,
                (session_token, datetime.utcnow().strftime(config.DATETIME_FORMAT))
            )
            row = cursor.fetchone()
            if row:
                data = dict(row)
                if isinstance(data.get("created_at"), str):
                    try:
                        data["created_at"] = datetime.strptime(data["created_at"], config.DATETIME_FORMAT)
                    except ValueError:
                        pass
                return data
            return None

    @staticmethod
    def get_session_by_token_only(session_token: str) -> Optional[Dict[str, Any]]:
        """仅获取会话信息（不检查过期）"""
        with get_db() as conn:
            cursor = conn.execute(
                """
                SELECT s.id, s.user_id, s.session_token, s.refresh_token, s.expires_at, s.created_at
                FROM sessions s
                WHERE s.session_token = ?
                """,
                (session_token,)
            )
            row = cursor.fetchone()
            if row:
                data = dict(row)
                # SQLite 存储的时间戳是字符串，需要转换成 datetime 对象
                # 检查 created_at 字段
                if isinstance(data.get("created_at"), str):
                    # from datetime import datetime
                    try:
                        # 尝试解析 SQLite 默认格式 'YYYY-MM-DD HH:MM:SS.f'
                        data["created_at"] = datetime.strptime(data["created_at"], config.DATETIME_FORMAT)
                    except ValueError:
                        pass # 忽略解析错误
                return data
            return None

    @staticmethod
    def get_latest_session_by_user_id(user_id: int) -> Optional[Dict[str, Any]]:
        """获取用户的最新活跃会话"""
        with get_db() as conn:
            cursor = conn.execute(
                """
                SELECT s.id, s.user_id, s.session_token, s.refresh_token, s.expires_at, s.created_at
                FROM sessions s
                WHERE s.user_id = ? AND s.expires_at > ?
                ORDER BY s.created_at DESC
                LIMIT 1
                """,
                (user_id, datetime.utcnow().strftime(config.DATETIME_FORMAT))
            )
            row = cursor.fetchone()
            if row:
                data = dict(row)
                # SQLite 存储的时间戳是字符串，需要转换成 datetime 对象
                # 检查 created_at 字段
                if isinstance(data.get("created_at"), str):
                    # from datetime import datetime
                    try:
                        # 尝试解析 SQLite 默认格式 'YYYY-MM-DD HH:MM:SS.f'
                        data["created_at"] = datetime.strptime(data["created_at"], config.DATETIME_FORMAT)
                    except ValueError:
                        pass # 忽略解析错误
                return data
            return None

    @staticmethod
    def get_session_by_refresh_token(refresh_token: str) -> Optional[Dict[str, Any]]:
        """根据 refresh token 获取会话信息"""
        with get_db() as conn:
            cursor = conn.execute(
                """
                SELECT s.id, s.user_id, s.session_token, s.refresh_token, s.expires_at, s.created_at
                FROM sessions s
                WHERE s.refresh_token = ? AND s.expires_at > ?
                """,
                (refresh_token, datetime.utcnow().strftime(config.DATETIME_FORMAT))
            )
            row = cursor.fetchone()
            if row:
                data = dict(row)
                # SQLite 存储的时间戳是字符串，需要转换成 datetime 对象
                # 检查 created_at 字段
                if isinstance(data.get("created_at"), str):
                    # from datetime import datetime
                    try:
                        # 尝试解析 SQLite 默认格式 'YYYY-MM-DD HH:MM:SS.f'
                        data["created_at"] = datetime.strptime(data["created_at"], config.DATETIME_FORMAT)
                    except ValueError:
                        pass # 忽略解析错误
                return data
            return None

    @staticmethod
    def get_active_sessions() -> List[Dict[str, Any]]:
        """获取所有活跃会话（按创建时间降序）"""
        with get_db() as conn:
            cursor = conn.execute(
                """
                SELECT s.id, s.user_id, s.session_token, s.refresh_token, s.expires_at, s.created_at, u.email, u.name, u.avatar_url
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.expires_at > ?
                ORDER BY s.created_at DESC
                """,
                (datetime.utcnow().strftime(config.DATETIME_FORMAT),)
            )
            return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def get_user_sessions(user_id: int) -> List[Dict[str, Any]]:
        """获取用户的所有活跃会话"""
        with get_db() as conn:
            cursor = conn.execute(
                """
                SELECT s.id, s.user_id, s.session_token, s.refresh_token, s.expires_at, s.created_at
                FROM sessions s
                WHERE s.user_id = ? AND s.expires_at > ?
                ORDER BY s.created_at DESC
                """,
                (user_id, datetime.utcnow().strftime(config.DATETIME_FORMAT))
            )
            return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def delete_session(session_token: str):
        """删除会话"""
        with get_db() as conn:
            conn.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
            conn.commit()

    @staticmethod
    def delete_user_sessions(user_id: int):
        """删除用户的所有会话"""
        with get_db() as conn:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            conn.commit()

    @staticmethod
    def delete_all_sessions():
        """删除所有会话"""
        with get_db() as conn:
            conn.execute("DELETE FROM sessions")
            conn.commit()
    @staticmethod
    def get_session(session_token: str) -> Optional[Dict[str, Any]]:
        """根据 session_token 获取会话（用于 Cookie 登录态）"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM sessions WHERE session_token = ?",
                (session_token,)
            )
            row = cursor.fetchone()
            if row:
                data = dict(row)
                if isinstance(data.get("expires_at"), str):
                    data["expires_at"] = parser.parse(data["expires_at"])
                return data
            return None

    @staticmethod
    def get_session_by_refresh_token(refresh_token: str) -> Optional[Dict[str, Any]]:
        """根据 refresh_token 获取会话（用于 OAuth2 refresh token 撤销检测）"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM sessions WHERE refresh_token = ?",
                (refresh_token,)
            )
            row = cursor.fetchone()
            if row:
                data = dict(row)
                if isinstance(data.get("expires_at"), str):
                    data["expires_at"] = parser.parse(data["expires_at"])
                return data
            return None

class AuthCodeDB:
    """授权码数据库操作"""

    @staticmethod
    def create_auth_code(code: str, user_id: int, client_id: str, redirect_uri: str, scope: str, expires_at: datetime) -> int:
        """创建授权码"""
        with get_db() as conn:
            cursor = conn.execute("""
                INSERT INTO authorization_codes (code, user_id, client_id, redirect_uri, scope, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (code, user_id, client_id, redirect_uri, scope, expires_at.strftime(config.DATETIME_FORMAT))) # 修复: 格式化时间
            conn.commit()
            return cursor.lastrowid

    @staticmethod
    def get_auth_code(code: str, client_id: str) -> Optional[dict]:
        """
        获取授权码信息
        修改: 包含 username、avatar_url 和 external_id 字段
        """
        with get_db() as conn:
            cursor = conn.execute("""
                SELECT ac.*, u.email, u.name, u.username, u.avatar_url, u.external_id
                FROM authorization_codes ac
                JOIN users u ON ac.user_id = u.id
                WHERE ac.code = ? AND ac.client_id = ?
                  AND ac.used = 0
                """,
                (code, client_id)
            )
            row = cursor.fetchone()
            if row:
                data = dict(row)
                # SQLite 存储的时间戳是字符串，需要转换成 datetime 对象
                # 检查 created_at 字段
                if isinstance(data.get("created_at"), str):
                    # from datetime import datetime
                    try:
                        # 尝试解析 SQLite 默认格式 'YYYY-MM-DD HH:MM:SS.f'
                        data["created_at"] = datetime.strptime(data["created_at"], config.DATETIME_FORMAT)
                    except ValueError:
                        pass # 忽略解析错误
                return data
            return None

    @staticmethod
    def delete_auth_code(code: str):
        """销毁授权码（标记为已使用）"""
        with get_db() as conn:
            conn.execute("UPDATE authorization_codes SET used = 1 WHERE code = ?", (code,))
            conn.commit()

    @staticmethod
    def delete_expired_auth_codes():
        """删除所有过期的授权码"""
        with get_db() as conn:
            conn.execute("DELETE FROM authorization_codes WHERE expires_at < ?", (datetime.utcnow().strftime(config.DATETIME_FORMAT),))
            conn.commit()

class AppDB:
    """应用数据库操作"""

    @staticmethod
    def create_app(app_name: str, redirect_uris: List[str], description: Optional[str] = None, app_url: Optional[str] = None, icon_url: Optional[str] = None) -> Dict[str, Any]:
        """注册新应用"""
        client_id = "app_" + str(uuid.uuid4()).replace("-", "")[:20]
        client_secret = str(uuid.uuid4()).replace("-", "")

        with get_db() as conn:
            conn.execute(
                "INSERT INTO registered_apps (client_id, client_secret, app_name, redirect_uris, description, app_url, icon_url) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (client_id, client_secret, app_name, json.dumps(redirect_uris), description, app_url, icon_url)
            )
            conn.commit()

            return {
                "client_id": client_id,
                "client_secret": client_secret,
                "app_name": app_name,
                "redirect_uris": redirect_uris,
                "description": description,
                "app_url": app_url,
                "icon_url": icon_url
            }

    @staticmethod
    def get_app_by_client_id(client_id: str) -> Optional[Dict[str, Any]]:
        """根据 client_id 获取应用信息"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT id, client_id, client_secret, app_name, redirect_uris, description, app_url, icon_url, created_at FROM registered_apps WHERE client_id = ?",
                (client_id,)
            )
            row = cursor.fetchone()
            if row:
                data = dict(row)
                # SQLite 存储的时间戳是字符串，需要转换成 datetime 对象
                # 检查 created_at 字段
                if isinstance(data.get("created_at"), str):
                    # from datetime import datetime
                    try:
                        # 尝试解析 SQLite 默认格式 'YYYY-MM-DD HH:MM:SS.f'
                        data["created_at"] = datetime.strptime(data["created_at"], config.DATETIME_FORMAT)
                    except ValueError:
                        pass # 忽略解析错误
                return data
            return None

    @staticmethod
    def get_all_apps() -> List[Dict[str, Any]]:
        """获取所有应用信息"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT id, client_id, client_secret, app_name, redirect_uris, description, app_url, icon_url, created_at FROM registered_apps ORDER BY created_at DESC"
            )
            apps = []
            for row in cursor.fetchall():
                data = dict(row)
                # SQLite 存储的时间戳是字符串，需要转换成 datetime 对象
                # 检查 created_at 字段
                if isinstance(data.get("created_at"), str):
                    # from datetime import datetime
                    try:
                        # 尝试解析 SQLite 默认格式 'YYYY-MM-DD HH:MM:SS.f'
                        data["created_at"] = datetime.strptime(data["created_at"], config.DATETIME_FORMAT)
                    except ValueError:
                        pass # 忽略解析错误
                apps.append(data)
            return apps

    @staticmethod
    def update_app(client_id: str, app_name: str, redirect_uris: List[str], description: Optional[str] = None, app_url: Optional[str] = None, icon_url: Optional[str] = None):
        """更新应用信息"""
        with get_db() as conn:
            conn.execute(
                "UPDATE registered_apps SET app_name = ?, redirect_uris = ?, description = ?, app_url = ?, icon_url = ? WHERE client_id = ?",
                (app_name, json.dumps(redirect_uris), description, app_url, icon_url, client_id)
            )
            conn.commit()

    @staticmethod
    def delete_app(client_id: str):
        """删除应用"""
        with get_db() as conn:
            # 删除用户授权记录
            conn.execute("DELETE FROM user_authorizations WHERE client_id = ?", (client_id,))
            # 删除授权码
            conn.execute("DELETE FROM authorization_codes WHERE client_id = ?", (client_id,))
            # 删除应用
            conn.execute("DELETE FROM registered_apps WHERE client_id = ?", (client_id,))
            conn.commit()

    @staticmethod
    def verify_redirect_uri(client_id: str, redirect_uri: str) -> bool:
        """验证 redirect_uri 是否在允许列表中"""
        app_info = AppDB.get_app_by_client_id(client_id)
        if not app_info:
            return False

        try:
            allowed_uris = json.loads(app_info["redirect_uris"])
        except:
            allowed_uris = []

        result = redirect_uri in allowed_uris
        return result

class UserAuthorizationDB:
    """用户授权数据库操作"""

    @staticmethod
    def create_authorization(user_id: int, client_id: str, scope: Optional[str] = None):
        """创建用户授权记录"""
        with get_db() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO user_authorizations (user_id, client_id, scope, authorized_at)
                VALUES (?, ?, ?, ?)
                """,
                (user_id, client_id, scope, datetime.utcnow().strftime(config.DATETIME_FORMAT)) # 修复: 格式化时间
            )
            conn.commit()

    @staticmethod
    def check_authorization(user_id: int, client_id: str) -> bool:
        """检查用户是否已授权应用"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT 1 FROM user_authorizations WHERE user_id = ? AND client_id = ?",
                (user_id, client_id)
            )
            return cursor.fetchone() is not None

    @staticmethod
    def delete_authorization(user_id: int, client_id: str):
        """删除用户授权记录"""
        with get_db() as conn:
            conn.execute(
                "DELETE FROM user_authorizations WHERE user_id = ? AND client_id = ?",
                (user_id, client_id)
            )
            conn.commit()

class CustomFieldDB:
    """自定义字段数据库操作"""

    @staticmethod
    def create_field(field_key: str, field_label: str, field_type: str, field_options: Optional[List[str]] = None, is_required: bool = False, show_in_profile: bool = True, show_in_oauth: bool = False, display_order: int = 0) -> int:
        """创建自定义字段"""
        with get_db() as conn:
            cursor = conn.execute(
                "INSERT INTO custom_fields (field_key, field_label, field_type, field_options, is_required, show_in_profile, show_in_oauth, display_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (field_key, field_label, field_type, json.dumps(field_options) if field_options else None, is_required, show_in_profile, show_in_oauth, display_order)
            )
            conn.commit()
            return cursor.lastrowid

    @staticmethod
    def get_field_by_key(field_key: str) -> Optional[Dict[str, Any]]:
        """根据 field_key 获取字段信息"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT id, field_key, field_label, field_type, field_options, is_required, show_in_profile, show_in_oauth, display_order, created_at FROM custom_fields WHERE field_key = ?",
                (field_key,)
            )
            row = cursor.fetchone()
            if row:
                data = dict(row)
                # SQLite 存储的时间戳是字符串，需要转换成 datetime 对象
                # 检查 created_at 字段
                if isinstance(data.get("created_at"), str):
                    # from datetime import datetime
                    try:
                        # 尝试解析 SQLite 默认格式 'YYYY-MM-DD HH:MM:SS.f'
                        data["created_at"] = datetime.strptime(data["created_at"], config.DATETIME_FORMAT)
                    except ValueError:
                        pass # 忽略解析错误
                return data
            return None

    @staticmethod
    def get_all_fields() -> List[Dict[str, Any]]:
        """获取所有字段信息"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT id, field_key, field_label, field_type, field_options, is_required, show_in_profile, show_in_oauth, display_order, created_at FROM custom_fields ORDER BY display_order ASC"
            )
            fields = []
            for row in cursor.fetchall():
                data = dict(row)
                # SQLite 存储的时间戳是字符串，需要转换成 datetime 对象
                # 检查 created_at 字段
                if isinstance(data.get("created_at"), str):
                    # from datetime import datetime
                    try:
                        # 尝试解析 SQLite 默认格式 'YYYY-MM-DD HH:MM:SS.f'
                        data["created_at"] = datetime.strptime(data["created_at"], config.DATETIME_FORMAT)
                    except ValueError:
                        pass # 忽略解析错误
                fields.append(data)
            return fields

    @staticmethod
    def update_field(field_key: str, field_label: str, field_type: str, field_options: Optional[List[str]] = None, is_required: bool = False, show_in_profile: bool = True, show_in_oauth: bool = False, display_order: int = 0):
        """更新自定义字段"""
        with get_db() as conn:
            conn.execute(
                "UPDATE custom_fields SET field_label = ?, field_type = ?, field_options = ?, is_required = ?, show_in_profile = ?, show_in_oauth = ?, display_order = ? WHERE field_key = ?",
                (field_label, field_type, json.dumps(field_options) if field_options else None, is_required, show_in_profile, show_in_oauth, display_order, field_key)
            )
            conn.commit()

    @staticmethod
    def delete_field(field_key: str):
        """删除自定义字段"""
        with get_db() as conn:
            # 删除用户自定义数据
            conn.execute("DELETE FROM user_custom_data WHERE field_key = ?", (field_key,))
            # 删除字段
            conn.execute("DELETE FROM custom_fields WHERE field_key = ?", (field_key,))
            conn.commit()

class UserCustomDataDB:
    """用户自定义数据数据库操作"""

    @staticmethod
    def set_user_data(user_id: int, field_key: str, field_value: Optional[str]):
        """设置用户自定义数据"""
        with get_db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO user_custom_data (user_id, field_key, field_value, updated_at) VALUES (?, ?, ?, ?)",
                (user_id, field_key, field_value, datetime.utcnow().strftime(config.DATETIME_FORMAT))
            )
            conn.commit()

    @staticmethod
    def get_user_data(user_id: int, field_key: str) -> Optional[str]:
        """获取用户自定义数据"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT field_value FROM user_custom_data WHERE user_id = ? AND field_key = ?",
                (user_id, field_key)
            )
            row = cursor.fetchone()
            return row[0] if row else None

    @staticmethod
    def get_all_user_data(user_id: int) -> Dict[str, Optional[str]]:
        """获取用户所有自定义数据"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT field_key, field_value FROM user_custom_data WHERE user_id = ?",
                (user_id,)
            )
            return {row[0]: row[1] for row in cursor.fetchall()}

    @staticmethod
    def delete_user_data(user_id: int, field_key: str):
        """删除用户自定义数据"""
        with get_db() as conn:
            conn.execute(
                "DELETE FROM user_custom_data WHERE user_id = ? AND field_key = ?",
                (user_id, field_key)
            )
            conn.commit()

class LoginLogDB:
    """登录日志数据库操作"""

    @staticmethod
    def create_log(
        email: str,
        status: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        user_id: Optional[int] = None,
        message: Optional[str] = None,
    ):
        """记录登录日志"""
        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO login_logs (user_id, email, ip_address, user_agent, status, message)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (user_id, email, ip_address, user_agent, status, message),
            )
            conn.commit()

    @staticmethod
    def get_user_logs(user_id: int, limit: int = 10) -> List[Dict[str, Any]]:
        """获取用户的最新登录日志"""
        with get_db() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM login_logs WHERE user_id = ? ORDER BY login_time DESC LIMIT ?
                """,
                (user_id, limit),
            )
            return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def get_recent_logs(limit: int = 20) -> List[Dict[str, Any]]:
        """获取最近的登录日志（用于管理员审计）"""
        with get_db() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM login_logs ORDER BY login_time DESC LIMIT ?
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def get_logs_by_email(email: str, limit: int = 10) -> List[Dict[str, Any]]:
        """根据邮箱获取登录日志"""
        with get_db() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM login_logs WHERE email = ? ORDER BY login_time DESC LIMIT ?
                """,
                (email, limit),
            )
            return [dict(row) for row in cursor.fetchall()]


class MFADB:
    """MFA 数据库操作"""

    @staticmethod
    def get_mfa_status(user_id: int) -> Dict[str, Any]:
        """获取用户MFA状态"""
        with get_db() as conn:
            row = conn.execute(
                "SELECT enabled FROM mfa_settings WHERE user_id = ?", (user_id,)
            ).fetchone()
            enabled = bool(row and row["enabled"])

            recovery_count = 0
            if enabled:
                result = conn.execute(
                    "SELECT COUNT(*) FROM mfa_recovery_codes WHERE user_id = ? AND used = 0",
                    (user_id,),
                ).fetchone()
                recovery_count = result[0] if result else 0

            return {"enabled": enabled, "recovery_codes_count": recovery_count}

    @staticmethod
    def get_mfa_secret(user_id: int) -> Optional[str]:
        """获取用户MFA密钥"""
        with get_db() as conn:
            row = conn.execute(
                "SELECT secret FROM mfa_settings WHERE user_id = ? AND enabled = 1",
                (user_id,),
            ).fetchone()
            return row["secret"] if row else None

    @staticmethod
    def store_temporary_secret(user_id: int, secret: str, expires_at) -> None:
        """临时存储MFA密钥（设置过程中使用）"""
        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO mfa_temp_secrets (user_id, secret, expires_at)
                VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, expires_at=excluded.expires_at
                """,
                (user_id, secret, expires_at.strftime("%Y-%m-%d %H:%M:%S")),
            )
            conn.commit()

    @staticmethod
    def get_temporary_secret(user_id: int) -> Optional[Dict[str, Any]]:
        """获取临时MFA密钥"""
        with get_db() as conn:
            row = conn.execute(
                "SELECT secret, expires_at FROM mfa_temp_secrets WHERE user_id = ? AND expires_at > datetime('now')",
                (user_id,),
            ).fetchone()
            return dict(row) if row else None

    @staticmethod
    def delete_temporary_secret(user_id: int) -> None:
        """删除临时MFA密钥"""
        with get_db() as conn:
            conn.execute("DELETE FROM mfa_temp_secrets WHERE user_id = ?", (user_id,))
            conn.commit()

    @staticmethod
    def enable_mfa(user_id: int, secret: str, recovery_codes: list) -> None:
        """启用MFA"""
        with get_db() as conn:
            conn.execute(
                """
                INSERT INTO mfa_settings (user_id, secret, enabled)
                VALUES (?, ?, 1)
                ON CONFLICT(user_id) DO UPDATE SET secret=excluded.secret, enabled=1
                """,
                (user_id, secret),
            )
            # 删除旧恢复码并插入新的
            conn.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", (user_id,))
            for code in recovery_codes:
                conn.execute(
                    "INSERT INTO mfa_recovery_codes (user_id, code) VALUES (?, ?)",
                    (user_id, code),
                )
            conn.commit()

    @staticmethod
    def disable_mfa(user_id: int) -> None:
        """禁用MFA"""
        with get_db() as conn:
            conn.execute(
                "UPDATE mfa_settings SET enabled = 0 WHERE user_id = ?", (user_id,)
            )
            conn.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", (user_id,))
            conn.commit()

    @staticmethod
    def verify_recovery_code(user_id: int, code: str) -> bool:
        """验证并消耗恢复码"""
        with get_db() as conn:
            row = conn.execute(
                "SELECT id FROM mfa_recovery_codes WHERE user_id = ? AND code = ? AND used = 0",
                (user_id, code),
            ).fetchone()
            if not row:
                return False
            conn.execute(
                "UPDATE mfa_recovery_codes SET used = 1 WHERE id = ?", (row["id"],)
            )
            conn.commit()
            return True

    @staticmethod
    def update_recovery_codes(user_id: int, recovery_codes: list) -> None:
        """更新恢复码"""
        with get_db() as conn:
            conn.execute("DELETE FROM mfa_recovery_codes WHERE user_id = ?", (user_id,))
            for code in recovery_codes:
                conn.execute(
                    "INSERT INTO mfa_recovery_codes (user_id, code) VALUES (?, ?)",
                    (user_id, code),
                )
            conn.commit()


class AuditLogDB:
    """操作审计日志 — 记录管理员和用户的关键操作"""

    @staticmethod
    def _ensure_table():
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

    @staticmethod
    def log(
        action_type: str,
        operator_id: Optional[int] = None,
        operator_email: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        detail: Optional[str] = None,
        success: bool = True,
        ip_address: Optional[str] = None,
    ):
        """写入一条审计记录，失败时静默忽略（不影响主业务）"""
        try:
            AuditLogDB._ensure_table()
            with get_db() as conn:
                conn.execute(
                    """INSERT INTO audit_logs
                       (operator_id, operator_email, action_type, target_type,
                        target_id, detail, success, ip_address)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (operator_id, operator_email, action_type, target_type,
                     str(target_id) if target_id is not None else None,
                     detail, 1 if success else 0, ip_address)
                )
                conn.commit()
        except Exception:
            pass  # 审计写入失败不应影响主流程


class PasswordResetDB:
    """密码重置令牌管理"""

    @staticmethod
    def create_token(user_id: int, token: str, expires_minutes: int = 30) -> bool:
        """创建重置令牌，同时使该用户所有旧令牌失效"""
        try:
            with get_db() as conn:
                # 先清除该用户的旧令牌
                conn.execute(
                    "DELETE FROM password_reset_tokens WHERE user_id = ?",
                    (user_id,)
                )
                conn.execute(
                    "INSERT INTO password_reset_tokens (user_id, token, expires_at) "
                    "VALUES (?, ?, datetime('now', ? || ' minutes'))",
                    (user_id, token, str(expires_minutes))
                )
            return True
        except Exception:
            return False

    @staticmethod
    def verify_token(token: str) -> Optional[dict]:
        """验证令牌并返回关联用户信息，令牌无效/已使用/已过期返回 None"""
        try:
            with get_db() as conn:
                row = conn.execute(
                    "SELECT id, user_id, expires_at, used FROM password_reset_tokens "
                    "WHERE token = ? AND used = 0 AND expires_at > datetime('now')",
                    (token,)
                ).fetchone()
                return dict(row) if row else None
        except Exception:
            return None

    @staticmethod
    def mark_used(token: str) -> bool:
        """将令牌标记为已使用"""
        try:
            with get_db() as conn:
                conn.execute(
                    "UPDATE password_reset_tokens SET used = 1 WHERE token = ?",
                    (token,)
                )
            return True
        except Exception:
            return False

    @staticmethod
    def cleanup_expired():
        """清理过期和已使用的令牌"""
        try:
            with get_db() as conn:
                conn.execute(
                    "DELETE FROM password_reset_tokens WHERE used = 1 OR expires_at <= datetime('now')"
                )
        except Exception:
            pass


class PortalTokenDB:
    """Portal API Token 数据库操作"""

    @staticmethod
    def create_token(name: str, created_by: int) -> str:
        import secrets
        token = "portal_" + secrets.token_urlsafe(32)
        with get_db() as conn:
            conn.execute(
                "INSERT INTO portal_api_tokens (token, name, created_by) VALUES (?, ?, ?)",
                (token, name, created_by)
            )
            conn.commit()
        return token

    @staticmethod
    def get_all_tokens(created_by: int) -> list:
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT id, token, name, last_used_at, created_at FROM portal_api_tokens WHERE created_by = ? ORDER BY created_at DESC",
                (created_by,)
            )
            return [dict(r) for r in cursor.fetchall()]

    @staticmethod
    def verify_token(token: str) -> Optional[Dict[str, Any]]:
        with get_db() as conn:
            row = conn.execute(
                "SELECT id, token, name, created_by FROM portal_api_tokens WHERE token = ?",
                (token,)
            ).fetchone()
            if row:
                conn.execute(
                    "UPDATE portal_api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE token = ?",
                    (token,)
                )
                conn.commit()
                return dict(row)
            return None

    @staticmethod
    def delete_token(token_id: int, created_by: int):
        with get_db() as conn:
            conn.execute(
                "DELETE FROM portal_api_tokens WHERE id = ? AND created_by = ?",
                (token_id, created_by)
            )
            conn.commit()


class TrustedDeviceDB:
    """可信设备数据库操作"""

    @staticmethod
    def is_trusted(user_id: int, device_fingerprint: str) -> bool:
        """检查设备是否在信任列表且未过期"""
        with get_db() as conn:
            row = conn.execute(
                """SELECT id FROM trusted_devices
                   WHERE user_id = ? AND device_fingerprint = ?
                   AND expires_at > datetime('now')""",
                (user_id, device_fingerprint)
            ).fetchone()
            return row is not None

    @staticmethod
    def trust_device(user_id: int, device_fingerprint: str, device_name: str = None, days: int = 30):
        """将设备加入信任列表"""
        from datetime import datetime, timedelta
        expires_at = (datetime.utcnow() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        with get_db() as conn:
            conn.execute(
                """INSERT INTO trusted_devices (user_id, device_fingerprint, device_name, expires_at)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(user_id, device_fingerprint) DO UPDATE SET
                   expires_at = excluded.expires_at,
                   device_name = excluded.device_name""",
                (user_id, device_fingerprint, device_name, expires_at)
            )
            conn.commit()

    @staticmethod
    def remove_device(user_id: int, device_fingerprint: str):
        """移除信任设备"""
        with get_db() as conn:
            conn.execute(
                "DELETE FROM trusted_devices WHERE user_id = ? AND device_fingerprint = ?",
                (user_id, device_fingerprint)
            )
            conn.commit()

    @staticmethod
    def get_user_trusted_devices(user_id: int):
        """获取用户所有可信设备"""
        with get_db() as conn:
            cursor = conn.execute(
                """SELECT id, device_fingerprint, device_name, created_at, expires_at
                   FROM trusted_devices WHERE user_id = ? ORDER BY created_at DESC""",
                (user_id,)
            )
            return [dict(r) for r in cursor.fetchall()]

class PasskeyDB:
    """Passkeys（WebAuthn 通行密钥）数据库操作"""

    @staticmethod
    def save_challenge(challenge: str, type: str, user_id=None, expires_minutes: int = 5):
        """保存 WebAuthn challenge（注册或认证流程用）"""
        from datetime import datetime, timedelta
        expires_at = (datetime.utcnow() + timedelta(minutes=expires_minutes)).strftime("%Y-%m-%d %H:%M:%S")
        with get_db() as conn:
            # 清理过期 challenge
            conn.execute("DELETE FROM webauthn_challenges WHERE expires_at < datetime('now')")
            conn.execute(
                "INSERT INTO webauthn_challenges (user_id, challenge, type, expires_at) VALUES (?, ?, ?, ?)",
                (user_id, challenge, type, expires_at)
            )
            conn.commit()

    @staticmethod
    def pop_challenge(challenge: str, type: str):
        """取出并删除 challenge（一次性使用）"""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM webauthn_challenges WHERE challenge = ? AND type = ? AND expires_at > datetime('now')",
                (challenge, type)
            )
            row = cursor.fetchone()
            if row:
                conn.execute("DELETE FROM webauthn_challenges WHERE id = ?", (row["id"],))
                conn.commit()
                return dict(row)
        return None

    @staticmethod
    def add_passkey(user_id: int, credential_id: str, public_key: bytes, sign_count: int, device_name: str = None):
        with get_db() as conn:
            conn.execute(
                """INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, device_name)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, credential_id, public_key, sign_count, device_name)
            )
            conn.commit()

    @staticmethod
    def get_passkeys_by_user(user_id: int):
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,)
            )
            return [dict(r) for r in cursor.fetchall()]

    @staticmethod
    def get_passkey_by_credential_id(credential_id: str):
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM passkeys WHERE credential_id = ?",
                (credential_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    @staticmethod
    def update_sign_count(credential_id: str, sign_count: int):
        with get_db() as conn:
            conn.execute(
                "UPDATE passkeys SET sign_count = ?, last_used_at = datetime('now') WHERE credential_id = ?",
                (sign_count, credential_id)
            )
            conn.commit()

    @staticmethod
    def delete_passkey(passkey_id: int, user_id: int):
        with get_db() as conn:
            conn.execute(
                "DELETE FROM passkeys WHERE id = ? AND user_id = ?",
                (passkey_id, user_id)
            )
            conn.commit()

    @staticmethod
    def get_all_credential_descriptors():
        """获取所有凭证 ID（用于无用户名登录流程）"""
        with get_db() as conn:
            cursor = conn.execute("SELECT credential_id FROM passkeys")
            return [row["credential_id"] for row in cursor.fetchall()]
