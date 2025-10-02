"""
Admin Authentication System

Session-based authentication for admin users with role-based access control.
Features:
- Session token management with expiry
- Role-based access control (admin, super_admin, moderator)
- Permission-based decorators
- Audit logging support
"""

from datetime import datetime, timedelta
from flask import request, jsonify
from functools import wraps
from typing import Optional, Dict, Any
import secrets


class AdminAuthSystem:
    """Admin authentication system with session tokens and RBAC"""

    def __init__(self, app=None, db=None, admin_model=None, audit_model=None):
        """
        Initialize admin authentication system.

        Args:
            app: Flask application instance
            db: SQLAlchemy database instance
            admin_model: AdminUser model class
            audit_model: AdminAuditLog model class (optional)
        """
        self.app = app
        self.db = db
        self.admin_model = admin_model
        self.audit_model = audit_model
        self.session_expiry = 24 * 60 * 60  # 24 hours default

        if app is not None:
            self.init_app(app)

    def init_app(self, app, db=None, admin_model=None, audit_model=None):
        """
        Initialize with Flask app.

        Args:
            app: Flask application instance
            db: SQLAlchemy database instance (optional)
            admin_model: AdminUser model class (optional)
            audit_model: AdminAuditLog model class (optional)
        """
        if db:
            self.db = db
        if admin_model:
            self.admin_model = admin_model
        if audit_model:
            self.audit_model = audit_model

        self.session_expiry = app.config.get('ADMIN_SESSION_EXPIRY_SECONDS', 24 * 60 * 60)

    def authenticate_admin(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate admin user.

        Args:
            username: Admin username
            password: Admin password

        Returns:
            Authentication result with token and admin user, or None if failed
        """
        if not self.admin_model or not self.db:
            return None

        admin = self.db.session.query(self.admin_model).filter_by(
            username=username
        ).first()

        if not admin or not admin.check_password(password):
            # Log failed login if admin exists
            if admin and self.audit_model:
                self._log_action(admin.id, 'login_failed', details={'username': username})
            return None

        if not admin.is_active:
            return None

        # Generate session token
        token = self._generate_session_token(admin)

        # Update last login
        admin.last_login = datetime.utcnow()
        self.db.session.commit()

        # Log successful login
        if self.audit_model:
            self._log_action(admin.id, 'login', details={'username': username})

        return {
            'token': token,
            'admin': admin,
            'expires_at': admin.session_expires
        }

    def _generate_session_token(self, admin: Any) -> str:
        """
        Generate session token for admin.

        Args:
            admin: AdminUser model instance

        Returns:
            Session token string
        """
        admin.session_token = secrets.token_urlsafe(32)
        admin.session_expires = datetime.utcnow() + timedelta(seconds=self.session_expiry)
        return admin.session_token

    def verify_session(self, token: str) -> Optional[Any]:
        """
        Verify admin session token.

        Args:
            token: Session token

        Returns:
            Admin user instance or None if invalid
        """
        if not self.admin_model or not self.db:
            return None

        admin = self.db.session.query(self.admin_model).filter_by(
            session_token=token,
            is_active=True
        ).first()

        if not admin or not self._is_session_valid(admin):
            return None

        return admin

    def _is_session_valid(self, admin: Any) -> bool:
        """
        Check if admin session is valid.

        Args:
            admin: AdminUser model instance

        Returns:
            True if session is valid
        """
        if not admin.session_token or not admin.session_expires:
            return False
        return datetime.utcnow() < admin.session_expires

    def logout_admin(self, admin: Any) -> None:
        """
        Logout admin user.

        Args:
            admin: AdminUser model instance
        """
        if self.audit_model:
            self._log_action(admin.id, 'logout')

        admin.session_token = None
        admin.session_expires = None
        if self.db:
            self.db.session.commit()

    def get_current_admin(self) -> Optional[Any]:
        """
        Get current authenticated admin from request.

        Returns:
            Admin user instance or None
        """
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]
        return self.verify_session(token)

    def _log_action(self, admin_id: int, action: str, resource_type: Optional[str] = None,
                    resource_id: Optional[int] = None, details: Optional[Dict] = None) -> None:
        """
        Log admin action for audit trail.

        Args:
            admin_id: Admin user ID
            action: Action performed
            resource_type: Type of resource affected (optional)
            resource_id: ID of resource affected (optional)
            details: Additional details (optional)
        """
        if not self.audit_model or not self.db:
            return

        import json
        audit_log = self.audit_model(
            admin_user_id=admin_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=json.dumps(details) if details else None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        self.db.session.add(audit_log)
        self.db.session.commit()


# Decorator functions
def require_admin(auth_system: AdminAuthSystem):
    """
    Decorator factory to require admin authentication.

    Args:
        auth_system: AdminAuthSystem instance

    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            admin = auth_system.get_current_admin()

            if not admin:
                return jsonify({'error': 'Admin authentication required'}), 401

            # Add admin to request context
            request.admin_user = admin

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_role(auth_system: AdminAuthSystem, *allowed_roles):
    """
    Decorator factory to require specific admin role.

    Args:
        auth_system: AdminAuthSystem instance
        *allowed_roles: Allowed role names

    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            admin = auth_system.get_current_admin()

            if not admin:
                return jsonify({'error': 'Admin authentication required'}), 401

            if admin.role not in allowed_roles:
                return jsonify({'error': f'Role must be one of: {", ".join(allowed_roles)}'}), 403

            request.admin_user = admin
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def require_super_admin(auth_system: AdminAuthSystem):
    """
    Decorator factory to require super admin role.

    Args:
        auth_system: AdminAuthSystem instance

    Returns:
        Decorator function
    """
    return require_role(auth_system, 'super_admin')
