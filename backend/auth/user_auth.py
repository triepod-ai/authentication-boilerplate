"""
User Authentication System

JWT-based authentication system with optional multi-tenant support.
Features:
- JWT token generation and verification
- Password hashing with SHA-256 and salt
- Token expiry management
- Failed login tracking
- Optional multi-tenant isolation
"""

import jwt
import hashlib
import secrets
from datetime import datetime, timedelta
from flask import request, jsonify, g
from functools import wraps
from typing import Dict, Optional, Any, Tuple


class UserAuthSystem:
    """User authentication system with JWT tokens"""

    def __init__(self, app=None, db=None, user_model=None):
        """
        Initialize authentication system.

        Args:
            app: Flask application instance
            db: SQLAlchemy database instance
            user_model: User model class
        """
        self.app = app
        self.db = db
        self.user_model = user_model
        self.jwt_secret = None
        self.token_expiry = 7 * 24 * 60 * 60  # 7 days default
        self.multi_tenant_enabled = False

        if app is not None:
            self.init_app(app)

    def init_app(self, app, db=None, user_model=None):
        """
        Initialize authentication system with Flask app.

        Args:
            app: Flask application instance
            db: SQLAlchemy database instance (optional)
            user_model: User model class (optional)
        """
        if db:
            self.db = db
        if user_model:
            self.user_model = user_model

        self.jwt_secret = app.config.get('JWT_SECRET', 'change-this-secret-in-production')
        self.token_expiry = app.config.get('TOKEN_EXPIRY_SECONDS', 7 * 24 * 60 * 60)
        self.multi_tenant_enabled = app.config.get('MULTI_TENANT_ENABLED', False)

    def hash_password(self, password: str) -> str:
        """
        Hash password using SHA-256 with salt.

        Args:
            password: Plain text password

        Returns:
            Hashed password in format "salt:hash"
        """
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return f"{salt}:{password_hash}"

    def verify_password(self, password: str, password_hash: str) -> bool:
        """
        Verify password against stored hash.

        Args:
            password: Plain text password to verify
            password_hash: Stored password hash

        Returns:
            True if password matches, False otherwise
        """
        try:
            salt, stored_hash = password_hash.split(':')
            computed_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            return stored_hash == computed_hash
        except ValueError:
            return False

    def generate_token(self, user: Any, tenant: Optional[str] = None) -> str:
        """
        Generate JWT token for user.

        Args:
            user: User model instance
            tenant: Tenant identifier (optional, for multi-tenant apps)

        Returns:
            JWT token string
        """
        payload = {
            'user_id': user.id,
            'email': user.email,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=self.token_expiry),
            'type': 'user'
        }

        # Add tenant info if multi-tenant is enabled
        if self.multi_tenant_enabled and tenant:
            payload['tenant'] = tenant
            payload['iss'] = f'app-{tenant}'
        else:
            payload['iss'] = 'app'

        token = jwt.encode(payload, self.jwt_secret, algorithm='HS256')

        # Update user login tracking
        user.last_login = datetime.utcnow()
        user.login_count = (user.login_count or 0) + 1
        if self.db:
            self.db.session.commit()

        return token

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Verify and decode JWT token.

        Args:
            token: JWT token string

        Returns:
            Decoded token payload or None if invalid
        """
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])

            # Verify token type
            if payload.get('type') != 'user':
                return None

            # Get user
            if not self.user_model or not self.db:
                return payload

            user = self.db.session.get(self.user_model, payload['user_id'])
            if not user or not user.is_active:
                return None

            return {
                'user_id': payload['user_id'],
                'email': payload['email'],
                'tenant': payload.get('tenant'),
                'user': user
            }

        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def authenticate_user(self, email: str, password: str, tenant: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Authenticate user with email/password.

        Args:
            email: User email
            password: User password
            tenant: Tenant identifier (optional)

        Returns:
            Authentication result with token and user, or None if failed
        """
        if not self.user_model or not self.db:
            return None

        # Build query
        query = self.db.session.query(self.user_model).filter_by(
            email=email,
            is_active=True
        )

        # Add tenant filter if multi-tenant is enabled
        if self.multi_tenant_enabled and tenant:
            query = query.filter_by(tenant=tenant)

        user = query.first()

        if not user:
            return None

        # Verify password
        if not user.check_password(password):
            # Track failed login attempt
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            user.last_failed_login = datetime.utcnow()
            self.db.session.commit()
            return None

        # Reset failed login attempts on success
        user.failed_login_attempts = 0
        user.last_failed_login = None

        # Generate token
        token = self.generate_token(user, tenant)

        return {
            'token': token,
            'user': user,
            'tenant': tenant
        }

    def register_user(self, email: str, password: str, name: str, tenant: Optional[str] = None) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Register new user.

        Args:
            email: User email
            password: User password
            name: User name
            tenant: Tenant identifier (optional)

        Returns:
            Tuple of (auth_result, error_message)
        """
        if not self.user_model or not self.db:
            return None, 'Database not configured'

        # Check if user exists
        query = self.db.session.query(self.user_model).filter_by(email=email)
        if self.multi_tenant_enabled and tenant:
            query = query.filter_by(tenant=tenant)

        if query.first():
            return None, 'User already exists'

        # Create new user
        user_data = {
            'email': email,
            'name': name,
            'is_active': True,
            'created_at': datetime.utcnow()
        }

        if self.multi_tenant_enabled and tenant:
            user_data['tenant'] = tenant

        user = self.user_model(**user_data)
        user.set_password(password)

        self.db.session.add(user)
        self.db.session.commit()

        # Generate token
        token = self.generate_token(user, tenant)

        return {
            'token': token,
            'user': user,
            'tenant': tenant
        }, None

    def get_current_user(self) -> Optional[Dict[str, Any]]:
        """
        Get current authenticated user from request.

        Returns:
            User data from token or None
        """
        auth_header = request.headers.get('Authorization')

        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]
        return self.verify_token(token)

    def refresh_token(self, user: Any, tenant: Optional[str] = None) -> str:
        """
        Refresh user token.

        Args:
            user: User model instance
            tenant: Tenant identifier (optional)

        Returns:
            New JWT token
        """
        return self.generate_token(user, tenant)


# Decorator functions
def require_user(auth_system: UserAuthSystem):
    """
    Decorator factory to require user authentication.

    Args:
        auth_system: UserAuthSystem instance

    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_data = auth_system.get_current_user()

            if not auth_data:
                return jsonify({'error': 'Authentication required'}), 401

            # Add user data to request context
            request.current_user = auth_data['user']
            request.user_data = auth_data

            return f(*args, **kwargs)
        return decorated_function
    return decorator


def optional_user(auth_system: UserAuthSystem):
    """
    Decorator factory for endpoints that work with or without authentication.

    Args:
        auth_system: UserAuthSystem instance

    Returns:
        Decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_data = auth_system.get_current_user()

            if auth_data:
                request.current_user = auth_data['user']
                request.user_data = auth_data
            else:
                request.current_user = None
                request.user_data = None

            return f(*args, **kwargs)
        return decorated_function
    return decorator
