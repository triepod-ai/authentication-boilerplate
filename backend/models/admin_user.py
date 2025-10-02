"""
Admin User Model

Database model for admin users with role-based access control.
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

# Import db from user.py to use the same instance
from .user import db


class AdminUser(db.Model):
    """Admin user model with RBAC"""

    __tablename__ = 'admin_users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    # Role-based access control
    # Roles: 'super_admin', 'admin', 'moderator'
    role = db.Column(db.String(50), nullable=False, default='admin')

    # Account status
    is_active = db.Column(db.Boolean, default=True)

    # Session management
    session_token = db.Column(db.String(255), index=True)
    session_expires = db.Column(db.DateTime)

    # Login tracking
    last_login = db.Column(db.DateTime)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password(self, password: str) -> None:
        """
        Set admin password.

        Args:
            password: Plain text password
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """
        Verify password against stored hash.

        Args:
            password: Plain text password to verify

        Returns:
            True if password matches
        """
        return check_password_hash(self.password_hash, password)

    def generate_session_token(self, expiry_hours: int = 24) -> str:
        """
        Generate a new session token.

        Args:
            expiry_hours: Hours until token expires

        Returns:
            Session token string
        """
        self.session_token = secrets.token_urlsafe(32)
        self.session_expires = datetime.utcnow() + timedelta(hours=expiry_hours)
        return self.session_token

    def is_session_valid(self) -> bool:
        """
        Check if current session is valid.

        Returns:
            True if session is valid
        """
        if not self.session_token or not self.session_expires:
            return False
        return datetime.utcnow() < self.session_expires

    def clear_session(self) -> None:
        """Clear session data."""
        self.session_token = None
        self.session_expires = None

    def has_role(self, *roles) -> bool:
        """
        Check if admin has any of the specified roles.

        Args:
            *roles: Role names to check

        Returns:
            True if admin has any of the roles
        """
        return self.role in roles

    def is_super_admin(self) -> bool:
        """
        Check if admin is super admin.

        Returns:
            True if super admin
        """
        return self.role == 'super_admin'

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert admin user to dictionary.

        Args:
            include_sensitive: Include sensitive fields

        Returns:
            Dictionary representation
        """
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

        if include_sensitive:
            data.update({
                'last_login': self.last_login.isoformat() if self.last_login else None,
                'session_expires': self.session_expires.isoformat() if self.session_expires else None,
            })

        return data

    def __repr__(self) -> str:
        return f'<AdminUser {self.username} ({self.role})>'
