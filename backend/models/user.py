"""
User Model

Database model for regular users with authentication support.
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import secrets

db = SQLAlchemy()


class User(db.Model):
    """User model for authentication"""

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # Optional: Multi-tenant support
    tenant = db.Column(db.String(50), index=True)

    # Account status
    is_active = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=False)

    # Login tracking
    last_login = db.Column(db.DateTime)
    login_count = db.Column(db.Integer, default=0)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def set_password(self, password: str, method: str = 'werkzeug') -> None:
        """
        Set user password using specified hashing method.

        Args:
            password: Plain text password
            method: Hashing method ('werkzeug' or 'sha256')
        """
        if method == 'werkzeug':
            self.password_hash = generate_password_hash(password)
        elif method == 'sha256':
            salt = secrets.token_hex(16)
            password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
            self.password_hash = f"{salt}:{password_hash}"
        else:
            raise ValueError(f"Unsupported hashing method: {method}")

    def check_password(self, password: str) -> bool:
        """
        Verify password against stored hash.

        Automatically detects hashing method.

        Args:
            password: Plain text password to verify

        Returns:
            True if password matches
        """
        # Check if it's SHA-256 format (salt:hash)
        # SHA-256 format has exactly one colon and both parts are hex strings
        if ':' in self.password_hash and not self.password_hash.startswith(('scrypt:', 'pbkdf2:', 'argon2:')):
            try:
                parts = self.password_hash.split(':')
                if len(parts) == 2:
                    salt, stored_hash = parts
                    # Verify both parts are hex strings
                    int(salt, 16)
                    int(stored_hash, 16)
                    # Compute and compare
                    computed_hash = hashlib.sha256((password + salt).encode()).hexdigest()
                    return stored_hash == computed_hash
            except (ValueError, TypeError):
                pass

        # Werkzeug format (scrypt, pbkdf2, argon2, etc.)
        return check_password_hash(self.password_hash, password)

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert user to dictionary.

        Args:
            include_sensitive: Include sensitive fields

        Returns:
            Dictionary representation
        """
        data = {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'is_active': self.is_active,
            'email_verified': self.email_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

        if self.tenant:
            data['tenant'] = self.tenant

        if include_sensitive:
            data.update({
                'last_login': self.last_login.isoformat() if self.last_login else None,
                'login_count': self.login_count,
                'failed_login_attempts': self.failed_login_attempts,
            })

        return data

    def __repr__(self) -> str:
        return f'<User {self.email}>'
