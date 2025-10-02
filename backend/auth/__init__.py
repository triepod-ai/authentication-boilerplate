"""
Authentication Module

Provides user and admin authentication systems for Flask applications.
"""

from .user_auth import UserAuthSystem, require_user, optional_user
from .admin_auth import AdminAuthSystem, require_admin, require_role, require_super_admin

__all__ = [
    'UserAuthSystem',
    'AdminAuthSystem',
    'require_user',
    'optional_user',
    'require_admin',
    'require_role',
    'require_super_admin',
]
