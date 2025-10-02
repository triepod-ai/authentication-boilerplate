"""
Routes Module

API route blueprints for authentication.
"""

from .user_auth_routes import create_user_auth_routes
from .admin_auth_routes import create_admin_auth_routes

__all__ = [
    'create_user_auth_routes',
    'create_admin_auth_routes',
]
