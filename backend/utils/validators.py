"""
Validation Utilities

Common validation functions for authentication.
"""

import re
from typing import Tuple, Optional


def validate_email(email: str) -> Tuple[bool, Optional[str]]:
    """
    Validate email format.

    Args:
        email: Email address to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not email:
        return False, 'Email is required'

    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_pattern, email):
        return False, 'Invalid email format'

    return True, None


def validate_password(password: str, min_length: int = 8) -> Tuple[bool, Optional[str]]:
    """
    Validate password strength.

    Args:
        password: Password to validate
        min_length: Minimum password length

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not password:
        return False, 'Password is required'

    if len(password) < min_length:
        return False, f'Password must be at least {min_length} characters'

    # Optional: Add more strength requirements
    # has_upper = any(c.isupper() for c in password)
    # has_lower = any(c.islower() for c in password)
    # has_digit = any(c.isdigit() for c in password)
    # has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)

    return True, None


def validate_username(username: str, min_length: int = 3, max_length: int = 80) -> Tuple[bool, Optional[str]]:
    """
    Validate username format.

    Args:
        username: Username to validate
        min_length: Minimum username length
        max_length: Maximum username length

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not username:
        return False, 'Username is required'

    if len(username) < min_length:
        return False, f'Username must be at least {min_length} characters'

    if len(username) > max_length:
        return False, f'Username must be no more than {max_length} characters'

    # Allow alphanumeric, underscore, and hyphen
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, 'Username can only contain letters, numbers, underscores, and hyphens'

    return True, None
