"""
User Authentication API Routes

Public API endpoints for user authentication.
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
import re


def create_user_auth_routes(auth_system, db=None):
    """
    Create user authentication routes blueprint.

    Args:
        auth_system: UserAuthSystem instance
        db: SQLAlchemy database instance (optional)

    Returns:
        Flask Blueprint
    """
    user_auth_bp = Blueprint('user_auth', __name__, url_prefix='/api/auth')

    # Import decorators
    from auth import require_user, optional_user

    @user_auth_bp.route('/register', methods=['POST'])
    def register():
        """User registration endpoint"""
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            name = data.get('name')
            tenant = data.get('tenant')  # Optional for multi-tenant apps

            # Validation
            if not email or not password or not name:
                return jsonify({'error': 'Email, password, and name are required'}), 400

            # Validate email format
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                return jsonify({'error': 'Invalid email format'}), 400

            # Validate password strength
            if len(password) < 8:
                return jsonify({'error': 'Password must be at least 8 characters'}), 400

            # Register user
            result, error = auth_system.register_user(email, password, name, tenant)

            if error:
                return jsonify({'error': error}), 400

            return jsonify({
                'token': result['token'],
                'user': result['user'].to_dict(),
                'message': 'Registration successful'
            }), 201

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @user_auth_bp.route('/login', methods=['POST'])
    def login():
        """User login endpoint"""
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            tenant = data.get('tenant')  # Optional for multi-tenant apps

            if not email or not password:
                return jsonify({'error': 'Email and password are required'}), 400

            # Authenticate user
            auth_result = auth_system.authenticate_user(email, password, tenant)

            if not auth_result:
                return jsonify({'error': 'Invalid credentials'}), 401

            return jsonify({
                'token': auth_result['token'],
                'user': auth_result['user'].to_dict(),
                'message': 'Login successful'
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @user_auth_bp.route('/logout', methods=['POST'])
    @require_user(auth_system)
    def logout():
        """User logout endpoint"""
        try:
            # Token invalidation is handled client-side by removing the token
            # Update last activity
            if hasattr(request, 'current_user'):
                request.current_user.last_activity = datetime.utcnow()
                if db:
                    db.session.commit()

            return jsonify({'message': 'Logged out successfully'})

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @user_auth_bp.route('/profile', methods=['GET'])
    @require_user(auth_system)
    def get_profile():
        """Get current user profile"""
        try:
            user = request.current_user

            return jsonify({
                'user': user.to_dict(include_sensitive=True),
                'account_status': {
                    'is_active': user.is_active,
                    'email_verified': user.email_verified,
                    'last_login': user.last_login.isoformat() if user.last_login else None
                }
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @user_auth_bp.route('/profile', methods=['PUT'])
    @require_user(auth_system)
    def update_profile():
        """Update user profile"""
        try:
            data = request.get_json()
            user = request.current_user

            # Update allowed fields
            updateable_fields = ['name', 'phone', 'email']

            for field in updateable_fields:
                if field in data:
                    setattr(user, field, data[field])

            user.updated_at = datetime.utcnow()
            if db:
                db.session.commit()

            return jsonify({
                'user': user.to_dict(),
                'message': 'Profile updated successfully'
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @user_auth_bp.route('/change-password', methods=['POST'])
    @require_user(auth_system)
    def change_password():
        """Change user password"""
        try:
            data = request.get_json()
            current_password = data.get('current_password')
            new_password = data.get('new_password')

            if not current_password or not new_password:
                return jsonify({'error': 'Current and new password are required'}), 400

            user = request.current_user

            # Verify current password
            if not user.check_password(current_password):
                return jsonify({'error': 'Current password is incorrect'}), 400

            # Validate new password
            if len(new_password) < 8:
                return jsonify({'error': 'New password must be at least 8 characters'}), 400

            # Update password
            user.set_password(new_password)
            user.updated_at = datetime.utcnow()
            if db:
                db.session.commit()

            return jsonify({'message': 'Password changed successfully'})

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @user_auth_bp.route('/refresh', methods=['POST'])
    @require_user(auth_system)
    def refresh_token():
        """Refresh user authentication token"""
        try:
            user = request.current_user
            tenant = request.user_data.get('tenant')

            # Generate new token
            new_token = auth_system.refresh_token(user, tenant)

            return jsonify({
                'token': new_token,
                'message': 'Token refreshed successfully'
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @user_auth_bp.route('/verify', methods=['GET'])
    @optional_user(auth_system)
    def verify_token():
        """Verify user token and return user info if valid"""
        try:
            if hasattr(request, 'current_user') and request.current_user:
                return jsonify({
                    'valid': True,
                    'user': request.current_user.to_dict()
                })
            else:
                return jsonify({'valid': False})

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return user_auth_bp
