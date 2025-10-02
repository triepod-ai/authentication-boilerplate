"""
Admin Authentication API Routes

API endpoints for admin authentication and management.
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
import json


def create_admin_auth_routes(auth_system, db=None, audit_log_model=None):
    """
    Create admin authentication routes blueprint.

    Args:
        auth_system: AdminAuthSystem instance
        db: SQLAlchemy database instance (optional)
        audit_log_model: AdminAuditLog model class (optional)

    Returns:
        Flask Blueprint
    """
    admin_auth_bp = Blueprint('admin_auth', __name__, url_prefix='/api/admin')

    # Import decorators
    from auth import require_admin, require_super_admin

    def log_action(action, resource_type=None, resource_id=None, details=None):
        """Helper to log admin actions"""
        if hasattr(request, 'admin_user') and audit_log_model and db:
            audit_log = audit_log_model(
                admin_user_id=request.admin_user.id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                details=json.dumps(details) if details else None,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')
            )
            db.session.add(audit_log)
            db.session.commit()

    @admin_auth_bp.route('/login', methods=['POST'])
    def login():
        """Admin login endpoint"""
        try:
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')

            if not username or not password:
                return jsonify({'error': 'Username and password are required'}), 400

            # Authenticate admin
            auth_result = auth_system.authenticate_admin(username, password)

            if not auth_result:
                return jsonify({'error': 'Invalid credentials'}), 401

            return jsonify({
                'token': auth_result['token'],
                'user': auth_result['admin'].to_dict(include_sensitive=True),
                'expires_at': auth_result['expires_at'].isoformat(),
                'message': 'Login successful'
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @admin_auth_bp.route('/logout', methods=['POST'])
    @require_admin(auth_system)
    def logout():
        """Admin logout endpoint"""
        try:
            log_action('logout')

            auth_system.logout_admin(request.admin_user)

            return jsonify({'message': 'Logged out successfully'})

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @admin_auth_bp.route('/profile', methods=['GET'])
    @require_admin(auth_system)
    def get_profile():
        """Get admin user profile"""
        try:
            admin = request.admin_user

            return jsonify({
                'user': admin.to_dict(include_sensitive=True),
                'session_valid': admin.is_session_valid()
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @admin_auth_bp.route('/change-password', methods=['POST'])
    @require_admin(auth_system)
    def change_password():
        """Change admin password"""
        try:
            data = request.get_json()
            current_password = data.get('current_password')
            new_password = data.get('new_password')

            if not current_password or not new_password:
                return jsonify({'error': 'Current and new password are required'}), 400

            admin = request.admin_user

            if not admin.check_password(current_password):
                return jsonify({'error': 'Current password is incorrect'}), 400

            if len(new_password) < 8:
                return jsonify({'error': 'New password must be at least 8 characters'}), 400

            # Update password
            admin.set_password(new_password)
            admin.updated_at = datetime.utcnow()
            if db:
                db.session.commit()

            log_action('password_changed')

            return jsonify({'message': 'Password changed successfully'})

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @admin_auth_bp.route('/users', methods=['GET'])
    @require_super_admin(auth_system)
    def get_admin_users():
        """Get list of admin users (super admin only)"""
        try:
            if not db or not auth_system.admin_model:
                return jsonify({'error': 'Admin model not configured'}), 500

            admins = db.session.query(auth_system.admin_model).all()

            return jsonify({
                'users': [admin.to_dict() for admin in admins]
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @admin_auth_bp.route('/users', methods=['POST'])
    @require_super_admin(auth_system)
    def create_admin_user():
        """Create new admin user (super admin only)"""
        try:
            data = request.get_json()
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
            role = data.get('role', 'admin')

            if not username or not email or not password:
                return jsonify({'error': 'Username, email, and password are required'}), 400

            if not db or not auth_system.admin_model:
                return jsonify({'error': 'Admin model not configured'}), 500

            # Check if user already exists
            existing = db.session.query(auth_system.admin_model).filter_by(username=username).first()
            if existing:
                return jsonify({'error': 'Username already exists'}), 400

            existing = db.session.query(auth_system.admin_model).filter_by(email=email).first()
            if existing:
                return jsonify({'error': 'Email already exists'}), 400

            # Create new admin user
            new_admin = auth_system.admin_model(
                username=username,
                email=email,
                role=role
            )
            new_admin.set_password(password)

            db.session.add(new_admin)
            db.session.commit()

            log_action('create_admin_user', 'admin_user', new_admin.id, {
                'username': username,
                'email': email,
                'role': role
            })

            return jsonify({
                'message': 'Admin user created successfully',
                'user': new_admin.to_dict()
            }), 201

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @admin_auth_bp.route('/users/<int:user_id>', methods=['PUT'])
    @require_super_admin(auth_system)
    def update_admin_user(user_id):
        """Update admin user (super admin only)"""
        try:
            if not db or not auth_system.admin_model:
                return jsonify({'error': 'Admin model not configured'}), 500

            admin = db.session.get(auth_system.admin_model, user_id)
            if not admin:
                return jsonify({'error': 'Admin user not found'}), 404

            data = request.get_json()

            # Update allowed fields
            if 'email' in data:
                admin.email = data['email']
            if 'role' in data:
                admin.role = data['role']
            if 'is_active' in data:
                admin.is_active = data['is_active']

            admin.updated_at = datetime.utcnow()
            db.session.commit()

            log_action('update_admin_user', 'admin_user', user_id, data)

            return jsonify({
                'message': 'Admin user updated successfully',
                'user': admin.to_dict()
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @admin_auth_bp.route('/audit-logs', methods=['GET'])
    @require_admin(auth_system)
    def get_audit_logs():
        """Get admin audit logs"""
        try:
            if not audit_log_model or not db:
                return jsonify({'error': 'Audit logging not configured'}), 500

            page = request.args.get('page', 1, type=int)
            per_page = request.args.get('per_page', 50, type=int)
            action_filter = request.args.get('action')
            user_filter = request.args.get('user_id', type=int)

            query = db.session.query(audit_log_model)

            if action_filter:
                query = query.filter(audit_log_model.action.contains(action_filter))

            if user_filter:
                query = query.filter(audit_log_model.admin_user_id == user_filter)

            # Order by most recent first
            query = query.order_by(audit_log_model.created_at.desc())

            # Paginate
            pagination = query.paginate(
                page=page,
                per_page=per_page,
                error_out=False
            )

            logs = [log.to_dict() for log in pagination.items]

            return jsonify({
                'logs': logs,
                'pagination': {
                    'page': page,
                    'pages': pagination.pages,
                    'per_page': per_page,
                    'total': pagination.total,
                    'has_next': pagination.has_next,
                    'has_prev': pagination.has_prev
                }
            })

        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return admin_auth_bp
