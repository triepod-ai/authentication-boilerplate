"""
Example Flask Application Setup

This example shows how to integrate the authentication boilerplate
into a Flask application.
"""

from flask import Flask
from flask_cors import CORS

# Import authentication components
from auth import UserAuthSystem, AdminAuthSystem
from models import db, User, AdminUser, AdminAuditLog
from routes import create_user_auth_routes, create_admin_auth_routes


def create_app(config=None):
    """
    Create and configure Flask application.

    Args:
        config: Configuration dictionary (optional)

    Returns:
        Configured Flask app
    """
    app = Flask(__name__)

    # Configuration
    app.config['SECRET_KEY'] = config.get('SECRET_KEY', 'dev-secret-change-in-production')
    app.config['SQLALCHEMY_DATABASE_URI'] = config.get('DATABASE_URI', 'sqlite:///auth.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Authentication settings
    app.config['JWT_SECRET'] = config.get('JWT_SECRET', 'jwt-secret-change-in-production')
    app.config['TOKEN_EXPIRY_SECONDS'] = config.get('TOKEN_EXPIRY_SECONDS', 7 * 24 * 60 * 60)  # 7 days
    app.config['ADMIN_SESSION_EXPIRY_SECONDS'] = config.get('ADMIN_SESSION_EXPIRY_SECONDS', 24 * 60 * 60)  # 24 hours

    # Multi-tenant (optional)
    app.config['MULTI_TENANT_ENABLED'] = config.get('MULTI_TENANT_ENABLED', False)

    # Enable CORS
    CORS(app)

    # Initialize database
    db.init_app(app)

    # Initialize authentication systems
    user_auth = UserAuthSystem(app, db, User)
    admin_auth = AdminAuthSystem(app, db, AdminUser, AdminAuditLog)

    # Register blueprints
    user_auth_routes = create_user_auth_routes(user_auth, db)
    admin_auth_routes = create_admin_auth_routes(admin_auth, db, AdminAuditLog)

    app.register_blueprint(user_auth_routes)
    app.register_blueprint(admin_auth_routes)

    # Create tables
    with app.app_context():
        db.create_all()

        # Create default super admin if not exists (optional)
        if not db.session.query(AdminUser).filter_by(username='admin').first():
            default_admin = AdminUser(
                username='admin',
                email='admin@example.com',
                role='super_admin',
                is_active=True
            )
            default_admin.set_password('admin123')  # Change this!
            db.session.add(default_admin)
            db.session.commit()
            print('Created default super admin: admin / admin123')

    # Health check endpoint
    @app.route('/health')
    def health():
        return {'status': 'ok', 'message': 'Authentication service is running'}

    # Root endpoint with API documentation
    @app.route('/')
    def index():
        return {
            'message': 'Authentication Boilerplate API',
            'version': '1.0.0',
            'endpoints': {
                'health': {
                    'method': 'GET',
                    'path': '/health',
                    'description': 'Health check endpoint'
                },
                'user_auth': {
                    'register': 'POST /api/auth/register',
                    'login': 'POST /api/auth/login',
                    'logout': 'POST /api/auth/logout',
                    'profile': 'GET /api/auth/profile',
                    'update_profile': 'PUT /api/auth/profile',
                    'change_password': 'POST /api/auth/change-password',
                    'refresh_token': 'POST /api/auth/refresh',
                    'verify_token': 'GET /api/auth/verify'
                },
                'admin_auth': {
                    'login': 'POST /api/admin/login',
                    'logout': 'POST /api/admin/logout',
                    'profile': 'GET /api/admin/profile',
                    'change_password': 'POST /api/admin/change-password',
                    'list_users': 'GET /api/admin/users',
                    'create_user': 'POST /api/admin/users',
                    'update_user': 'PUT /api/admin/users/<id>',
                    'audit_logs': 'GET /api/admin/audit-logs'
                }
            },
            'documentation': 'See README.md for full documentation',
            'test_examples': {
                'register': {
                    'method': 'POST',
                    'url': 'http://localhost:5000/api/auth/register',
                    'body': {
                        'email': 'user@example.com',
                        'password': 'password123',
                        'name': 'John Doe'
                    }
                },
                'login': {
                    'method': 'POST',
                    'url': 'http://localhost:5000/api/auth/login',
                    'body': {
                        'email': 'user@example.com',
                        'password': 'password123'
                    }
                },
                'admin_login': {
                    'method': 'POST',
                    'url': 'http://localhost:5000/api/admin/login',
                    'body': {
                        'username': 'admin',
                        'password': 'admin123'
                    }
                }
            }
        }

    return app


if __name__ == '__main__':
    # Example configuration
    config = {
        'SECRET_KEY': 'dev-secret-key',
        'DATABASE_URI': 'sqlite:///auth_example.db',
        'JWT_SECRET': 'jwt-secret-key',
    }

    app = create_app(config)
    app.run(debug=True, port=5000)
