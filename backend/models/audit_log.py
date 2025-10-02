"""
Admin Audit Log Model

Database model for tracking admin actions for security and compliance.
"""

from datetime import datetime
from .user import db


class AdminAuditLog(db.Model):
    """Admin audit log for tracking admin actions"""

    __tablename__ = 'admin_audit_logs'

    id = db.Column(db.Integer, primary_key=True)

    # Admin who performed the action
    admin_user_id = db.Column(db.Integer, db.ForeignKey('admin_users.id'), nullable=False, index=True)

    # Action details
    action = db.Column(db.String(100), nullable=False, index=True)
    # Examples: login, logout, login_failed, create_user, update_user, delete_user, etc.

    # Resource affected (optional)
    resource_type = db.Column(db.String(50), index=True)  # user, business, review, etc.
    resource_id = db.Column(db.Integer, index=True)

    # Additional details (JSON string)
    details = db.Column(db.Text)

    # Request context
    ip_address = db.Column(db.String(45))  # IPv4 or IPv6
    user_agent = db.Column(db.String(255))

    # Timestamp
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Relationship
    admin_user = db.relationship('AdminUser', backref='audit_logs', lazy=True)

    def to_dict(self) -> dict:
        """
        Convert audit log to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            'id': self.id,
            'admin_user_id': self.admin_user_id,
            'admin_username': self.admin_user.username if self.admin_user else None,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    @staticmethod
    def log_action(admin_user_id: int, action: str, resource_type=None, resource_id=None,
                   details=None, ip_address=None, user_agent=None) -> 'AdminAuditLog':
        """
        Helper method to create and save an audit log entry.

        Args:
            admin_user_id: Admin user ID
            action: Action performed
            resource_type: Type of resource (optional)
            resource_id: Resource ID (optional)
            details: Additional details as JSON string (optional)
            ip_address: IP address (optional)
            user_agent: User agent (optional)

        Returns:
            Created audit log instance
        """
        audit_log = AdminAuditLog(
            admin_user_id=admin_user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.session.add(audit_log)
        db.session.commit()
        return audit_log

    def __repr__(self) -> str:
        return f'<AdminAuditLog {self.action} by admin:{self.admin_user_id}>'
