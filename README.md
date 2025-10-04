# Authentication Boilerplate

## ⚠️ Important Notice

**This repository is for demonstration purposes only.**

This authentication boilerplate has been extracted from private production repositories to demonstrate architectural patterns and best practices. All sensitive implementation details, proprietary business logic, and confidential information have been removed or sanitized.

**Purpose:**
- Demonstrate authentication system architecture patterns used in production environments
- Provide educational reference for secure authentication implementation
- Showcase integration patterns between Flask backend and React frontend
- Share proven patterns while maintaining privacy of production systems

**What this is NOT:**
- Not a copy of any production system
- Not intended to expose proprietary or confidential code
- Not a security risk or leak of private repositories

This repository serves as a pattern reference extracted and adapted from real-world production systems, modified specifically for public demonstration and educational purposes.

---

A comprehensive, production-ready authentication system for Flask + React applications.

## Features

### Backend (Flask)
- **JWT-based user authentication**
  - Secure token generation and verification
  - Password hashing (SHA-256 with salt + Werkzeug)
  - Token refresh mechanism
  - Failed login tracking

- **Admin authentication with RBAC**
  - Session-based authentication
  - Role-based access control (super_admin, admin, moderator)
  - Admin audit logging
  - Permission-based decorators

- **Multi-tenant support** (optional)
  - Tenant-aware authentication
  - Isolated user spaces

- **Security features**
  - Password strength validation
  - Email format validation
  - Session expiry management
  - Audit trail for admin actions

### Frontend (React)
- **Reusable authentication components**
  - LoginForm
  - RegisterForm
  - ProtectedRoute

- **Global authentication state**
  - AuthContext with React Context API
  - useAuth hook
  - LocalStorage token persistence

- **Features**
  - Auto token verification
  - Token refresh
  - Profile management
  - Password change

## Project Structure

```
authentication-boilerplate/
├── backend/
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── user_auth.py          # User authentication system
│   │   └── admin_auth.py         # Admin authentication system
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py               # User model
│   │   ├── admin_user.py         # Admin user model
│   │   └── audit_log.py          # Admin audit log model
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── user_auth_routes.py   # User API routes
│   │   └── admin_auth_routes.py  # Admin API routes
│   ├── utils/
│   │   ├── __init__.py
│   │   └── validators.py         # Validation utilities
│   ├── app_example.py            # Example Flask app
│   └── requirements.txt
├── frontend/
│   ├── components/
│   │   └── auth/
│   │       ├── LoginForm.jsx
│   │       ├── RegisterForm.jsx
│   │       └── ProtectedRoute.jsx
│   ├── context/
│   │   └── AuthContext.jsx       # Global auth state
│   ├── hooks/
│   │   └── useAuth.js
│   └── package.json
├── docs/
├── .env.example
└── README.md
```

## Development Approach

This repository represents a curated boilerplate extracted and sanitized
from private production implementations. The single/minimal commit history
reflects:

- **Extraction & Sanitization**: Production code adapted for public use
- **Security-First**: All proprietary business logic and credentials removed
- **Pattern Focus**: Emphasis on reusable patterns vs. specific features

For iterative development history, see active projects:
- [mcp-server-qdrant-enhanced](https://github.com/triepod-ai/mcp-server-qdrant-enhanced) - 88+ commits
- [inspector-assessment](https://github.com/triepod-ai/inspector) - 1,612+ commits
- [chroma-mcp](https://github.com/triepod-ai/chroma-mcp) - 63+ commits

## Quick Start

### Automated Setup (Recommended)

Run the setup script to automatically configure everything:

```bash
./setup.sh
```

This will:
- Install `uv` if not present
- Create virtual environment
- Install all backend dependencies
- Install all frontend dependencies
- Create `.env` file from template

### Manual Backend Setup

1. **Create virtual environment (recommended - uses uv for WSL compatibility):**
   ```bash
   cd backend
   uv venv
   source .venv/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   uv pip install -r requirements.txt
   ```

   **Optional - for PostgreSQL or MySQL:**
   ```bash
   # For PostgreSQL
   uv pip install -r requirements-postgres.txt

   # For MySQL
   uv pip install -r requirements-mysql.txt
   ```

3. **Configure environment:**
   ```bash
   cp ../.env.example ../.env
   # Edit .env with your configuration
   ```

4. **Run the application:**
   ```bash
   python3 app_example.py
   ```

   The backend will start on `http://localhost:5000`

4. **Default admin credentials:**
   - Username: `admin`
   - Password: `admin123` (change this immediately!)

### Frontend Setup

1. **Install dependencies:**
   ```bash
   cd frontend
   npm install
   ```

2. **Run development server:**
   ```bash
   npm run dev
   ```

   The frontend will start on `http://localhost:5173`

## Usage

### Backend Integration

#### Basic Setup

```python
from flask import Flask
from auth import UserAuthSystem, AdminAuthSystem
from models import db, User, AdminUser, AdminAuditLog
from routes import create_user_auth_routes, create_admin_auth_routes

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.config['JWT_SECRET'] = 'your-secret-key'

# Initialize database
db.init_app(app)

# Initialize authentication systems
user_auth = UserAuthSystem(app, db, User)
admin_auth = AdminAuthSystem(app, db, AdminUser, AdminAuditLog)

# Register routes
app.register_blueprint(create_user_auth_routes(user_auth, db))
app.register_blueprint(create_admin_auth_routes(admin_auth, db, AdminAuditLog))

# Create tables
with app.app_context():
    db.create_all()
```

#### Using Decorators

```python
from auth import require_user, require_admin

@app.route('/api/protected')
@require_user(user_auth)
def protected_endpoint():
    user = request.current_user
    return {'message': f'Hello {user.name}!'}

@app.route('/api/admin/dashboard')
@require_admin(admin_auth)
def admin_dashboard():
    admin = request.admin_user
    return {'message': f'Admin: {admin.username}'}
```

#### Multi-tenant Support

```python
app.config['MULTI_TENANT_ENABLED'] = True

# In your routes
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    tenant = request.headers.get('X-Tenant-ID')  # Get tenant from header
    result = user_auth.authenticate_user(
        data['email'],
        data['password'],
        tenant
    )
```

### Frontend Integration

#### Setup AuthProvider

```jsx
import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import App from './App';

function Root() {
  return (
    <BrowserRouter>
      <AuthProvider apiUrl="http://localhost:5000/api/auth">
        <App />
      </AuthProvider>
    </BrowserRouter>
  );
}

export default Root;
```

#### Using Authentication Components

```jsx
import { LoginForm, RegisterForm } from './components/auth';
import { useAuth } from './hooks/useAuth';

function LoginPage() {
  const { login } = useAuth();

  const handleLogin = async (email, password) => {
    try {
      await login(email, password);
      // Redirect or update UI
    } catch (error) {
      console.error('Login failed:', error);
    }
  };

  return <LoginForm onLogin={handleLogin} />;
}
```

#### Protected Routes

```jsx
import { Routes, Route } from 'react-router-dom';
import { ProtectedRoute } from './components/auth';
import { useAuth } from './hooks/useAuth';

function App() {
  const { isAuthenticated } = useAuth();

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute isAuthenticated={isAuthenticated}>
            <Dashboard />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}
```

#### Using useAuth Hook

```jsx
import { useAuth } from './hooks/useAuth';

function UserProfile() {
  const { user, logout, updateProfile } = useAuth();

  const handleUpdate = async (updates) => {
    try {
      await updateProfile(updates);
      alert('Profile updated!');
    } catch (error) {
      console.error('Update failed:', error);
    }
  };

  return (
    <div>
      <h1>Welcome, {user?.name}!</h1>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

## API Endpoints

### User Authentication

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/auth/register` | Register new user | No |
| POST | `/api/auth/login` | User login | No |
| POST | `/api/auth/logout` | User logout | Yes |
| GET | `/api/auth/profile` | Get user profile | Yes |
| PUT | `/api/auth/profile` | Update user profile | Yes |
| POST | `/api/auth/change-password` | Change password | Yes |
| POST | `/api/auth/refresh` | Refresh token | Yes |
| GET | `/api/auth/verify` | Verify token | Optional |

### Admin Authentication

| Method | Endpoint | Description | Auth Required | Role Required |
|--------|----------|-------------|---------------|---------------|
| POST | `/api/admin/login` | Admin login | No | - |
| POST | `/api/admin/logout` | Admin logout | Yes | - |
| GET | `/api/admin/profile` | Get admin profile | Yes | - |
| POST | `/api/admin/change-password` | Change password | Yes | - |
| GET | `/api/admin/users` | List admin users | Yes | super_admin |
| POST | `/api/admin/users` | Create admin user | Yes | super_admin |
| PUT | `/api/admin/users/:id` | Update admin user | Yes | super_admin |
| GET | `/api/admin/audit-logs` | Get audit logs | Yes | - |

## Configuration

### Database Setup

**SQLite (Default - No setup required)**

The boilerplate uses SQLite by default, which requires no additional setup. Perfect for development and small deployments.

**PostgreSQL (Optional)**

1. Install PostgreSQL driver:
   ```bash
   cd backend
   source .venv/bin/activate
   uv pip install -r requirements-postgres.txt
   ```

2. Update `.env`:
   ```
   DATABASE_URI=postgresql://user:password@localhost:5432/auth_db
   ```

**MySQL (Optional)**

1. Install MySQL driver:
   ```bash
   cd backend
   source .venv/bin/activate
   uv pip install -r requirements-mysql.txt
   ```

2. Update `.env`:
   ```
   DATABASE_URI=mysql://user:password@localhost:3306/auth_db
   ```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key | (required) |
| `DATABASE_URI` | Database connection string | `sqlite:///auth.db` |
| `JWT_SECRET` | JWT signing secret | (required) |
| `TOKEN_EXPIRY_SECONDS` | User token expiry | `604800` (7 days) |
| `ADMIN_SESSION_EXPIRY_SECONDS` | Admin session expiry | `86400` (24 hours) |
| `MULTI_TENANT_ENABLED` | Enable multi-tenant | `false` |

## Database Models

### User

- `id`: Integer, primary key
- `email`: String, unique
- `name`: String
- `password_hash`: String
- `tenant`: String (optional, for multi-tenant)
- `is_active`: Boolean
- `email_verified`: Boolean
- `last_login`: DateTime
- `login_count`: Integer
- `failed_login_attempts`: Integer
- `created_at`: DateTime
- `updated_at`: DateTime

### AdminUser

- `id`: Integer, primary key
- `username`: String, unique
- `email`: String, unique
- `password_hash`: String
- `role`: String (super_admin, admin, moderator)
- `is_active`: Boolean
- `session_token`: String
- `session_expires`: DateTime
- `last_login`: DateTime
- `created_at`: DateTime
- `updated_at`: DateTime

### AdminAuditLog

- `id`: Integer, primary key
- `admin_user_id`: Integer, foreign key
- `action`: String
- `resource_type`: String
- `resource_id`: Integer
- `details`: Text (JSON)
- `ip_address`: String
- `user_agent`: String
- `created_at`: DateTime

## Security Best Practices

1. **Change default credentials** immediately in production
2. **Use strong secrets** for JWT_SECRET and SECRET_KEY
3. **Use HTTPS** in production
4. **Set secure cookie flags** if using cookies
5. **Implement rate limiting** for login endpoints
6. **Monitor audit logs** regularly
7. **Keep dependencies updated**
8. **Use environment variables** for sensitive config
9. **Implement password complexity rules** as needed
10. **Enable CORS carefully** in production

## Customization

### Adding Custom User Fields

1. Extend the User model in `backend/models/user.py`
2. Update registration endpoint to accept new fields
3. Update frontend forms as needed

### Custom Password Hashing

The system supports both Werkzeug and SHA-256 hashing:

```python
# In User model
user.set_password('password', method='werkzeug')  # or 'sha256'
```

### Adding Permissions

1. Add permission fields to AdminUser model
2. Create custom decorators in `backend/auth/admin_auth.py`
3. Apply decorators to protected routes

## Testing

### Backend Testing

```bash
cd backend
source .venv/bin/activate  # Activate virtual environment
uv pip install pytest      # Install pytest if not already installed
python3 -m pytest tests/
```

### Frontend Testing

```bash
cd frontend
npm run test
```

## License

MIT License - feel free to use this boilerplate in your projects.

## Support

For issues or questions, please check the documentation or create an issue in the repository.
