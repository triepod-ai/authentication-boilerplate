# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A production-ready authentication boilerplate for Flask (backend) + React (frontend) applications with JWT-based user authentication and session-based admin authentication with RBAC.

## Development Setup

### Backend Setup (Flask)

**Virtual Environment (WSL/Linux):**
```bash
cd backend
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

**Run Backend:**
```bash
cd backend
source .venv/bin/activate
python3 app_example.py
# Runs on http://localhost:5000
```

**Default admin credentials:** `admin` / `admin123`

### Frontend Setup (React + Vite)

**Install & Run:**
```bash
cd frontend
npm install
npm run dev
# Runs on http://localhost:5173
```

**Build for Production:**
```bash
cd frontend
npm run build
```

### Automated Setup

```bash
./setup.sh
# Installs uv, sets up venv, installs all dependencies, creates .env
```

## Testing

**Backend API Testing:**
```bash
cd backend
source .venv/bin/activate
python3 test_api.py
# Comprehensive API test suite that tests all endpoints
```

**Manual API Testing:**
```bash
# User Registration
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "password123", "name": "Test User"}'

# User Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "password123"}'

# Admin Login
curl -X POST http://localhost:5000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

## Architecture

### Backend Structure (Flask)

**Two-tier Authentication System:**

1. **User Authentication** (`auth/user_auth.py`)
   - JWT-based token authentication
   - Token expiry: 7 days (configurable)
   - Password hashing: SHA-256 + salt (also supports Werkzeug)
   - Failed login tracking
   - Optional multi-tenant support

2. **Admin Authentication** (`auth/admin_auth.py`)
   - Session-based authentication with token
   - Role-based access control: super_admin, admin, moderator
   - Session expiry: 24 hours (configurable)
   - Audit logging support

**Models:** (`models/`)
- `User` - User accounts with JWT authentication
- `AdminUser` - Admin accounts with session tokens
- `AdminAuditLog` - Admin action audit trail

**Routes:** (`routes/`)
- `user_auth_routes.py` - User API endpoints (`/api/auth/*`)
- `admin_auth_routes.py` - Admin API endpoints (`/api/admin/*`)

**Authentication Decorators:**
- `@require_user(user_auth)` - Protects user endpoints
- `@require_admin(admin_auth)` - Protects admin endpoints
- Sets `request.current_user` or `request.admin_user`

### Frontend Structure (React)

**Authentication System:**
- `context/AuthContext.jsx` - Global auth state with Context API
- `hooks/useAuth.js` - Custom hook for auth operations
- Token storage: localStorage
- Auto token verification on mount
- Token refresh support

**Auth Components:** (`components/auth/`)
- `LoginForm.jsx` - Reusable login form
- `RegisterForm.jsx` - Reusable registration form
- `ProtectedRoute.jsx` - Route guard component

**Vite Configuration:**
- Dev server on port 5173
- API proxy: `/api` → `http://localhost:5000`

### Database Support

**Default:** SQLite (no setup required)

**Optional PostgreSQL:**
```bash
cd backend
source .venv/bin/activate
uv pip install -r requirements-postgres.txt
# Update DATABASE_URI in .env
```

**Optional MySQL:**
```bash
cd backend
source .venv/bin/activate
uv pip install -r requirements-mysql.txt
# Update DATABASE_URI in .env
```

## Configuration

**Environment Variables (.env):**
- `SECRET_KEY` - Flask secret key
- `DATABASE_URI` - Database connection (default: SQLite)
- `JWT_SECRET` - JWT signing secret
- `TOKEN_EXPIRY_SECONDS` - User token expiry (default: 604800 = 7 days)
- `ADMIN_SESSION_EXPIRY_SECONDS` - Admin session expiry (default: 86400 = 24 hours)
- `MULTI_TENANT_ENABLED` - Enable multi-tenant mode (default: false)
- `CORS_ORIGINS` - Allowed CORS origins

## API Endpoints

### User Auth (`/api/auth/`)
- `POST /register` - Register new user
- `POST /login` - User login (returns JWT)
- `POST /logout` - User logout
- `GET /profile` - Get user profile (requires JWT)
- `PUT /profile` - Update user profile (requires JWT)
- `POST /change-password` - Change password (requires JWT)
- `POST /refresh` - Refresh JWT token
- `GET /verify` - Verify JWT token

### Admin Auth (`/api/admin/`)
- `POST /login` - Admin login (returns session token)
- `POST /logout` - Admin logout
- `GET /profile` - Get admin profile (requires session)
- `POST /change-password` - Change admin password
- `GET /users` - List admin users (super_admin only)
- `POST /users` - Create admin user (super_admin only)
- `PUT /users/<id>` - Update admin user (super_admin only)
- `GET /audit-logs` - Get audit logs

## Integration Patterns

**Backend - Protecting Routes:**
```python
from auth import require_user, require_admin

@app.route('/api/protected')
@require_user(user_auth)
def protected():
    user = request.current_user
    return {'message': f'Hello {user.name}'}

@app.route('/api/admin/dashboard')
@require_admin(admin_auth)
def admin_dashboard():
    admin = request.admin_user
    return {'role': admin.role}
```

**Frontend - Using Auth:**
```jsx
import { useAuth } from './hooks/useAuth';

function Component() {
  const { user, isAuthenticated, login, logout } = useAuth();
  // Authentication logic
}
```

**Frontend - Protected Routes:**
```jsx
<Route path="/dashboard" element={
  <ProtectedRoute isAuthenticated={isAuthenticated}>
    <Dashboard />
  </ProtectedRoute>
} />
```

## Multi-tenant Support

Enable in configuration:
```python
app.config['MULTI_TENANT_ENABLED'] = True
```

Pass tenant in request headers:
```
X-Tenant-ID: tenant_name
```

## Security Features

- Password hashing (SHA-256 + salt, Werkzeug)
- JWT token expiry and refresh
- Session expiry management
- Failed login tracking
- Email/password validation
- Admin audit logging
- RBAC for admin users
