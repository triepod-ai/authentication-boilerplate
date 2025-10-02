# Usage Examples

Practical examples for common authentication scenarios.

## Backend Examples

### Example 1: Basic User Authentication

```python
from flask import Flask, request, jsonify
from auth import UserAuthSystem, require_user
from models import db, User
from routes import create_user_auth_routes

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///myapp.db'
app.config['JWT_SECRET'] = 'my-secret-key'

db.init_app(app)
user_auth = UserAuthSystem(app, db, User)

# Register routes
app.register_blueprint(create_user_auth_routes(user_auth, db))

# Protected endpoint
@app.route('/api/user/dashboard')
@require_user(user_auth)
def dashboard():
    user = request.current_user
    return jsonify({
        'message': f'Welcome {user.name}!',
        'email': user.email,
        'last_login': user.last_login.isoformat() if user.last_login else None
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)
```

### Example 2: Multi-Tenant Application

```python
from flask import Flask, request, jsonify
from auth import UserAuthSystem
from models import db, User

app = Flask(__name__)
app.config['MULTI_TENANT_ENABLED'] = True

user_auth = UserAuthSystem(app, db, User)

@app.route('/api/auth/login', methods=['POST'])
def custom_login():
    data = request.get_json()
    # Get tenant from subdomain or header
    tenant = request.headers.get('X-Tenant-ID')

    result = user_auth.authenticate_user(
        data['email'],
        data['password'],
        tenant
    )

    if not result:
        return jsonify({'error': 'Invalid credentials'}), 401

    return jsonify({
        'token': result['token'],
        'user': result['user'].to_dict(),
        'tenant': tenant
    })
```

### Example 3: Custom Admin Permissions

```python
from flask import Flask, jsonify
from auth import AdminAuthSystem

app = Flask(__name__)
admin_auth = AdminAuthSystem(app, db, AdminUser)

def require_permission(permission):
    """Custom decorator for permission-based access"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            admin = admin_auth.get_current_admin()
            if not admin:
                return jsonify({'error': 'Authentication required'}), 401

            # Check if admin has permission (extend AdminUser model)
            if not hasattr(admin, 'permissions') or permission not in admin.permissions:
                return jsonify({'error': f'Permission "{permission}" required'}), 403

            request.admin_user = admin
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/admin/sensitive-action')
@require_permission('delete_users')
def sensitive_action():
    return jsonify({'message': 'Action performed'})
```

### Example 4: Custom Password Validation

```python
from utils import validate_password

def validate_strong_password(password):
    """Enhanced password validation"""
    # Check length
    is_valid, error = validate_password(password, min_length=10)
    if not is_valid:
        return False, error

    # Check complexity
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in '!@#$%^&*()' for c in password)

    if not all([has_upper, has_lower, has_digit, has_special]):
        return False, 'Password must contain uppercase, lowercase, digit, and special character'

    return True, None

# Use in registration endpoint
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()

    is_valid, error = validate_strong_password(data['password'])
    if not is_valid:
        return jsonify({'error': error}), 400

    # Continue with registration...
```

## Frontend Examples

### Example 1: Login Page

```jsx
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { LoginForm } from './components/auth';
import { useAuth } from './hooks/useAuth';

function LoginPage() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [error, setError] = useState('');

  const handleLogin = async (email, password) => {
    try {
      await login(email, password);
      navigate('/dashboard');
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="login-page">
      <h1>Login to Your Account</h1>
      {error && <div className="error">{error}</div>}
      <LoginForm onLogin={handleLogin} />
      <p>
        Don't have an account? <a href="/register">Register</a>
      </p>
    </div>
  );
}

export default LoginPage;
```

### Example 2: Registration Page

```jsx
import React from 'react';
import { useNavigate } from 'react-router-dom';
import { RegisterForm } from './components/auth';
import { useAuth } from './hooks/useAuth';

function RegisterPage() {
  const navigate = useNavigate();
  const { register } = useAuth();

  const handleSuccess = () => {
    navigate('/dashboard');
  };

  return (
    <div className="register-page">
      <h1>Create Account</h1>
      <RegisterForm
        onRegister={register}
        onSuccess={handleSuccess}
      />
    </div>
  );
}

export default RegisterPage;
```

### Example 3: User Dashboard with Auth Check

```jsx
import React, { useEffect, useState } from 'react';
import { useAuth } from './hooks/useAuth';
import { Navigate } from 'react-router-dom';

function Dashboard() {
  const { user, isAuthenticated, loading, logout } = useAuth();
  const [userData, setUserData] = useState(null);

  useEffect(() => {
    if (isAuthenticated && user) {
      // Fetch additional user data
      fetchUserData();
    }
  }, [isAuthenticated, user]);

  const fetchUserData = async () => {
    // Fetch user-specific data from API
    // ...
  };

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div className="dashboard">
      <header>
        <h1>Welcome, {user.name}!</h1>
        <button onClick={logout}>Logout</button>
      </header>
      <main>
        <div className="user-info">
          <p>Email: {user.email}</p>
          <p>Member since: {new Date(user.created_at).toLocaleDateString()}</p>
        </div>
      </main>
    </div>
  );
}

export default Dashboard;
```

### Example 4: Protected Routes with Role-Based Access

```jsx
import { Routes, Route } from 'react-router-dom';
import { ProtectedRoute } from './components/auth';
import { useAuth } from './hooks/useAuth';

function App() {
  const { isAuthenticated, user } = useAuth();

  return (
    <Routes>
      <Route path="/" element={<HomePage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />

      {/* Regular user routes */}
      <Route
        path="/dashboard"
        element={
          <ProtectedRoute isAuthenticated={isAuthenticated}>
            <Dashboard />
          </ProtectedRoute>
        }
      />

      {/* Admin-only routes */}
      <Route
        path="/admin"
        element={
          <ProtectedRoute
            isAuthenticated={isAuthenticated}
            requiredRole="admin"
            userRole={user?.role}
          >
            <AdminPanel />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}
```

### Example 5: Profile Update Form

```jsx
import React, { useState } from 'react';
import { useAuth } from './hooks/useAuth';

function ProfilePage() {
  const { user, updateProfile } = useAuth();
  const [formData, setFormData] = useState({
    name: user?.name || '',
    email: user?.email || ''
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage('');

    try {
      await updateProfile(formData);
      setMessage('Profile updated successfully!');
    } catch (err) {
      setMessage(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="profile-page">
      <h1>Edit Profile</h1>
      {message && <div className="message">{message}</div>}

      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="name">Name</label>
          <input
            id="name"
            value={formData.name}
            onChange={(e) => setFormData({...formData, name: e.target.value})}
            disabled={loading}
          />
        </div>

        <div>
          <label htmlFor="email">Email</label>
          <input
            id="email"
            type="email"
            value={formData.email}
            onChange={(e) => setFormData({...formData, email: e.target.value})}
            disabled={loading}
          />
        </div>

        <button type="submit" disabled={loading}>
          {loading ? 'Saving...' : 'Save Changes'}
        </button>
      </form>
    </div>
  );
}

export default ProfilePage;
```

### Example 6: Token Refresh on API Calls

```jsx
import { useAuth } from './hooks/useAuth';

function useAuthenticatedFetch() {
  const { token, refreshToken, logout } = useAuth();

  const authFetch = async (url, options = {}) => {
    // Add auth header
    const headers = {
      ...options.headers,
      'Authorization': `Bearer ${token}`
    };

    let response = await fetch(url, { ...options, headers });

    // If token expired, try to refresh
    if (response.status === 401) {
      try {
        await refreshToken();
        // Retry with new token
        headers.Authorization = `Bearer ${token}`;
        response = await fetch(url, { ...options, headers });
      } catch (err) {
        // Refresh failed, logout user
        logout();
        throw new Error('Session expired');
      }
    }

    return response;
  };

  return authFetch;
}

// Usage
function MyComponent() {
  const authFetch = useAuthenticatedFetch();

  const fetchData = async () => {
    const response = await authFetch('/api/user/data');
    const data = await response.json();
    return data;
  };

  // ...
}
```

## Testing Examples

### Backend Unit Test

```python
import pytest
from app_example import create_app
from models import db, User

@pytest.fixture
def client():
    app = create_app({'TESTING': True, 'DATABASE_URI': 'sqlite:///:memory:'})
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client

def test_user_registration(client):
    response = client.post('/api/auth/register', json={
        'email': 'test@example.com',
        'password': 'password123',
        'name': 'Test User'
    })

    assert response.status_code == 201
    data = response.get_json()
    assert 'token' in data
    assert data['user']['email'] == 'test@example.com'

def test_user_login(client):
    # Register user first
    client.post('/api/auth/register', json={
        'email': 'test@example.com',
        'password': 'password123',
        'name': 'Test User'
    })

    # Test login
    response = client.post('/api/auth/login', json={
        'email': 'test@example.com',
        'password': 'password123'
    })

    assert response.status_code == 200
    data = response.get_json()
    assert 'token' in data
```

**Run tests:**
```bash
# Activate virtual environment first
source .venv/bin/activate
# Install pytest
uv pip install pytest
# Run tests
python3 -m pytest tests/
```

### Frontend Component Test

```jsx
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { LoginForm } from './components/auth/LoginForm';

test('login form submits with correct data', async () => {
  const mockLogin = jest.fn();

  render(<LoginForm onLogin={mockLogin} />);

  fireEvent.change(screen.getByLabelText(/email/i), {
    target: { value: 'test@example.com' }
  });

  fireEvent.change(screen.getByLabelText(/password/i), {
    target: { value: 'password123' }
  });

  fireEvent.click(screen.getByRole('button', { name: /login/i }));

  await waitFor(() => {
    expect(mockLogin).toHaveBeenCalledWith('test@example.com', 'password123');
  });
});
```

## Production Deployment

### Backend with Gunicorn

```bash
# Install gunicorn
pip install gunicorn

# Run with 4 workers
gunicorn -w 4 -b 0.0.0.0:8000 backend.app_example:app
```

### Frontend Build

```bash
npm run build
# Deploy the dist/ folder to your hosting service
```

### Docker Example

```dockerfile
# Backend Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt
COPY backend/ .
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app_example:app"]
```
