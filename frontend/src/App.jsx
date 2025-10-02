import React from 'react'
import { Routes, Route, Link, Navigate } from 'react-router-dom'
import { useAuth } from '../hooks/useAuth'
import LoginForm from '../components/auth/LoginForm'
import RegisterForm from '../components/auth/RegisterForm'
import ProtectedRoute from '../components/auth/ProtectedRoute'
import './App.css'

function HomePage() {
  return (
    <div className="home-page">
      <h1>Authentication Boilerplate</h1>
      <p>A production-ready authentication system for Flask + React applications.</p>

      <div className="feature-grid">
        <div className="feature-card">
          <h3>🔐 Secure Authentication</h3>
          <p>JWT-based user authentication with token refresh</p>
        </div>
        <div className="feature-card">
          <h3>👥 User Management</h3>
          <p>Complete user profile and password management</p>
        </div>
        <div className="feature-card">
          <h3>🛡️ Admin System</h3>
          <p>Role-based access control with audit logging</p>
        </div>
        <div className="feature-card">
          <h3>🏢 Multi-tenant</h3>
          <p>Optional tenant isolation support</p>
        </div>
      </div>

      <div className="cta-buttons">
        <Link to="/login" className="btn btn-primary">Login</Link>
        <Link to="/register" className="btn btn-secondary">Register</Link>
      </div>
    </div>
  )
}

function LoginPage() {
  const { login } = useAuth()
  const [error, setError] = React.useState('')

  const handleLogin = async (email, password) => {
    try {
      await login(email, password)
    } catch (err) {
      setError(err.message || 'Login failed')
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-container">
        <h1>Login</h1>
        {error && <div className="error-message">{error}</div>}
        <LoginForm onLogin={handleLogin} />
        <p className="auth-footer">
          Don't have an account? <Link to="/register">Register here</Link>
        </p>
      </div>
    </div>
  )
}

function RegisterPage() {
  const { register } = useAuth()
  const [error, setError] = React.useState('')

  const handleRegister = async (email, password, name) => {
    try {
      await register(email, password, name)
    } catch (err) {
      setError(err.message || 'Registration failed')
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-container">
        <h1>Register</h1>
        {error && <div className="error-message">{error}</div>}
        <RegisterForm onRegister={handleRegister} />
        <p className="auth-footer">
          Already have an account? <Link to="/login">Login here</Link>
        </p>
      </div>
    </div>
  )
}

function Dashboard() {
  const { user, logout } = useAuth()

  return (
    <div className="dashboard">
      <div className="dashboard-header">
        <h1>Dashboard</h1>
        <button onClick={logout} className="btn btn-secondary">Logout</button>
      </div>

      <div className="user-info-card">
        <h2>Welcome, {user?.name}!</h2>
        <div className="user-details">
          <p><strong>Email:</strong> {user?.email}</p>
          <p><strong>Account Status:</strong> <span className="status-active">Active</span></p>
          <p><strong>Last Login:</strong> {user?.last_login ? new Date(user.last_login).toLocaleString() : 'N/A'}</p>
        </div>
      </div>

      <div className="dashboard-actions">
        <Link to="/profile" className="btn btn-primary">Edit Profile</Link>
        <Link to="/change-password" className="btn btn-secondary">Change Password</Link>
      </div>
    </div>
  )
}

function App() {
  const { isAuthenticated, loading } = useAuth()

  if (loading) {
    return <div className="loading">Loading...</div>
  }

  return (
    <div className="app">
      <nav className="navbar">
        <div className="nav-brand">
          <Link to="/">Auth Boilerplate</Link>
        </div>
        <div className="nav-links">
          {isAuthenticated ? (
            <>
              <Link to="/dashboard">Dashboard</Link>
              <Link to="/" onClick={(e) => { e.preventDefault(); useAuth().logout() }}>Logout</Link>
            </>
          ) : (
            <>
              <Link to="/login">Login</Link>
              <Link to="/register">Register</Link>
            </>
          )}
        </div>
      </nav>

      <main className="main-content">
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/login" element={
            isAuthenticated ? <Navigate to="/dashboard" /> : <LoginPage />
          } />
          <Route path="/register" element={
            isAuthenticated ? <Navigate to="/dashboard" /> : <RegisterPage />
          } />
          <Route path="/dashboard" element={
            <ProtectedRoute isAuthenticated={isAuthenticated}>
              <Dashboard />
            </ProtectedRoute>
          } />
        </Routes>
      </main>
    </div>
  )
}

export default App
