import React, { createContext, useContext, useState, useEffect } from 'react';

/**
 * AuthContext
 *
 * Global authentication state management.
 */
const AuthContext = createContext(null);

/**
 * AuthProvider Component
 *
 * Provides authentication state and methods to the app.
 *
 * Props:
 *   - children: React nodes
 *   - apiUrl: string - Base API URL (default: '/api/auth')
 *   - onAuthChange: (isAuthenticated, user) => void - Called when auth state changes
 */
export const AuthProvider = ({
  children,
  apiUrl = '/api/auth',
  onAuthChange
}) => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Initialize from localStorage
  useEffect(() => {
    const storedToken = localStorage.getItem('auth_token');
    const storedUser = localStorage.getItem('auth_user');

    if (storedToken && storedUser) {
      try {
        setToken(storedToken);
        setUser(JSON.parse(storedUser));
        setIsAuthenticated(true);
        verifyToken(storedToken);
      } catch (err) {
        console.error('Failed to parse stored user:', err);
        logout();
      }
    }

    setLoading(false);
  }, []);

  // Notify on auth change
  useEffect(() => {
    if (onAuthChange) {
      onAuthChange(isAuthenticated, user);
    }
  }, [isAuthenticated, user]);

  /**
   * Verify token validity
   */
  const verifyToken = async (tokenToVerify) => {
    try {
      const response = await fetch(`${apiUrl}/verify`, {
        headers: {
          'Authorization': `Bearer ${tokenToVerify}`
        }
      });

      const data = await response.json();

      if (!data.valid) {
        logout();
      }
    } catch (err) {
      console.error('Token verification failed:', err);
    }
  };

  /**
   * Login user
   */
  const login = async (email, password) => {
    const response = await fetch(`${apiUrl}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Login failed');
    }

    // Store token and user
    localStorage.setItem('auth_token', data.token);
    localStorage.setItem('auth_user', JSON.stringify(data.user));

    setToken(data.token);
    setUser(data.user);
    setIsAuthenticated(true);

    return data;
  };

  /**
   * Register new user
   */
  const register = async (email, password, name) => {
    const response = await fetch(`${apiUrl}/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password, name }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Registration failed');
    }

    // Store token and user
    localStorage.setItem('auth_token', data.token);
    localStorage.setItem('auth_user', JSON.stringify(data.user));

    setToken(data.token);
    setUser(data.user);
    setIsAuthenticated(true);

    return data;
  };

  /**
   * Logout user
   */
  const logout = async () => {
    try {
      if (token) {
        await fetch(`${apiUrl}/logout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`
          }
        });
      }
    } catch (err) {
      console.error('Logout error:', err);
    } finally {
      // Clear state regardless of API call success
      localStorage.removeItem('auth_token');
      localStorage.removeItem('auth_user');
      setToken(null);
      setUser(null);
      setIsAuthenticated(false);
    }
  };

  /**
   * Update user profile
   */
  const updateProfile = async (updates) => {
    const response = await fetch(`${apiUrl}/profile`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(updates),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Update failed');
    }

    // Update stored user
    localStorage.setItem('auth_user', JSON.stringify(data.user));
    setUser(data.user);

    return data;
  };

  /**
   * Change password
   */
  const changePassword = async (currentPassword, newPassword) => {
    const response = await fetch(`${apiUrl}/change-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Password change failed');
    }

    return data;
  };

  /**
   * Refresh token
   */
  const refreshToken = async () => {
    const response = await fetch(`${apiUrl}/refresh`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Token refresh failed');
    }

    // Update stored token
    localStorage.setItem('auth_token', data.token);
    setToken(data.token);

    return data;
  };

  const value = {
    user,
    token,
    isAuthenticated,
    loading,
    login,
    register,
    logout,
    updateProfile,
    changePassword,
    refreshToken
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

/**
 * useAuth Hook
 *
 * Access authentication state and methods.
 */
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;
