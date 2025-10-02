import React from 'react';
import { Navigate } from 'react-router-dom';

/**
 * ProtectedRoute Component
 *
 * Route guard that requires authentication.
 * Redirects to login if user is not authenticated.
 *
 * Props:
 *   - children: React nodes to render if authenticated
 *   - isAuthenticated: boolean - Authentication status
 *   - redirectTo: string - Path to redirect if not authenticated (default: '/login')
 *   - requiredRole: string - Required user role (optional)
 *   - userRole: string - Current user role (optional)
 */
const ProtectedRoute = ({
  children,
  isAuthenticated,
  redirectTo = '/login',
  requiredRole,
  userRole
}) => {
  // Check authentication
  if (!isAuthenticated) {
    return <Navigate to={redirectTo} replace />;
  }

  // Check role if specified
  if (requiredRole && userRole !== requiredRole) {
    return <Navigate to="/unauthorized" replace />;
  }

  return children;
};

export default ProtectedRoute;
