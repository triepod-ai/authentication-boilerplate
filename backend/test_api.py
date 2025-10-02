#!/usr/bin/env python3
"""
Comprehensive API Testing Script

Tests all authentication endpoints for the boilerplate.
"""

import requests
import json
import time
from datetime import datetime


class Colors:
    """Terminal colors for output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


class APITester:
    def __init__(self, base_url='http://localhost:5000'):
        self.base_url = base_url
        self.user_token = None
        self.admin_token = None
        self.test_user_email = f'test_{int(time.time())}@example.com'
        self.test_user_password = 'TestPassword123!'
        self.test_user_name = 'Test User'

        self.passed_tests = 0
        self.failed_tests = 0

    def log(self, message, color=Colors.END):
        """Print colored log message"""
        print(f"{color}{message}{Colors.END}")

    def test_endpoint(self, name, method, endpoint, data=None, headers=None, expected_status=200):
        """Test a single endpoint"""
        url = f"{self.base_url}{endpoint}"

        self.log(f"\n{'='*60}", Colors.CYAN)
        self.log(f"Testing: {name}", Colors.BOLD)
        self.log(f"Method: {method} | Endpoint: {endpoint}", Colors.CYAN)

        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=data)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=headers)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers)
            else:
                raise ValueError(f"Unsupported method: {method}")

            # Print request details
            if data:
                self.log(f"Request Data: {json.dumps(data, indent=2)}", Colors.BLUE)

            # Print response
            self.log(f"Status Code: {response.status_code}", Colors.YELLOW)

            try:
                response_data = response.json()
                self.log(f"Response: {json.dumps(response_data, indent=2)}", Colors.BLUE)
            except:
                self.log(f"Response: {response.text}", Colors.BLUE)
                response_data = None

            # Check status code
            if response.status_code == expected_status:
                self.log(f"✓ PASSED - Status code matches expected {expected_status}", Colors.GREEN)
                self.passed_tests += 1
                return response_data, True
            else:
                self.log(f"✗ FAILED - Expected {expected_status}, got {response.status_code}", Colors.RED)
                self.failed_tests += 1
                return response_data, False

        except Exception as e:
            self.log(f"✗ ERROR: {str(e)}", Colors.RED)
            self.failed_tests += 1
            return None, False

    def run_user_auth_tests(self):
        """Test user authentication endpoints"""
        self.log(f"\n\n{'#'*60}", Colors.HEADER)
        self.log("USER AUTHENTICATION TESTS", Colors.HEADER)
        self.log(f"{'#'*60}", Colors.HEADER)

        # Test 1: Register new user
        register_data = {
            'email': self.test_user_email,
            'password': self.test_user_password,
            'name': self.test_user_name
        }
        response, success = self.test_endpoint(
            "User Registration",
            "POST",
            "/api/auth/register",
            data=register_data,
            expected_status=201
        )

        if success and response:
            self.user_token = response.get('token')
            self.log(f"User Token: {self.user_token[:20]}...", Colors.GREEN)

        # Test 2: Register duplicate (should fail)
        response, success = self.test_endpoint(
            "Duplicate Registration (should fail)",
            "POST",
            "/api/auth/register",
            data=register_data,
            expected_status=400
        )

        # Test 3: Login
        login_data = {
            'email': self.test_user_email,
            'password': self.test_user_password
        }
        response, success = self.test_endpoint(
            "User Login",
            "POST",
            "/api/auth/login",
            data=login_data,
            expected_status=200
        )

        if success and response:
            self.user_token = response.get('token')

        # Test 4: Verify token
        headers = {'Authorization': f'Bearer {self.user_token}'}
        response, success = self.test_endpoint(
            "Verify Token",
            "GET",
            "/api/auth/verify",
            headers=headers,
            expected_status=200
        )

        # Test 5: Get profile
        response, success = self.test_endpoint(
            "Get User Profile",
            "GET",
            "/api/auth/profile",
            headers=headers,
            expected_status=200
        )

        # Test 6: Update profile
        update_data = {
            'name': 'Updated Test User',
            'phone': '+1234567890'
        }
        response, success = self.test_endpoint(
            "Update User Profile",
            "PUT",
            "/api/auth/profile",
            data=update_data,
            headers=headers,
            expected_status=200
        )

        # Test 7: Change password
        change_password_data = {
            'current_password': self.test_user_password,
            'new_password': 'NewPassword123!'
        }
        response, success = self.test_endpoint(
            "Change Password",
            "POST",
            "/api/auth/change-password",
            data=change_password_data,
            headers=headers,
            expected_status=200
        )

        # Update password for future tests
        if success:
            self.test_user_password = 'NewPassword123!'

        # Test 8: Refresh token
        response, success = self.test_endpoint(
            "Refresh Token",
            "POST",
            "/api/auth/refresh",
            headers=headers,
            expected_status=200
        )

        # Test 9: Logout
        response, success = self.test_endpoint(
            "User Logout",
            "POST",
            "/api/auth/logout",
            headers=headers,
            expected_status=200
        )

        # Test 10: Invalid login
        invalid_login = {
            'email': self.test_user_email,
            'password': 'wrong_password'
        }
        response, success = self.test_endpoint(
            "Invalid Login (should fail)",
            "POST",
            "/api/auth/login",
            data=invalid_login,
            expected_status=401
        )

    def run_admin_auth_tests(self):
        """Test admin authentication endpoints"""
        self.log(f"\n\n{'#'*60}", Colors.HEADER)
        self.log("ADMIN AUTHENTICATION TESTS", Colors.HEADER)
        self.log(f"{'#'*60}", Colors.HEADER)

        # Test 1: Admin login (default admin created on startup)
        admin_login_data = {
            'username': 'admin',
            'password': 'admin123'
        }
        response, success = self.test_endpoint(
            "Admin Login",
            "POST",
            "/api/admin/login",
            data=admin_login_data,
            expected_status=200
        )

        if success and response:
            self.admin_token = response.get('token')
            self.log(f"Admin Token: {self.admin_token[:20]}...", Colors.GREEN)

        headers = {'Authorization': f'Bearer {self.admin_token}'}

        # Test 2: Get admin profile
        response, success = self.test_endpoint(
            "Get Admin Profile",
            "GET",
            "/api/admin/profile",
            headers=headers,
            expected_status=200
        )

        # Test 3: Change admin password
        change_admin_password = {
            'current_password': 'admin123',
            'new_password': 'NewAdmin123!'
        }
        response, success = self.test_endpoint(
            "Change Admin Password",
            "POST",
            "/api/admin/change-password",
            data=change_admin_password,
            headers=headers,
            expected_status=200
        )

        # Re-login with new password if change was successful
        if success:
            admin_login_data['password'] = 'NewAdmin123!'
            response, success = self.test_endpoint(
                "Re-login with New Admin Password",
                "POST",
                "/api/admin/login",
                data=admin_login_data,
                expected_status=200
            )
            if success and response:
                self.admin_token = response.get('token')
                headers = {'Authorization': f'Bearer {self.admin_token}'}

        # Test 4: List admin users (super admin only)
        response, success = self.test_endpoint(
            "List Admin Users",
            "GET",
            "/api/admin/users",
            headers=headers,
            expected_status=200
        )

        # Test 5: Create new admin user (super admin only)
        new_admin_data = {
            'username': f'testadmin_{int(time.time())}',
            'email': f'testadmin_{int(time.time())}@example.com',
            'password': 'TestAdmin123!',
            'role': 'admin'
        }
        response, success = self.test_endpoint(
            "Create New Admin User",
            "POST",
            "/api/admin/users",
            data=new_admin_data,
            headers=headers,
            expected_status=201
        )

        new_admin_id = None
        if success and response:
            new_admin_id = response.get('user', {}).get('id')

        # Test 6: Update admin user (super admin only)
        if new_admin_id:
            update_admin_data = {
                'email': f'updated_{new_admin_data["email"]}',
                'role': 'admin',
                'is_active': True
            }
            response, success = self.test_endpoint(
                "Update Admin User",
                "PUT",
                f"/api/admin/users/{new_admin_id}",
                data=update_admin_data,
                headers=headers,
                expected_status=200
            )

        # Test 7: Get audit logs
        response, success = self.test_endpoint(
            "Get Audit Logs",
            "GET",
            "/api/admin/audit-logs",
            headers=headers,
            expected_status=200
        )

        # Test 8: Admin logout
        response, success = self.test_endpoint(
            "Admin Logout",
            "POST",
            "/api/admin/logout",
            headers=headers,
            expected_status=200
        )

        # Test 9: Invalid admin login
        invalid_admin_login = {
            'username': 'admin',
            'password': 'wrong_password'
        }
        response, success = self.test_endpoint(
            "Invalid Admin Login (should fail)",
            "POST",
            "/api/admin/login",
            data=invalid_admin_login,
            expected_status=401
        )

    def run_general_tests(self):
        """Test general endpoints"""
        self.log(f"\n\n{'#'*60}", Colors.HEADER)
        self.log("GENERAL ENDPOINT TESTS", Colors.HEADER)
        self.log(f"{'#'*60}", Colors.HEADER)

        # Test 1: Health check
        response, success = self.test_endpoint(
            "Health Check",
            "GET",
            "/health",
            expected_status=200
        )

        # Test 2: Root endpoint (API docs)
        response, success = self.test_endpoint(
            "Root Endpoint (API Documentation)",
            "GET",
            "/",
            expected_status=200
        )

    def print_summary(self):
        """Print test summary"""
        total_tests = self.passed_tests + self.failed_tests

        self.log(f"\n\n{'='*60}", Colors.HEADER)
        self.log("TEST SUMMARY", Colors.HEADER)
        self.log(f"{'='*60}", Colors.HEADER)

        self.log(f"Total Tests: {total_tests}", Colors.BOLD)
        self.log(f"Passed: {self.passed_tests}", Colors.GREEN)
        self.log(f"Failed: {self.failed_tests}", Colors.RED)

        success_rate = (self.passed_tests / total_tests * 100) if total_tests > 0 else 0
        self.log(f"Success Rate: {success_rate:.1f}%", Colors.CYAN)

        if self.failed_tests == 0:
            self.log("\n✓ ALL TESTS PASSED!", Colors.GREEN)
        else:
            self.log(f"\n✗ {self.failed_tests} TEST(S) FAILED", Colors.RED)

    def run_all_tests(self):
        """Run all tests"""
        start_time = time.time()

        self.log(f"\n{'='*60}", Colors.HEADER)
        self.log(f"AUTHENTICATION BOILERPLATE API TESTS", Colors.HEADER)
        self.log(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", Colors.HEADER)
        self.log(f"{'='*60}\n", Colors.HEADER)

        # Run test suites
        self.run_general_tests()
        self.run_user_auth_tests()
        self.run_admin_auth_tests()

        # Print summary
        elapsed_time = time.time() - start_time
        self.log(f"\nTotal Time: {elapsed_time:.2f} seconds", Colors.CYAN)
        self.print_summary()


if __name__ == '__main__':
    tester = APITester()
    tester.run_all_tests()
