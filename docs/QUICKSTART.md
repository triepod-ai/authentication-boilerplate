# Quick Start Guide

Get your authentication system up and running in 5 minutes.

## Prerequisites

- Python 3.8+
- Node.js 16+
- pip and npm

## Backend Setup (2 minutes)

1. **Navigate to backend directory:**
   ```bash
   cd backend
   ```

2. **Create virtual environment using uv (recommended for WSL):**
   ```bash
   uv venv
   source .venv/bin/activate
   ```

   *Alternative (standard venv):*
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   uv pip install -r requirements.txt
   # OR with standard pip: pip install -r requirements.txt
   ```

   **Note:** This uses SQLite by default (no database server needed). For PostgreSQL or MySQL, see the main README.

4. **Set up environment:**
   ```bash
   cp ../.env.example ../.env
   ```

5. **Run the application:**
   ```bash
   python3 app_example.py
   ```

   You should see:
   ```
   Created default super admin: admin / admin123
   * Running on http://127.0.0.1:5000
   ```

## Frontend Setup (2 minutes)

1. **Navigate to frontend directory:**
   ```bash
   cd frontend
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Run development server:**
   ```bash
   npm run dev
   ```

   You should see:
   ```
   Local: http://localhost:5173/
   ```

## Test It Out (1 minute)

### Test User Registration

```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123",
    "name": "Test User"
  }'
```

### Test User Login

```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

### Test Admin Login

```bash
curl -X POST http://localhost:5000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

## Next Steps

1. **Change default admin password** in production
2. **Configure database** in `.env` (currently using SQLite)
3. **Set proper secrets** for JWT_SECRET and SECRET_KEY
4. **Review API documentation** in main README
5. **Customize models** and routes for your needs

## Common Issues

### Port already in use

Change the port in `backend/app_example.py`:
```python
app.run(debug=True, port=5001)  # Use a different port
```

### Database errors

Delete the database and recreate:
```bash
rm backend/auth_example.db
python3 backend/app_example.py
```

### Virtual environment issues (WSL)

If you get "externally-managed-environment" error, use `uv`:
```bash
# Install uv if not already installed
pip install --user uv

# Create venv with uv
cd backend
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
```

### CORS errors

Update CORS_ORIGINS in `.env`:
```
CORS_ORIGINS=http://localhost:3000,http://localhost:5173
```

## Ready to Integrate

Check out the main README.md for:
- Full API documentation
- Integration examples
- Customization guides
- Security best practices
