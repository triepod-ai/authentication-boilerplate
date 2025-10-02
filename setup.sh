#!/bin/bash
# Authentication Boilerplate Setup Script
# Automates the setup process for WSL/Linux environments

set -e  # Exit on error

echo "🔐 Authentication Boilerplate Setup"
echo "===================================="
echo ""

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "⚠️  'uv' not found. Installing uv..."
    pip3 install --user uv
    echo "✅ uv installed"
fi

# Backend setup
echo ""
echo "📦 Setting up backend..."
cd backend

# Create virtual environment
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment with uv..."
    uv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate and install dependencies
echo "Installing Python dependencies..."
source .venv/bin/activate
uv pip install -r requirements.txt
echo "✅ Backend dependencies installed"

# Setup environment file
cd ..
if [ ! -f ".env" ]; then
    echo "Creating .env file..."
    cp .env.example .env
    echo "✅ .env file created (please edit with your configuration)"
else
    echo "✅ .env file already exists"
fi

# Frontend setup
echo ""
echo "🎨 Setting up frontend..."
cd frontend

if [ ! -d "node_modules" ]; then
    echo "Installing Node dependencies..."
    npm install
    echo "✅ Frontend dependencies installed"
else
    echo "✅ Frontend dependencies already installed"
fi

cd ..

# Summary
echo ""
echo "✅ Setup complete!"
echo ""
echo "📝 Next steps:"
echo "1. Edit .env file with your configuration"
echo "2. Start backend:"
echo "   cd backend"
echo "   source .venv/bin/activate"
echo "   python3 app_example.py"
echo ""
echo "3. Start frontend (in a new terminal):"
echo "   cd frontend"
echo "   npm run dev"
echo ""
echo "🔑 Default admin credentials:"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "⚠️  Remember to change the admin password immediately!"
